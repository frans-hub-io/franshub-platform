//! Custom roles and bindings: the access file, and the principals they produce.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AccessError;
use crate::catalog::{Catalog, PermSet, Role, valid_role_name};
use crate::grants::{Grants, Principal, PrincipalKind};

/// The scope entry that stands for every scope, including scopes created later.
pub const ALL_SCOPES: &str = "*";

const MAX_SUBJECT: usize = 256;
const MAX_SCOPE_KEY: usize = 128;

/// Valid scope key: 1..=128 characters of `[A-Za-z0-9._@-]`, not starting with `.` or `-`.
pub fn valid_scope_key(key: &str) -> bool {
    let b = key.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_SCOPE_KEY
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'@' | b'-'))
        && b[0] != b'.'
        && b[0] != b'-'
}

/// Who a binding applies to.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Subject {
    /// An OIDC user by user name.
    User(String),
    /// Every OIDC user in a group.
    Group(String),
    /// A managed token by id.
    Token(Uuid),
}

impl Subject {
    /// Parses `user:<name>`, `group:<name>` or `token:<uuid>`.
    pub fn parse(s: &str) -> Result<Self, AccessError> {
        let (kind, name) = s.split_once(':').ok_or_else(|| {
            AccessError::new("subject must be user:<name>, group:<name> or token:<uuid>")
        })?;
        let name = name.trim();
        if name.is_empty() || name.len() > MAX_SUBJECT || name.chars().any(char::is_control) {
            return Err(AccessError::new(
                "subject name must be 1..256 printable characters",
            ));
        }
        Ok(match kind.trim() {
            "user" => Subject::User(name.to_string()),
            "group" => Subject::Group(name.to_string()),
            "token" => Subject::Token(
                Uuid::parse_str(name)
                    .map_err(|_| AccessError::new("token subjects take the token id (a UUID)"))?,
            ),
            other => {
                return Err(AccessError::new(format!(
                    "unknown subject kind `{other}`: use user, group or token"
                )));
            }
        })
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Subject::User(n) => write!(f, "user:{n}"),
            Subject::Group(n) => write!(f, "group:{n}"),
            Subject::Token(id) => write!(f, "token:{id}"),
        }
    }
}

impl Serialize for Subject {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

/// Where a binding grants its role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scopes {
    /// Everywhere, including global-only permissions.
    Global,
    /// In these scopes only; global-only permissions are never granted.
    List(Vec<String>),
    /// In every scope, including scopes created later (`*`); global-only permissions are never
    /// granted.
    All,
}

impl Scopes {
    /// The scope list as written: empty for global, `["*"]` for every scope.
    pub fn keys(&self) -> Vec<String> {
        match self {
            Scopes::Global => vec![],
            Scopes::List(l) => l.clone(),
            Scopes::All => vec![ALL_SCOPES.to_string()],
        }
    }

    /// The scopes of a `scopes` list and `global` flag, checked: either a non-empty list or
    /// `global: true`; `*` must be the only entry; keys are valid and listed once.
    pub fn from_parts(list: Option<Vec<String>>, global: bool) -> Result<Self, AccessError> {
        match (global, list) {
            (true, None) => Ok(Scopes::Global),
            (true, Some(l)) if l.is_empty() => Ok(Scopes::Global),
            (false, Some(list)) if !list.is_empty() => {
                if list.iter().any(|s| s == ALL_SCOPES) {
                    if list.len() != 1 {
                        return Err(AccessError::new("\"*\" must be the only entry in scopes"));
                    }
                    return Ok(Scopes::All);
                }
                let mut seen = BTreeSet::new();
                for s in &list {
                    if !valid_scope_key(s) {
                        return Err(AccessError::new(format!(
                            "scope `{s}` must be 1..{MAX_SCOPE_KEY} characters of [A-Za-z0-9._@-]"
                        )));
                    }
                    if !seen.insert(s.as_str()) {
                        return Err(AccessError::new(format!("scope `{s}` listed twice")));
                    }
                }
                Ok(Scopes::List(list))
            }
            (true, Some(_)) => Err(AccessError::new(
                "set either scopes or global: true, not both",
            )),
            _ => Err(AccessError::new(
                "set scopes (a non-empty list) or global: true",
            )),
        }
    }
}

/// A role granted to a subject, globally or in scopes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// Who receives the role.
    pub subject: Subject,
    /// The role name (built into the catalog or defined in the access file).
    pub role: String,
    /// Where the role applies.
    pub scopes: Scopes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessDoc {
    #[serde(default)]
    roles: Vec<RoleDoc>,
    #[serde(default)]
    bindings: Vec<BindingDoc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleDoc {
    name: String,
    #[serde(default)]
    description: Option<String>,
    permissions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingDoc {
    subject: String,
    role: String,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    global: Option<bool>,
}

/// The catalog plus the custom roles and bindings of the access file: decides what principals
/// may do.
///
/// The access file is YAML:
///
/// ```yaml
/// roles:
///   - name: release-manager
///     description: Runs and finishes launches
///     permissions: ["launches:*", "projects:read"]
/// bindings:
///   - subject: group:qa
///     role: viewer
///     scopes: [team-a, team-b]
///   - subject: group:platform
///     role: admin
///     global: true
///   - subject: user:alice
///     role: release-manager
///     scopes: ["*"]
/// ```
#[derive(Clone, Debug)]
pub struct AccessPolicy {
    catalog: Arc<Catalog>,
    roles: BTreeMap<String, Role>,
    bindings: Vec<Binding>,
    origin: Option<String>,
}

impl AccessPolicy {
    /// A policy with the catalog's roles and no bindings.
    pub fn new(catalog: Arc<Catalog>) -> Self {
        Self {
            catalog,
            roles: BTreeMap::new(),
            bindings: Vec::new(),
            origin: None,
        }
    }

    /// Reads and checks an access file. Errors are one line naming the file and the entry.
    pub fn load(catalog: Arc<Catalog>, path: &Path) -> Result<Self, AccessError> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            AccessError::new(format!("reading the access file {}: {e}", path.display()))
        })?;
        let origin = format!("access file {}", path.display());
        let mut p =
            Self::parse(catalog, &text).map_err(|e| AccessError::new(format!("{origin}: {e}")))?;
        p.origin = Some(origin);
        Ok(p)
    }

    /// Parses and checks an access file. Errors name the entry, such as `bindings[2] (group:qa)`.
    pub fn parse(catalog: Arc<Catalog>, text: &str) -> Result<Self, AccessError> {
        let doc: AccessDoc = if text.trim().is_empty() {
            AccessDoc {
                roles: vec![],
                bindings: vec![],
            }
        } else {
            serde_yaml_ng::from_str(text).map_err(|e| AccessError::new(e.to_string()))?
        };
        let mut policy = Self::new(catalog);
        for (i, r) in doc.roles.into_iter().enumerate() {
            let at = format!("roles[{i}] ({})", r.name);
            if !valid_role_name(&r.name) {
                return Err(AccessError::new(format!(
                    "{at}: role names must match [a-z0-9]([a-z0-9-]{{0,61}}[a-z0-9])?"
                )));
            }
            if policy.catalog.role(&r.name).is_some() {
                return Err(AccessError::new(format!(
                    "{at}: the built-in role {} cannot be redefined",
                    r.name
                )));
            }
            if policy.roles.contains_key(&r.name) {
                return Err(AccessError::new(format!("{at}: role defined twice")));
            }
            if r.description
                .as_ref()
                .is_some_and(|d| d.len() > 1024 || d.chars().any(char::is_control))
            {
                return Err(AccessError::new(format!(
                    "{at}: description is limited to 1024 bytes without control characters"
                )));
            }
            let (permissions, explicit) = policy
                .catalog
                .expand(&r.permissions)
                .map_err(|e| AccessError::new(format!("{at}: {e}")))?;
            policy.roles.insert(
                r.name.clone(),
                Role {
                    name: r.name,
                    description: r.description,
                    permissions,
                    builtin: false,
                    explicit,
                },
            );
        }
        for (i, b) in doc.bindings.into_iter().enumerate() {
            let at = format!("bindings[{i}] ({})", b.subject);
            let subject =
                Subject::parse(&b.subject).map_err(|e| AccessError::new(format!("{at}: {e}")))?;
            let scopes = Scopes::from_parts(b.scopes, b.global.unwrap_or(false))
                .map_err(|e| AccessError::new(format!("{at}: {e}")))?;
            policy
                .add_binding(Binding {
                    subject,
                    role: b.role,
                    scopes,
                })
                .map_err(|e| AccessError::new(format!("{at}: {e}")))?;
        }
        Ok(policy)
    }

    /// Adds a binding after checking it: the role exists, and a binding limited to scopes does not
    /// use a role that names a global-only permission explicitly.
    pub fn add_binding(&mut self, b: Binding) -> Result<(), AccessError> {
        let role = self
            .role(&b.role)
            .ok_or_else(|| AccessError::new(format!("unknown role `{}`", b.role)))?;
        if let Scopes::List(l) = &b.scopes {
            for s in l {
                if !valid_scope_key(s) {
                    return Err(AccessError::new(format!(
                        "scope `{s}` must be 1..{MAX_SCOPE_KEY} characters of [A-Za-z0-9._@-]"
                    )));
                }
            }
        }
        if b.scopes != Scopes::Global
            && let Some(p) = role
                .explicit
                .iter()
                .find(|p| self.catalog.is_global_only(p))
        {
            return Err(AccessError::new(format!(
                "role `{}` lists {p}, a global-only permission that a binding limited to scopes cannot grant; bind the role with global: true or remove {p} from it",
                b.role
            )));
        }
        self.bindings.push(b);
        Ok(())
    }

    /// `access file <path>`, or `access file` for a policy not read from a file.
    pub fn origin(&self) -> &str {
        self.origin.as_deref().unwrap_or("access file")
    }

    /// The product's catalog.
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// The catalog as a shared handle.
    pub fn catalog_arc(&self) -> &Arc<Catalog> {
        &self.catalog
    }

    /// A built-in role or a custom role of the access file.
    pub fn role(&self, name: &str) -> Option<&Role> {
        self.catalog.role(name).or_else(|| self.roles.get(name))
    }

    /// Built-in roles in catalog order, then custom roles by name.
    pub fn roles(&self) -> impl Iterator<Item = &Role> {
        self.catalog.roles().chain(self.roles.values())
    }

    /// Every binding, in file order.
    pub fn bindings(&self) -> &[Binding] {
        &self.bindings
    }

    /// The bindings of an OIDC user: `user:` subjects by name and `group:` subjects by group.
    pub fn bindings_for_user(&self, name: &str, groups: &[String]) -> Vec<Binding> {
        self.bindings
            .iter()
            .filter(|b| match &b.subject {
                Subject::User(n) => n == name,
                Subject::Group(g) => groups.iter().any(|x| x == g),
                Subject::Token(_) => false,
            })
            .cloned()
            .collect()
    }

    /// The bindings of the access file for a managed token.
    pub fn bindings_for_token(&self, id: Uuid) -> Vec<Binding> {
        self.bindings
            .iter()
            .filter(|b| b.subject == Subject::Token(id))
            .cloned()
            .collect()
    }

    /// Permissions of a role usable in a binding with these scopes: global-only permissions only
    /// apply to global bindings.
    fn effective(&self, role: &Role, scopes: &Scopes) -> PermSet {
        match scopes {
            Scopes::Global => role.permissions.clone(),
            _ => role
                .permissions
                .iter()
                .filter(|p| !self.catalog.is_global_only(p))
                .cloned()
                .collect(),
        }
    }

    /// The effective permissions of a list of bindings; bindings of unknown roles grant nothing.
    pub fn grants(&self, bindings: &[Binding]) -> Grants {
        let mut g = Grants::default();
        for b in bindings {
            let Some(role) = self.role(&b.role) else {
                continue;
            };
            let perms = self.effective(role, &b.scopes);
            match &b.scopes {
                Scopes::Global => g.global.extend(perms),
                Scopes::All => g.all_scopes.extend(perms),
                Scopes::List(list) => {
                    for s in list {
                        g.scopes.entry(s.clone()).or_default().extend(perms.clone());
                    }
                }
            }
        }
        g.scopes.retain(|_, p| !p.is_empty());
        g
    }

    /// The principal of a list of bindings.
    pub fn principal(&self, kind: PrincipalKind, name: &str, bindings: &[Binding]) -> Principal {
        let mut roles: Vec<String> = Vec::new();
        for b in bindings {
            if !roles.contains(&b.role) {
                roles.push(b.role.clone());
            }
        }
        Principal {
            kind,
            name: name.to_string(),
            perms: self.grants(bindings),
            roles,
            groups: Vec::new(),
            token_id: None,
        }
    }

    /// The principal of an OIDC user, or `None` when no binding applies to the user or its groups.
    pub fn user_principal(&self, name: &str, groups: &[String]) -> Option<Principal> {
        let b = self.bindings_for_user(name, groups);
        if b.is_empty() {
            return None;
        }
        let mut p = self.principal(PrincipalKind::User, name, &b);
        p.groups = groups.to_vec();
        Some(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Permission;

    pub(crate) fn catalog() -> Arc<Catalog> {
        Arc::new(
            Catalog::builder()
                .permission("launches:read", "r")
                .permission("launches:write", "w")
                .permission("launches:delete", "d")
                .permission("projects:read", "p")
                .global_permission("settings:write", "s")
                .global_permission("audit:read", "a")
                .role("viewer", &["launches:read", "projects:read"])
                .role("editor", &["launches:*", "projects:read", "tokens:*"])
                .role("admin", &["*"])
                .build()
                .unwrap(),
        )
    }

    fn perm(s: &str) -> Permission {
        Permission::parse(s).unwrap()
    }

    const EXAMPLE: &str = r#"
roles:
  - name: launch-author
    description: Writes launches
    permissions: [launches:read, launches:write]
  - name: launches-all
    permissions: ["launches:*"]
bindings:
  - subject: group:payments-dev
    role: editor
    scopes: [payments]
  - subject: group:platform
    role: admin
    global: true
  - subject: token:0190e0d0-0000-7000-8000-000000000001
    role: launch-author
    scopes: [billing]
  - subject: user:alice
    role: viewer
    global: true
  - subject: group:qa
    role: viewer
    scopes: ["*"]
"#;

    #[test]
    fn parses_the_example() {
        let c = AccessPolicy::parse(catalog(), EXAMPLE).unwrap();
        let names: Vec<&str> = c
            .role("launch-author")
            .unwrap()
            .permissions
            .iter()
            .map(Permission::as_str)
            .collect();
        assert_eq!(names, vec!["launches:read", "launches:write"]);
        assert_eq!(c.role("launches-all").unwrap().permissions.len(), 3);
        let id = Uuid::parse_str("0190e0d0-0000-7000-8000-000000000001").unwrap();
        let b = c.bindings_for_token(id);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].scopes, Scopes::List(vec!["billing".into()]));
        let u = c.bindings_for_user("alice", &["payments-dev".to_string(), "other".to_string()]);
        assert_eq!(u.len(), 2);
        assert!(c.bindings_for_user("ci-billing", &[]).is_empty());
        assert_eq!(c.bindings_for_user("bob", &["platform".into()]).len(), 1);
        assert_eq!(c.roles().count(), 5);
        assert!(c.user_principal("nobody", &[]).is_none());
        let alice = c.user_principal("alice", &["qa".into()]).unwrap();
        assert_eq!(alice.groups, vec!["qa"]);
        assert_eq!(alice.roles, vec!["viewer"]);
    }

    #[test]
    fn errors_name_the_entry() {
        let cases = [
            (
                "roles: [{name: viewer, permissions: [launches:read]}]",
                "roles[0] (viewer): the built-in role viewer cannot be redefined",
            ),
            (
                "roles: [{name: x, permissions: [launches:wrte]}]",
                "roles[0] (x): unknown permission `launches:wrte`",
            ),
            (
                "roles: [{name: x, permissions: [nothing:*]}]",
                "roles[0] (x): unknown permission",
            ),
            ("roles: [{name: x, permissions: []}]", "roles[0] (x)"),
            (
                "roles: [{name: Bad, permissions: [launches:read]}]",
                "roles[0] (Bad)",
            ),
            (
                "roles: [{name: a, permissions: [launches:read]}, {name: a, permissions: [launches:read]}]",
                "roles[1] (a): role defined twice",
            ),
            (
                "bindings: [{subject: 'team:x', role: viewer, global: true}]",
                "bindings[0] (team:x)",
            ),
            (
                "bindings: [{subject: 'token:ci', role: viewer, global: true}]",
                "bindings[0] (token:ci): token subjects take the token id",
            ),
            (
                "bindings: [{subject: 'user:x', role: nobody, global: true}]",
                "bindings[0] (user:x): unknown role `nobody`",
            ),
            (
                "bindings: [{subject: 'user:x', role: viewer}]",
                "bindings[0] (user:x): set scopes",
            ),
            (
                "bindings: [{subject: 'user:x', role: viewer, scopes: []}]",
                "bindings[0] (user:x): set scopes",
            ),
            (
                "bindings: [{subject: 'user:x', role: viewer, global: true, scopes: [a]}]",
                "not both",
            ),
            (
                "bindings: [{subject: 'user:x', role: viewer, scopes: ['*', a]}]",
                "\"*\" must be the only entry",
            ),
            (
                "bindings: [{subject: 'user:x', role: viewer, scopes: [a, a]}]",
                "scope `a` listed twice",
            ),
            (
                "bindings: [{subject: 'user:x', role: viewer, scopes: ['a b']}]",
                "scope `a b` must be",
            ),
            ("rolez: []", "unknown field"),
        ];
        for (doc, want) in cases {
            let e = AccessPolicy::parse(catalog(), doc).unwrap_err().to_string();
            assert!(e.contains(want), "{doc}: {e}");
        }
        assert!(
            AccessPolicy::parse(catalog(), "")
                .unwrap()
                .bindings()
                .is_empty()
        );
    }

    #[test]
    fn explicit_global_only_permissions_refuse_scoped_bindings() {
        let e = AccessPolicy::parse(
            catalog(),
            "roles: [{name: ops, permissions: [launches:write, settings:write]}]\nbindings: [{subject: 'user:x', role: viewer, global: true}, {subject: 'group:qa', role: ops, scopes: [billing]}]",
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.starts_with(
                "bindings[1] (group:qa): role `ops` lists settings:write, a global-only permission"
            ),
            "{e}"
        );
        let all = AccessPolicy::parse(
            catalog(),
            "roles: [{name: ops, permissions: [settings:write]}]\nbindings: [{subject: 'group:qa', role: ops, scopes: ['*']}]",
        )
        .unwrap_err()
        .to_string();
        assert!(all.contains("global-only"), "{all}");
        let ok = AccessPolicy::parse(
            catalog(),
            "roles: [{name: ops, permissions: [launches:write, settings:write]}, {name: tester, permissions: ['*']}]\nbindings: [{subject: 'group:ops', role: ops, global: true}, {subject: 'group:qa', role: tester, scopes: [billing]}, {subject: 'group:pay', role: admin, scopes: [billing]}]",
        )
        .unwrap();
        let ops = ok.user_principal("a", &["ops".into()]).unwrap();
        assert!(ops.allowed(&perm("settings:write"), None));
        assert!(ops.allowed(&perm("settings:write"), Some("billing")));
        for group in ["qa", "pay"] {
            let g = ok.user_principal("a", &[group.into()]).unwrap();
            assert!(
                g.allowed(&perm("launches:write"), Some("billing")),
                "{group}"
            );
            assert!(
                !g.allowed(&perm("settings:write"), Some("billing")),
                "{group}"
            );
            assert!(!g.perms.anywhere(&perm("settings:write")), "{group}");
            let v = serde_json::to_value(&g.perms).unwrap();
            assert!(
                !v["scopes"]["billing"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!("settings:write")),
                "{group}: {v}"
            );
        }
    }

    #[test]
    fn load_errors_are_one_line_with_the_file_and_the_entry() {
        let f = std::env::temp_dir().join(format!("franshub-access-{}.yaml", Uuid::new_v4()));
        std::fs::write(
            &f,
            "roles: [{name: author, permissions: [launches:wrte]}]\n",
        )
        .unwrap();
        let e = AccessPolicy::load(catalog(), &f).unwrap_err();
        assert_eq!(
            e.to_string(),
            format!(
                "access file {}: roles[0] (author): unknown permission `launches:wrte`",
                f.display()
            )
        );
        assert!(!e.to_string().contains('\n'));
        std::fs::write(
            &f,
            "bindings: [{subject: 'user:a', role: viewer, global: true}]\n",
        )
        .unwrap();
        let ok = AccessPolicy::load(catalog(), &f).unwrap();
        assert_eq!(ok.origin(), format!("access file {}", f.display()));
        std::fs::remove_file(&f).unwrap();
        let missing = AccessPolicy::load(catalog(), &f).unwrap_err();
        assert!(
            missing.to_string().starts_with("reading the access file "),
            "{missing}"
        );
    }

    #[test]
    fn scope_keys() {
        for ok in ["payments", "team-a", "a.b", "x_y", "A1", "a@b"] {
            assert!(valid_scope_key(ok), "{ok}");
        }
        for bad in ["", "*", "-a", ".a", "a b", "a/b", &"a".repeat(129)] {
            assert!(!valid_scope_key(bad), "{bad}");
        }
        assert_eq!(Scopes::All.keys(), vec!["*"]);
        assert!(Scopes::Global.keys().is_empty());
        assert_eq!(
            Subject::parse("user: alice ").unwrap(),
            Subject::User("alice".into())
        );
        assert_eq!(Subject::Group("g".into()).to_string(), "group:g");
    }
}
