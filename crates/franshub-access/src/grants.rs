//! Effective permissions and access decisions.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::catalog::{PermSet, Permission};

/// Effective permissions of a principal: global ones, ones granted in single scopes, and ones
/// granted in every scope (`*`). Scoped sets never hold global-only permissions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Grants {
    pub(crate) global: PermSet,
    pub(crate) scopes: BTreeMap<String, PermSet>,
    pub(crate) all_scopes: PermSet,
}

/// The JSON form of [`Grants`]: `{"global": [...], "scopes": {"key": [...]}, "allScopes": [...]}`.
/// The effective permissions in a scope are `global ∪ allScopes ∪ scopes[key]`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GrantsView {
    /// Permissions granted everywhere.
    pub global: Vec<String>,
    /// Permissions granted only in single scopes, by scope key.
    pub scopes: BTreeMap<String, Vec<String>>,
    /// Permissions granted in every scope, including scopes created later.
    pub all_scopes: Vec<String>,
}

fn names(s: &PermSet) -> Vec<String> {
    s.iter().map(|p| p.as_str().to_string()).collect()
}

impl Grants {
    /// Grants holding every permission of `perms` globally.
    pub fn global_only(perms: PermSet) -> Self {
        Self {
            global: perms,
            ..Self::default()
        }
    }

    /// `allowed(permission, scope)`: granted globally; or, with a scope, granted in that scope or in
    /// every scope. Global-only permissions are only ever granted globally.
    pub fn allowed(&self, p: &Permission, scope: Option<&str>) -> bool {
        self.global.contains(p)
            || scope.is_some_and(|s| {
                self.all_scopes.contains(p) || self.scopes.get(s).is_some_and(|x| x.contains(p))
            })
    }

    /// Granted globally.
    pub fn allowed_globally(&self, p: &Permission) -> bool {
        self.global.contains(p)
    }

    /// Granted in every scope, including scopes created later: globally or through `*`.
    pub fn allowed_in_all_scopes(&self, p: &Permission) -> bool {
        self.global.contains(p) || self.all_scopes.contains(p)
    }

    /// Granted somewhere: globally, through `*` or in at least one scope.
    pub fn anywhere(&self, p: &Permission) -> bool {
        self.allowed_in_all_scopes(p) || self.scopes.values().any(|x| x.contains(p))
    }

    /// Scopes where a scoped binding grants the permission (global and `*` grants not included).
    pub fn scopes_with(&self, p: &Permission) -> Vec<String> {
        self.scopes
            .iter()
            .filter(|(_, x)| x.contains(p))
            .map(|(s, _)| s.clone())
            .collect()
    }

    /// Effective permissions in one scope: global, `*` and that scope's grants.
    pub fn in_scope(&self, scope: &str) -> PermSet {
        let mut out = self.global.clone();
        out.extend(self.all_scopes.iter().cloned());
        if let Some(s) = self.scopes.get(scope) {
            out.extend(s.iter().cloned());
        }
        out
    }

    /// Whether the principal holds anything in the scope, so that the scope may be shown to it.
    pub fn sees_scope(&self, scope: &str) -> bool {
        !self.global.is_empty() || !self.all_scopes.is_empty() || self.scopes.contains_key(scope)
    }

    /// Permissions granted globally.
    pub fn global(&self) -> &PermSet {
        &self.global
    }

    /// Permissions granted in every scope through `*`.
    pub fn all_scopes(&self) -> &PermSet {
        &self.all_scopes
    }

    /// Permissions granted in single scopes.
    pub fn scoped(&self) -> &BTreeMap<String, PermSet> {
        &self.scopes
    }

    /// True when no permission is granted anywhere.
    pub fn is_empty(&self) -> bool {
        self.global.is_empty() && self.all_scopes.is_empty() && self.scopes.is_empty()
    }

    /// The JSON view.
    pub fn view(&self) -> GrantsView {
        GrantsView {
            global: names(&self.global),
            scopes: self
                .scopes
                .iter()
                .map(|(k, v)| (k.clone(), names(v)))
                .collect(),
            all_scopes: names(&self.all_scopes),
        }
    }
}

impl Serialize for Grants {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.view().serialize(s)
    }
}

/// How a principal authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PrincipalKind {
    /// An OIDC user (session cookie or bearer JWT).
    User,
    /// A static token from the server's token file.
    Token,
    /// A managed token created through the API.
    ApiToken,
}

impl PrincipalKind {
    /// `user`, `token` or `apiToken`.
    pub fn as_str(self) -> &'static str {
        match self {
            PrincipalKind::User => "user",
            PrincipalKind::Token => "token",
            PrincipalKind::ApiToken => "apiToken",
        }
    }
}

/// Why a principal may not do something.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Denial {
    /// The permission needed.
    pub permission: Permission,
    /// The scope it was needed in; `None` for a global check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// One sentence for the error body, such as `requires permission launches:write in scope a`.
    pub reason: String,
}

/// An authenticated caller and its effective permissions.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Principal {
    /// How the caller authenticated.
    pub kind: PrincipalKind,
    /// User name, static token name or managed token name.
    pub name: String,
    /// Effective permissions.
    #[serde(rename = "permissions")]
    pub perms: Grants,
    /// Role names of the bindings that apply, without duplicates.
    pub roles: Vec<String>,
    /// OIDC users: group names from the identity provider.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// Managed tokens: the token id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<Uuid>,
}

impl Principal {
    /// Whether the principal holds `p` globally or, with a scope, in that scope.
    pub fn allowed(&self, p: &Permission, scope: Option<&str>) -> bool {
        self.perms.allowed(p, scope)
    }

    /// `None` when allowed; otherwise why not.
    pub fn denial(&self, p: &Permission, scope: Option<&str>) -> Option<Denial> {
        if self.allowed(p, scope) {
            return None;
        }
        let reason = match scope {
            Some(s) => format!("requires permission {p} in scope {s}"),
            None => format!("requires permission {p} globally"),
        };
        Some(Denial {
            permission: p.clone(),
            scope: scope.map(String::from),
            reason,
        })
    }

    /// Role names joined with commas, for audit records.
    pub fn role_label(&self) -> String {
        self.roles.join(",")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{AccessPolicy, Binding, Catalog, Scopes, Subject};

    fn policy() -> AccessPolicy {
        let c = Catalog::builder()
            .permission("launches:read", "r")
            .permission("launches:write", "w")
            .global_permission("settings:write", "s")
            .role("viewer", &["launches:read"])
            .role("editor", &["launches:*", "tokens:*"])
            .role("admin", &["*"])
            .build()
            .unwrap();
        AccessPolicy::new(Arc::new(c))
    }

    fn p(s: &str) -> Permission {
        Permission::parse(s).unwrap()
    }

    fn bind(role: &str, scopes: Scopes) -> Binding {
        Binding {
            subject: Subject::User("u".into()),
            role: role.into(),
            scopes,
        }
    }

    #[test]
    fn scoped_bindings_grant_only_in_their_scopes() {
        let pol = policy();
        let pr = pol.principal(
            PrincipalKind::Token,
            "ci",
            &[bind("editor", Scopes::List(vec!["billing".into()]))],
        );
        assert!(pr.allowed(&p("launches:write"), Some("billing")));
        assert!(!pr.allowed(&p("launches:write"), Some("payments")));
        assert!(!pr.allowed(&p("launches:write"), None));
        assert!(pr.perms.anywhere(&p("launches:read")));
        assert_eq!(pr.perms.scopes_with(&p("launches:read")), vec!["billing"]);
        assert!(pr.perms.sees_scope("billing"));
        assert!(!pr.perms.sees_scope("payments"));
        let d = pr.denial(&p("launches:write"), Some("payments")).unwrap();
        assert_eq!(
            d.reason,
            "requires permission launches:write in scope payments"
        );
        assert_eq!(
            pr.denial(&p("launches:write"), None).unwrap().reason,
            "requires permission launches:write globally"
        );
        assert!(pr.denial(&p("launches:write"), Some("billing")).is_none());
    }

    #[test]
    fn admin_in_a_scope_never_gets_global_only_permissions() {
        let pol = policy();
        let pr = pol.principal(
            PrincipalKind::User,
            "a",
            &[bind("admin", Scopes::List(vec!["payments".into()]))],
        );
        assert!(!pr.allowed(&p("settings:write"), Some("payments")));
        assert!(!pr.allowed(&p("settings:write"), None));
        assert!(pr.allowed(&p("tokens:write"), Some("payments")));
        let all = pol.principal(PrincipalKind::User, "a", &[bind("admin", Scopes::All)]);
        assert!(!all.allowed(&p("settings:write"), Some("payments")));
        assert!(!all.perms.anywhere(&p("settings:write")));
        let global = pol.principal(PrincipalKind::User, "a", &[bind("admin", Scopes::Global)]);
        assert!(global.allowed(&p("settings:write"), None));
        assert!(global.allowed(&p("settings:write"), Some("x")));
    }

    #[test]
    fn all_scopes_covers_scopes_created_later_but_not_global_checks() {
        let pol = policy();
        let pr = pol.principal(PrincipalKind::User, "a", &[bind("viewer", Scopes::All)]);
        assert!(pr.allowed(&p("launches:read"), Some("created-tomorrow")));
        assert!(!pr.allowed(&p("launches:read"), None));
        assert!(pr.perms.allowed_in_all_scopes(&p("launches:read")));
        assert!(!pr.perms.allowed_globally(&p("launches:read")));
        assert!(pr.perms.sees_scope("anything"));
        let v = serde_json::to_value(&pr.perms).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"global": [], "scopes": {}, "allScopes": ["launches:read"]})
        );
    }

    #[test]
    fn unknown_roles_grant_nothing_and_json_shape() {
        let pol = policy();
        let pr = pol.principal(
            PrincipalKind::ApiToken,
            "t",
            &[
                bind("gone", Scopes::Global),
                bind("viewer", Scopes::List(vec!["a".into()])),
                bind("editor", Scopes::List(vec!["a".into()])),
            ],
        );
        assert!(!pr.perms.allowed_globally(&p("launches:read")));
        assert_eq!(pr.roles, vec!["gone", "viewer", "editor"]);
        assert_eq!(pr.role_label(), "gone,viewer,editor");
        let v = serde_json::to_value(&pr).unwrap();
        assert_eq!(v["kind"], "apiToken");
        assert_eq!(
            v["permissions"]["scopes"]["a"],
            serde_json::json!([
                "launches:read",
                "launches:write",
                "tokens:read",
                "tokens:write"
            ])
        );
        assert!(v.get("groups").is_none());
        assert!(
            pol.principal(PrincipalKind::User, "x", &[])
                .perms
                .is_empty()
        );
    }
}
