//! Permissions and built-in roles that a product registers at start-up.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use serde::{Serialize, Serializer};

use crate::AccessError;

/// Permission that lists managed tokens and reads their metadata. Registered by every catalog.
pub const TOKENS_READ: &str = "tokens:read";
/// Permission that creates and revokes managed tokens. Registered by every catalog.
pub const TOKENS_WRITE: &str = "tokens:write";

const MAX_PART: usize = 48;
const MAX_DESCRIPTION: usize = 512;

fn valid_part(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_PART
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'_')
        && b[b.len() - 1] != b'-'
}

/// A `resource:action` permission name such as `launches:read`.
///
/// Both parts start with a lowercase letter and use `[a-z0-9_-]` (at most 48 bytes each). A
/// permission only has an effect when the product registered it in its [`Catalog`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Permission(Arc<str>);

impl Permission {
    /// Checks the syntax of a permission name.
    pub fn parse(name: &str) -> Result<Self, AccessError> {
        let (resource, action) = name.split_once(':').ok_or_else(|| {
            AccessError::new(format!(
                "permission `{name}` must have the form resource:action"
            ))
        })?;
        if !valid_part(resource) || !valid_part(action) {
            return Err(AccessError::new(format!(
                "permission `{name}`: resource and action must start with a lowercase letter and use [a-z0-9_-] (at most {MAX_PART} bytes each)"
            )));
        }
        Ok(Self(Arc::from(name)))
    }

    /// The full name, `resource:action`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The part before the colon.
    pub fn resource(&self) -> &str {
        self.0.split_once(':').map(|(r, _)| r).unwrap_or_default()
    }

    /// The part after the colon.
    pub fn action(&self) -> &str {
        self.0.split_once(':').map(|(_, a)| a).unwrap_or_default()
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Permission({})", self.0)
    }
}

impl Serialize for Permission {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl std::str::FromStr for Permission {
    type Err = AccessError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// A set of permissions.
pub type PermSet = BTreeSet<Permission>;

/// A registered permission.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionInfo {
    /// The permission.
    pub permission: Permission,
    /// What the permission allows, for the UI and the documentation.
    pub description: String,
    /// The permission can only be granted globally: a binding limited to scopes never grants it.
    pub global_only: bool,
}

/// A named set of permissions: built into the product's catalog or defined in the access file.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    /// Role name (`[a-z0-9-]`, at most 63 characters).
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Every permission of the role, wildcards expanded.
    pub permissions: PermSet,
    /// Defined by the product's catalog rather than the access file.
    pub builtin: bool,
    /// Permissions the role names one by one (not through a wildcard).
    #[serde(skip)]
    pub(crate) explicit: PermSet,
}

/// Valid role name: `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`.
pub fn valid_role_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

/// The permissions and built-in roles of a product, fixed at start-up.
///
/// ```
/// use franshub_access::Catalog;
///
/// let catalog = Catalog::builder()
///     .permission("launches:read", "Read launches and their results")
///     .permission("launches:write", "Create and finish launches")
///     .global_permission("settings:write", "Change server settings")
///     .role("viewer", &["launches:read"])
///     .role("editor", &["launches:*", "tokens:read"])
///     .role("admin", &["*"])
///     .build()
///     .unwrap();
/// assert!(catalog.permission("launches:read").is_some());
/// assert!(catalog.is_global_only(&catalog.require("settings:write")));
/// ```
#[derive(Debug)]
pub struct Catalog {
    perms: BTreeMap<Permission, PermissionInfo>,
    order: Vec<Permission>,
    roles: Vec<Role>,
}

/// Builds a [`Catalog`]; errors are reported by [`CatalogBuilder::build`].
#[derive(Debug)]
pub struct CatalogBuilder {
    perms: Vec<(String, String, bool, bool)>,
    roles: Vec<(String, Option<String>, Vec<String>)>,
}

impl Catalog {
    /// A builder holding the platform permissions [`TOKENS_READ`] and [`TOKENS_WRITE`].
    pub fn builder() -> CatalogBuilder {
        CatalogBuilder {
            perms: vec![
                (
                    TOKENS_READ.into(),
                    "List managed tokens and read their metadata".into(),
                    false,
                    true,
                ),
                (
                    TOKENS_WRITE.into(),
                    "Create and revoke managed tokens".into(),
                    false,
                    true,
                ),
            ],
            roles: Vec::new(),
        }
    }

    /// The registered permission with this name.
    pub fn permission(&self, name: &str) -> Option<Permission> {
        let p = Permission::parse(name).ok()?;
        self.perms.get_key_value(&p).map(|(k, _)| k.clone())
    }

    /// The registered permission with this name; panics when it is not registered. For wiring at
    /// start-up, where a missing permission is a programming error.
    pub fn require(&self, name: &str) -> Permission {
        self.permission(name)
            .unwrap_or_else(|| panic!("permission `{name}` is not registered in the catalog"))
    }

    /// Whether the permission is registered.
    pub fn contains(&self, p: &Permission) -> bool {
        self.perms.contains_key(p)
    }

    /// Details of a registered permission.
    pub fn info(&self, p: &Permission) -> Option<&PermissionInfo> {
        self.perms.get(p)
    }

    /// Every registered permission, in registration order.
    pub fn permissions(&self) -> impl Iterator<Item = &PermissionInfo> {
        self.order.iter().filter_map(|p| self.perms.get(p))
    }

    /// Whether only a global binding can grant the permission.
    pub fn is_global_only(&self, p: &Permission) -> bool {
        self.perms.get(p).is_some_and(|i| i.global_only)
    }

    /// A built-in role.
    pub fn role(&self, name: &str) -> Option<&Role> {
        self.roles.iter().find(|r| r.name == name)
    }

    /// The built-in roles, in registration order.
    pub fn roles(&self) -> impl Iterator<Item = &Role> {
        self.roles.iter()
    }

    /// The permissions of a list of names and wildcards (`*` for every permission, `resource:*`
    /// for every permission of a resource), and those of them named one by one.
    pub fn expand(&self, list: &[impl AsRef<str>]) -> Result<(PermSet, PermSet), AccessError> {
        if list.is_empty() {
            return Err(AccessError::new("permissions must not be empty"));
        }
        let mut set = PermSet::new();
        let mut explicit = PermSet::new();
        for raw in list {
            let p = raw.as_ref().trim();
            if p == "*" {
                set.extend(self.perms.keys().cloned());
            } else if let Some(resource) = p.strip_suffix(":*") {
                let mut any = false;
                for m in self.perms.keys().filter(|x| x.resource() == resource) {
                    any = true;
                    set.insert(m.clone());
                }
                if !any {
                    return Err(AccessError::new(format!("unknown permission `{p}`")));
                }
            } else {
                let one = self
                    .permission(p)
                    .ok_or_else(|| AccessError::new(format!("unknown permission `{p}`")))?;
                set.insert(one.clone());
                explicit.insert(one);
            }
        }
        Ok((set, explicit))
    }
}

impl CatalogBuilder {
    fn push(mut self, name: &str, description: &str, global_only: bool) -> Self {
        if let Some(e) = self
            .perms
            .iter_mut()
            .find(|(n, _, _, platform)| *platform && n == name)
        {
            e.1 = description.to_string();
            e.2 = global_only;
            e.3 = false;
            return self;
        }
        self.perms.push((
            name.to_string(),
            description.to_string(),
            global_only,
            false,
        ));
        self
    }

    /// Registers a permission that can be granted globally or in scopes.
    pub fn permission(self, name: &str, description: &str) -> Self {
        self.push(name, description, false)
    }

    /// Registers a global-only permission: only a global binding grants it, never a binding
    /// limited to scopes or to every scope (`*`).
    pub fn global_permission(self, name: &str, description: &str) -> Self {
        self.push(name, description, true)
    }

    /// Adds a built-in role. `permissions` holds names and wildcards (`*`, `resource:*`).
    pub fn role(mut self, name: &str, permissions: &[&str]) -> Self {
        self.roles.push((
            name.to_string(),
            None,
            permissions.iter().map(|p| p.to_string()).collect(),
        ));
        self
    }

    /// Adds a built-in role with a description.
    pub fn role_described(mut self, name: &str, description: &str, permissions: &[&str]) -> Self {
        self.roles.push((
            name.to_string(),
            Some(description.to_string()),
            permissions.iter().map(|p| p.to_string()).collect(),
        ));
        self
    }

    /// Checks the permissions and roles and builds the catalog.
    pub fn build(self) -> Result<Catalog, AccessError> {
        let mut perms = BTreeMap::new();
        let mut order = Vec::new();
        for (name, description, global_only, _) in self.perms {
            let p = Permission::parse(&name)?;
            if description.len() > MAX_DESCRIPTION || description.chars().any(char::is_control) {
                return Err(AccessError::new(format!(
                    "permission `{name}`: the description must be at most {MAX_DESCRIPTION} bytes without control characters"
                )));
            }
            if perms.contains_key(&p) {
                return Err(AccessError::new(format!(
                    "permission `{name}` is registered twice"
                )));
            }
            order.push(p.clone());
            perms.insert(
                p.clone(),
                PermissionInfo {
                    permission: p,
                    description,
                    global_only,
                },
            );
        }
        let mut catalog = Catalog {
            perms,
            order,
            roles: Vec::new(),
        };
        let mut roles = Vec::new();
        for (name, description, list) in self.roles {
            if !valid_role_name(&name) {
                return Err(AccessError::new(format!(
                    "role `{name}`: role names must match [a-z0-9]([a-z0-9-]{{0,61}}[a-z0-9])?"
                )));
            }
            if roles.iter().any(|r: &Role| r.name == name) {
                return Err(AccessError::new(format!("role `{name}` is defined twice")));
            }
            let (permissions, explicit) = catalog
                .expand(&list)
                .map_err(|e| AccessError::new(format!("role `{name}`: {e}")))?;
            roles.push(Role {
                name,
                description,
                permissions,
                builtin: true,
                explicit,
            });
        }
        catalog.roles = roles;
        Ok(catalog)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_syntax() {
        for ok in ["launches:read", "test-runs:write", "a:b", "x_y:z1"] {
            assert!(Permission::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "launches",
            "launches:",
            ":read",
            "Launches:read",
            "a:b:c",
            "a b:c",
            "1a:b",
            "a-:b",
            "a:*",
        ] {
            assert!(Permission::parse(bad).is_err(), "{bad}");
        }
        let p = Permission::parse("launches:read").unwrap();
        assert_eq!(p.resource(), "launches");
        assert_eq!(p.action(), "read");
        assert_eq!(p.to_string(), "launches:read");
        assert_eq!(
            serde_json::to_value(&p).unwrap(),
            serde_json::json!("launches:read")
        );
    }

    #[test]
    fn builder_expands_wildcards_and_validates() {
        let c = Catalog::builder()
            .permission("launches:read", "r")
            .permission("launches:write", "w")
            .global_permission("settings:write", "s")
            .role("viewer", &["launches:read"])
            .role("editor", &["launches:*", "tokens:read"])
            .role("admin", &["*"])
            .build()
            .unwrap();
        assert_eq!(c.permissions().count(), 5);
        assert_eq!(c.role("editor").unwrap().permissions.len(), 3);
        assert_eq!(c.role("admin").unwrap().permissions.len(), 5);
        assert!(c.is_global_only(&c.require("settings:write")));
        assert!(!c.is_global_only(&c.require("tokens:write")));
        assert!(c.permission("nope:read").is_none());
        assert!(c.permission("not valid").is_none());

        let err = |b: CatalogBuilder| b.build().unwrap_err().to_string();
        assert!(
            err(Catalog::builder()
                .permission("a:b", "x")
                .permission("a:b", "y"))
            .contains("registered twice")
        );
        assert!(err(Catalog::builder().permission("bad", "x")).contains("resource:action"));
        assert!(err(Catalog::builder().role("viewer", &["nope:read"])).contains("unknown"));
        assert!(err(Catalog::builder().role("viewer", &["nope:*"])).contains("unknown"));
        assert!(err(Catalog::builder().role("Viewer", &["*"])).contains("role names"));
        assert!(
            err(Catalog::builder().role("a", &["*"]).role("a", &["*"])).contains("defined twice")
        );
        assert!(err(Catalog::builder().role("a", &[])).contains("must not be empty"));
        let renamed = Catalog::builder()
            .global_permission("tokens:write", "only global here")
            .build()
            .unwrap();
        assert!(renamed.is_global_only(&renamed.require("tokens:write")));
        assert_eq!(renamed.permissions().count(), 2);
    }

    #[test]
    #[should_panic(expected = "not registered")]
    fn require_panics_for_unknown_permissions() {
        Catalog::builder().build().unwrap().require("x:y");
    }
}
