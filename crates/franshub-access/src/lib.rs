//! Access control for FransHub products.
//!
//! A product registers its permissions and built-in roles in a [`Catalog`] at start-up. The
//! operator's access file adds custom roles and [`Binding`]s of roles to users, groups and managed
//! tokens, globally, in a list of scopes, or in every scope (`*`, which also covers scopes created
//! later but never grants global-only permissions). An [`AccessPolicy`] turns the bindings of a
//! caller into a [`Principal`] whose [`Principal::allowed`] answers access questions.
//!
//! ```
//! use std::sync::Arc;
//! use franshub_access::{AccessPolicy, Catalog};
//!
//! let catalog = Arc::new(
//!     Catalog::builder()
//!         .permission("launches:read", "Read launches")
//!         .permission("launches:write", "Write launches")
//!         .role("viewer", &["launches:read"])
//!         .role("admin", &["*"])
//!         .build()
//!         .unwrap(),
//! );
//! let policy = AccessPolicy::parse(
//!     catalog.clone(),
//!     "bindings:\n  - subject: group:qa\n    role: viewer\n    scopes: [team-a]\n",
//! )
//! .unwrap();
//! let alice = policy.user_principal("alice", &["qa".to_string()]).unwrap();
//! let read = catalog.require("launches:read");
//! assert!(alice.allowed(&read, Some("team-a")));
//! assert!(!alice.allowed(&read, Some("team-b")));
//! assert!(alice.denial(&read, None).is_some());
//! ```

pub mod audit;
pub mod catalog;
pub mod grants;
pub mod policy;

pub use audit::{AuditEvent, AuditFilter, AuditPage, AuditStore, MemoryAuditStore};
pub use catalog::{
    Catalog, CatalogBuilder, PermSet, Permission, PermissionInfo, Role, TOKENS_READ, TOKENS_WRITE,
    valid_role_name,
};
pub use grants::{Denial, Grants, GrantsView, Principal, PrincipalKind};
pub use policy::{ALL_SCOPES, AccessPolicy, Binding, Scopes, Subject, valid_scope_key};

/// A configuration error: an invalid permission, role, binding or access file. The message is one
/// line that names the offending entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessError(String);

impl AccessError {
    /// An error with this message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl std::fmt::Display for AccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AccessError {}
