//! Authentication for FransHub products.
//!
//! A product builds a [`Platform`] at start-up (access policy, static tokens, managed tokens,
//! optional OIDC, audit store, scopes), keeps it in its axum state, implements
//! [`PlatformState`], and mounts [`routes`] (`/api/v1/me`, `/api/v1/tokens…`) and
//! [`Platform::oidc_router`] (`/auth/…`) beside its own routes. Handlers take an [`Auth`]
//! argument and call [`require`].
//!
//! ```no_run
//! use std::sync::Arc;
//! use axum::Router;
//! use franshub_access::{AccessPolicy, Catalog, MemoryAuditStore};
//! use franshub_auth::{MemoryTokenStore, Platform, StaticTokens, routes};
//!
//! # fn main() -> anyhow::Result<()> {
//! let catalog = Arc::new(
//!     Catalog::builder()
//!         .permission("launches:read", "Read launches")
//!         .role("viewer", &["launches:read"])
//!         .role("admin", &["*"])
//!         .build()?,
//! );
//! let policy = Arc::new(AccessPolicy::load(catalog, "access.yaml".as_ref())?);
//! let platform = Arc::new(
//!     Platform::builder(policy.clone())
//!         .static_tokens(StaticTokens::from_file("tokens".as_ref(), &policy)?)
//!         .managed_tokens(Arc::new(MemoryTokenStore::default()), "fp_")
//!         .audit(Arc::new(MemoryAuditStore::default()))
//!         .build()?,
//! );
//! let app: Router = routes::<Arc<Platform>>()
//!     .merge(platform.oidc_router())
//!     .with_state(platform);
//! # Ok(()) }
//! ```

pub mod platform;
pub mod routes;
pub mod static_tokens;
pub mod tokens;

pub use platform::{
    Auth, AuthMethod, DEFAULT_TOKEN_DAYS, KEEP_INACTIVE_DAYS, Platform, PlatformBuilder,
    PlatformSettings, PlatformState, ScopeSource, StaticScopes, require,
};
pub use routes::{
    CreateToken, CreatedToken, GrantableRole, MeView, TokenInfo, TokenList, TokenOptions, routes,
};
pub use static_tokens::{MAX_TOKEN_BYTES, StaticTokens};
pub use tokens::{
    ApiToken, Lookup, MemoryTokenStore, TokenFormat, TokenSecret, TokenService, TokenStatus,
    TokenStore, hash_token, stored_precision,
};
