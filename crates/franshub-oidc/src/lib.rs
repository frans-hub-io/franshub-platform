//! OpenID Connect for FransHub products.
//!
//! - Sign-in for the UI as a backend for frontend: the authorization code flow with `state`,
//!   `nonce` and PKCE S256 (`/auth/login`, `/auth/callback`), server-side sessions in a
//!   [`SessionStore`] behind an HttpOnly cookie (`__Host-` prefixed and `Secure` unless insecure
//!   cookies are configured for local http), and logout with RP-initiated logout (`/auth/logout`).
//! - Bearer JWTs for API clients ([`Oidc::bearer_identity`]): signature (RS256, PS256, ES256,
//!   EdDSA; an allow-list), `iss`, `aud`, `exp`, `nbf`, `iat`, with a JWKS cache refreshed hourly
//!   and on unknown `kid`s at most every 5 seconds (the same unknown `kid` at most once a minute).
//! - The groups claim (a name or dotted path) maps users to `group:` bindings of the
//!   [`franshub_access::AccessPolicy`]; a user without a binding cannot sign in.
//!
//! Hardening kept from FastMock: egress only to the issuer host and allowed hosts (https, or http
//! on loopback), no redirects on the token request, bounded responses (1 MiB), bounded caches,
//! a per-replica sign-in rate limit (burst 100, 10 per second), single-use pending logins tied to
//! the browser by a login cookie, and secrets that never reach logs, `Debug` output or errors.

pub mod client;
pub mod jwt;
pub mod routes;
pub mod session;
pub mod settings;

pub use client::{
    Identity, JWKS_MIN_AGE, JWKS_MIN_REFRESH, Oidc, Provider, claim, cookie_value, groups_of,
    pkce_challenge,
};
pub use jwt::{ALL_ALGS, Alg, JwtError};
pub use routes::{
    CSRF_HEADER, LogoutResponse, OidcRuntime, csrf_header_ok, disabled_router, router, safe_return,
};
pub use session::{
    Lifetimes, MemorySessionStore, PendingLogin, SessionRecord, SessionStore, Sessions,
};
pub use settings::{CALLBACK_PATH, OidcConfig, OidcSettings};
