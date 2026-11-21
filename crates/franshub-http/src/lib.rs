//! HTTP building blocks for FransHub products.
//!
//! - [`ApiError`] and [`ApiJson`]: the uniform JSON error `{"code", "message", "details"?}`.
//! - [`server_config`] and [`serve`]: rustls (ring) with optional client certificates, HTTP/1
//!   and HTTP/2, graceful shutdown.
//! - [`security_headers`], [`Csp`], [`origin_allowed`], [`body_limit`], [`request_timeout`].
//! - [`spa_router`]: an embedded single-page application with correct caching and SPA fallback.

pub mod assets;
pub mod error;
pub mod headers;
pub mod server;

pub use assets::{IMMUTABLE, NO_CACHE, SpaConfig, content_type, spa_router};
pub use error::{ApiError, ApiJson, ApiResult, ErrorBody};
pub use headers::{
    Csp, SecurityHeaders, body_limit, origin_allowed, request_timeout, security_headers,
};
pub use rust_embed;
pub use server::{
    ClientCertFingerprint, ServeOptions, TlsFiles, serve, server_config, shutdown_signal,
};
