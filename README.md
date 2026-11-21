# FransHub platform

Shared foundation of FransHub products: Rust crates for access control, authentication, OIDC
sign-in, PostgreSQL stores, observability and HTTP serving, plus a React shell for product UIs.
The code started in FastMock and was made product-neutral.

| Package | What it gives a product |
|---|---|
| [`franshub-access`](crates/franshub-access) | Permission catalog, roles, bindings, the access file, access decisions, audit records |
| [`franshub-auth`](crates/franshub-auth) | `Platform`, the `Auth` extractor, static and managed tokens, `/api/v1/me`, `/api/v1/tokens` |
| [`franshub-oidc`](crates/franshub-oidc) | OIDC sign-in with PKCE and server-side sessions, bearer JWT validation |
| [`franshub-store-pg`](crates/franshub-store-pg) | PostgreSQL token, session and audit stores with embedded migrations |
| [`franshub-observe`](crates/franshub-observe) | Logs, OTLP export, Prometheus metrics, request ids, `traceparent` helpers |
| [`franshub-http`](crates/franshub-http) | rustls serving, security headers and CSP, embedded SPA assets, uniform API errors |
| [`franshub-redact`](crates/franshub-redact) | Redaction of secrets in headers, queries, JSON and text |
| [`@franshub/ui-shell`](packages/ui-shell) | Theme, app shell, command palette, `useMe()`, `useCan()` for React + Mantine |

All crates use edition 2024 and are Apache-2.0 licensed.

## Putting it together

A product registers its permissions, loads the operator's access file, builds a `Platform`,
mounts the platform routes next to its own, and checks permissions in its handlers:

```rust
use std::sync::Arc;
use axum::{Router, extract::State, routing::get};
use franshub_access::{AccessPolicy, Catalog};
use franshub_auth::{Auth, Platform, PlatformState, StaticTokens, require, routes};
use franshub_http::ApiResult;
use franshub_store_pg::PgPlatformStore;

#[derive(Clone)]
struct AppState {
    platform: Arc<Platform>,
}

impl PlatformState for AppState {
    fn platform(&self) -> &Platform {
        &self.platform
    }
}

async fn list_launches(State(s): State<AppState>, auth: Auth) -> ApiResult<String> {
    require(&auth, &s.platform.permission("launches:read"), Some("team-a"))?;
    Ok("[]".into())
}

async fn start() -> anyhow::Result<Router> {
    let catalog = Arc::new(
        Catalog::builder()
            .permission("launches:read", "Read launches and their results")
            .permission("launches:write", "Create and finish launches")
            .global_permission("settings:write", "Change server settings")
            .role("viewer", &["launches:read"])
            .role("editor", &["launches:*", "tokens:*"])
            .role("admin", &["*"])
            .build()?,
    );
    let policy = Arc::new(AccessPolicy::load(catalog, "/etc/fastproof/access.yaml".as_ref())?);

    let pool = sqlx::PgPool::connect("postgres://fastproof@db.example.com/fastproof").await?;
    franshub_store_pg::migrate(&pool).await?;
    let store = Arc::new(PgPlatformStore::new(pool));

    let platform = Arc::new(
        Platform::builder(policy.clone())
            .static_tokens(StaticTokens::from_file("/etc/fastproof/tokens".as_ref(), &policy)?)
            .managed_tokens(store.clone(), "fp_")
            .audit(store.clone())
            .build()?,
    );
    let state = AppState { platform: platform.clone() };
    Ok(routes::<AppState>()
        .route("/api/v1/launches", get(list_launches))
        .merge(platform.oidc_router())
        .with_state(state))
}
```

## franshub-access

- `Permission`: a checked `resource:action` name. `Catalog::builder()` registers permissions
  (`.permission(name, description)`, `.global_permission(...)` for global-only ones) and built-in
  roles (`.role(name, &["launches:read", "launches:*", "*"])`), then `.build()`. Every catalog
  also holds `tokens:read` and `tokens:write`, which the tokens API checks.
- `AccessPolicy::load(catalog, path)` / `AccessPolicy::parse(catalog, yaml)` read the access file;
  errors are one line naming the entry, such as `bindings[2] (group:qa): unknown role ...`.
- `Binding { subject: Subject::{User, Group, Token(Uuid)}, role, scopes: Scopes::{Global,
  List(..), All} }`. `All` (`scopes: ["*"]`) covers every scope, including scopes created later,
  but never grants global-only permissions; nor does a list of scopes.
- `Principal { kind, name, perms, roles, groups, token_id }` with `allowed(&perm, scope)` and
  `denial(&perm, scope)` (the reason, or `None`). `policy.user_principal(name, groups)` maps OIDC
  users and groups to bindings.
- `AuditEvent`, `AuditFilter` (action or `prefix*`, principal, scope, time window, keyset paging
  with `before`), `AuditPage`, the `AuditStore` trait and a bounded `MemoryAuditStore`.

```yaml
roles:
  - name: release-manager
    permissions: ["launches:*"]
bindings:
  - subject: group:qa
    role: viewer
    scopes: [team-a, team-b]
  - subject: group:platform
    role: admin
    global: true
  - subject: user:alice
    role: release-manager
    scopes: ["*"]
```

## franshub-auth

- `Platform::builder(policy)` with `.static_tokens(..)`, `.managed_tokens(store, "fp_")`,
  `.oidc(runtime)`, `.audit(store)`, `.scopes(source)`, `.settings(PlatformSettings { .. })`,
  `.build()`. At least static tokens or OIDC must be configured.
- `PlatformState` (`fn platform(&self) -> &Platform`) on the product's state; `Auth` is the
  extractor (`auth.principal`, `auth.method`). Missing, unknown, expired and revoked credentials
  all answer the same `401 {"code":"unauthorized","message":"authentication required"}`.
  `require(&principal, &perm, scope)` answers the uniform 403 with `details.required`.
- Order of authentication: an `Authorization` header decides alone (static tokens in constant
  time, then OIDC bearer JWTs, then managed tokens); otherwise the session cookie, and then
  requests other than GET and HEAD need `X-FransHub-Request: 1`. A foreign `Origin` is refused.
- Static tokens file: `name:role:sha256:<hex>` (or bare hex, or a plain value of 16+ bytes).
- Managed tokens: `<prefix><64 hex>`, only SHA-256 stored, mandatory expiry, a per-replica cache
  with TTL (revocations reach other replicas within it), last-use writes at most once a minute,
  tokens created by tokens never outlive their parent and are revoked with it.
- `routes::<S>()` mounts `GET /api/v1/me` and `GET|POST /api/v1/tokens`,
  `GET /api/v1/tokens/options`, `GET /api/v1/tokens/self`, `GET|DELETE /api/v1/tokens/{id}`. A
  caller can only grant what it holds in every requested scope (and `*` only what it holds
  globally or through its own `*`); the options endpoint computes those choices.
- `ScopeSource` tells the platform which scopes (projects, teams) exist.
- `Platform::maintain()` deletes tokens inactive for 90 days; run it periodically.

## franshub-oidc

- `OidcConfig` (issuer, client id, client secret or secret file, redirect URL ending in
  `/auth/callback`, scopes, username and groups claims (dotted paths work), allowed algorithms,
  API audience, CA file, session TTL and idle timeout, allowed hosts, cookie name, insecure cookie
  for loopback only, post-logout redirect, return prefix); `OidcConfig::from_env("FASTPROOF_", ..)`
  reads `FASTPROOF_OIDC_*`. `OidcSettings::new(config)` checks it.
- `Oidc::new(settings)`, `OidcRuntime::new(oidc, sessions, policy).with_audit(..)`, then
  `runtime.start().await` (discovery; an unreachable provider is retried in the background).
- `franshub_oidc::router(runtime)` (or `platform.oidc_router()`): `GET /auth/login?return=/path`,
  `GET /auth/callback`, `POST /auth/logout` (returns `{"loggedOut", "logoutUrl"}`).
- `SessionStore` trait with `MemorySessionStore`; sessions and pending logins are stored under
  SHA-256 hashes of the browser's secrets. Cookies: `__Host-<name>_session`, `HttpOnly`, `Secure`,
  `SameSite=Lax`.
- JWT validation: RS256, PS256, ES256, EdDSA only (configurable subset), JWKS cache with an hourly
  refresh and rate-limited refreshes for unknown `kid`s.

## franshub-store-pg

- `PgPlatformStore::new(pool)` implements `TokenStore`, `SessionStore` and `AuditStore`.
- `franshub_store_pg::migrate(&pool)` applies the embedded migrations under a polled advisory
  lock; `franshub_store_pg::migrator()` exposes them; `check_schema(&pool)` verifies them.
- Migrations are tracked in `platform_schema_migrations`, apart from the product's
  `_sqlx_migrations`. Tables: `platform_api_tokens`, `platform_sessions`,
  `platform_pending_logins`, `platform_audit`. Migrations are additive; indexes are created with
  `CREATE INDEX CONCURRENTLY` in their own no-transaction migrations.

## franshub-observe

- `init(TelemetryConfig::new("fastproof", LogFormat::Json))` installs JSON or text logs, OTLP
  traces and logs when `OTEL_EXPORTER_OTLP_*ENDPOINT` is set, and the Prometheus recorder
  (`telemetry.prometheus`); `metrics_router(handle)` serves `GET /metrics`.
- Middleware: `http_metrics` (`http_requests_total`, `http_request_duration_seconds` by route
  template) and `request_id` (`X-Request-Id`, `RequestId` extension, request span).
- `parse_traceparent`, `TraceContext`, `attach_parent`, `outgoing_traceparent`.

```rust
use axum::{Router, middleware};
let app: Router = Router::new()
    .layer(middleware::from_fn(franshub_observe::http_metrics))
    .layer(middleware::from_fn(franshub_observe::request_id));
```

## franshub-http

- `ApiError` / `ApiResult` / `ApiJson`: `{"code", "message", "details"?}` for every error,
  including JSON body rejections; internal causes are logged, never returned.
- `server_config(&TlsFiles { .. })` (rustls with ring, optional client certificates) and
  `serve(listener, router, tls, shutdown, ServeOptions::default())` with graceful shutdown;
  `shutdown_signal()`; `ClientCertFingerprint` request extension.
- `security_headers` middleware, `Csp::strict()` builder, `origin_allowed`, `body_limit`,
  `request_timeout`.
- `spa_router::<Assets, S>(SpaConfig { .. })` for a `#[derive(rust_embed::RustEmbed)]` type:
  hashed `assets/` files are `immutable`, `index.html` is `no-cache` (with an optional style
  nonce), client routes fall back to `index.html`, unknown `api/` and `auth/` paths answer a JSON
  404.

## franshub-redact

`Redactor::with_defaults()` masks sensitive headers (keeping the auth scheme), query parameters,
JSON keys at any depth, keys inside XML, multipart and broken JSON text, and registered literals
(`register_literal`); `body(bytes, content_type, max)` returns safe, truncated text.

## @franshub/ui-shell

React 19 + Mantine 9 package: `FransHubProvider` (dark by default, remembered toggle),
`AppShellLayout`, `CommandPalette` (Ctrl+K), `AuthProvider` + `useMe()` (redirects to
`/auth/login` on 401), `useCan(perm, scope)` / `<Can>`, `apiFetch` (adds `X-FransHub-Request`),
`ErrorState`, `EmptyState`. See [packages/ui-shell/README.md](packages/ui-shell/README.md).

## Development

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
FRANSHUB_TEST_DATABASE_URL=postgres://user@localhost:5432/postgres cargo test --workspace
cd packages/ui-shell && npm ci && npm run lint && npm run typecheck && npm test && npm run build
```

PostgreSQL tests run when `FRANSHUB_TEST_DATABASE_URL` points to a role that may create
databases; each test creates and drops its own `platform_test_*` database. Without the variable
they are skipped.

Security issues: see [SECURITY.md](SECURITY.md).
