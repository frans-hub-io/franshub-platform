//! The [`Platform`] a product keeps in its axum state, authentication, and the [`Auth`]
//! extractor.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, header};
use chrono::Utc;
use franshub_access::{
    AccessPolicy, AuditEvent, AuditStore, Binding, Permission, Principal, PrincipalKind, Scopes,
    Subject, valid_scope_key,
};
use franshub_http::{ApiError, origin_allowed};
use franshub_oidc::{OidcRuntime, csrf_header_ok, jwt};
use serde::Serialize;

use crate::static_tokens::{MAX_TOKEN_BYTES, StaticTokens};
use crate::tokens::{ApiToken, Lookup, TokenFormat, TokenService, TokenStore};

/// Default lifetime of a managed token, in days, when the request sets none.
pub const DEFAULT_TOKEN_DAYS: u32 = 90;
/// Revoked and expired tokens are kept this long for inspection, then deleted by
/// [`Platform::maintain`].
pub const KEEP_INACTIVE_DAYS: i64 = 90;

/// The scopes a product has (projects, teams, spaces): used to check scope keys of new tokens and
/// to list the choices of `GET /api/v1/tokens/options`.
#[async_trait]
pub trait ScopeSource: Send + Sync {
    /// Whether a scope with this key exists.
    async fn exists(&self, key: &str) -> anyhow::Result<bool>;
    /// Every scope key (the options endpoint filters them by what the caller may see).
    async fn list(&self) -> anyhow::Result<Vec<String>>;
}

/// A fixed list of scopes.
#[derive(Clone, Debug, Default)]
pub struct StaticScopes(pub Vec<String>);

#[async_trait]
impl ScopeSource for StaticScopes {
    async fn exists(&self, key: &str) -> anyhow::Result<bool> {
        Ok(self.0.iter().any(|s| s == key))
    }

    async fn list(&self) -> anyhow::Result<Vec<String>> {
        Ok(self.0.clone())
    }
}

/// How a request authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthMethod {
    /// OIDC session cookie.
    Session,
    /// OIDC bearer JWT.
    Bearer,
    /// Static token.
    StaticToken,
    /// Managed token.
    ManagedToken,
}

/// The authenticated caller of a request: an axum extractor. Missing or invalid credentials
/// answer 401 with the uniform body, whatever the reason; a store outage answers 503.
///
/// ```no_run
/// use franshub_auth::{Auth, PlatformState};
/// use franshub_http::ApiResult;
///
/// async fn list_launches<S: PlatformState>(
///     axum::extract::State(state): axum::extract::State<S>,
///     auth: Auth,
/// ) -> ApiResult<String> {
///     let read = state.platform().permission("launches:read");
///     franshub_auth::require(&auth, &read, Some("team-a"))?;
///     Ok(format!("hello {}", auth.principal.name))
/// }
/// ```
#[derive(Clone, Debug)]
pub struct Auth {
    /// Who is calling and what it may do.
    pub principal: Principal,
    /// How it authenticated.
    pub method: AuthMethod,
}

impl std::ops::Deref for Auth {
    type Target = Principal;

    fn deref(&self) -> &Principal {
        &self.principal
    }
}

/// Implemented by the product's axum state to give the platform routes and the [`Auth`]
/// extractor access to the [`Platform`].
pub trait PlatformState: Clone + Send + Sync + 'static {
    /// The platform.
    fn platform(&self) -> &Platform;
}

impl PlatformState for Arc<Platform> {
    fn platform(&self) -> &Platform {
        self
    }
}

impl<S: PlatformState> FromRequestParts<S> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let Some(a) = parts.extensions.get::<Auth>() {
            return Ok(a.clone());
        }
        let a = state
            .platform()
            .authenticate(&parts.headers, &parts.method)
            .await?;
        parts.extensions.insert(a.clone());
        Ok(a)
    }
}

/// `Ok` when the principal holds `perm` globally or, with a scope, in that scope; otherwise a
/// 403 with the uniform body (`details.required`, `details.scope`), a warning on the `audit`
/// target and the `auth_denials_total` counter.
pub fn require(p: &Principal, perm: &Permission, scope: Option<&str>) -> Result<(), ApiError> {
    match p.denial(perm, scope) {
        None => Ok(()),
        Some(d) => Err(deny(p, &d.reason, perm, scope)),
    }
}

pub(crate) fn deny(p: &Principal, msg: &str, perm: &Permission, scope: Option<&str>) -> ApiError {
    metrics::counter!("auth_denials_total").increment(1);
    tracing::warn!(target: "audit", principal = %p.name, kind = p.kind.as_str(), permission = %perm, scope = scope.unwrap_or_default(), "request rejected: permission missing");
    let mut details = serde_json::json!({"required": perm.as_str()});
    if let Some(s) = scope {
        details["scope"] = serde_json::json!(s);
    }
    ApiError::forbidden(msg).with_details(details)
}

/// Settings of a [`Platform`].
#[derive(Clone, Debug)]
pub struct PlatformSettings {
    /// Longest managed token lifetime, in days.
    pub token_max_days: u32,
    /// How long a revoked token may still work on another replica (cache TTL).
    pub token_cache_ttl: Duration,
    /// Origins besides the request's own that may call the API from a browser.
    pub allowed_origins: Vec<String>,
}

impl Default for PlatformSettings {
    fn default() -> Self {
        Self {
            token_max_days: 365,
            token_cache_ttl: Duration::from_secs(10),
            allowed_origins: Vec::new(),
        }
    }
}

/// Everything the platform routes need: the access policy, static tokens, managed tokens, OIDC,
/// the audit store and the product's scopes.
pub struct Platform {
    policy: Arc<AccessPolicy>,
    static_tokens: StaticTokens,
    tokens: Option<Arc<TokenService>>,
    oidc: Option<Arc<OidcRuntime>>,
    audit: Option<Arc<dyn AuditStore>>,
    scopes: Arc<dyn ScopeSource>,
    settings: PlatformSettings,
}

impl std::fmt::Debug for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Platform")
            .field("static_tokens", &self.static_tokens)
            .field("managed_tokens", &self.tokens.is_some())
            .field("oidc", &self.oidc.is_some())
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// Builds a [`Platform`].
pub struct PlatformBuilder {
    policy: Arc<AccessPolicy>,
    static_tokens: StaticTokens,
    token_store: Option<Arc<dyn TokenStore>>,
    token_prefix: Option<String>,
    oidc: Option<Arc<OidcRuntime>>,
    audit: Option<Arc<dyn AuditStore>>,
    scopes: Option<Arc<dyn ScopeSource>>,
    settings: PlatformSettings,
}

impl PlatformBuilder {
    /// Static tokens.
    pub fn static_tokens(mut self, t: StaticTokens) -> Self {
        self.static_tokens = t;
        self
    }

    /// Managed tokens in this store, with values `<prefix><64 hex>` (for example `fp_`).
    pub fn managed_tokens(mut self, store: Arc<dyn TokenStore>, prefix: &str) -> Self {
        self.token_store = Some(store);
        self.token_prefix = Some(prefix.to_string());
        self
    }

    /// OIDC sign-in and bearer JWTs.
    pub fn oidc(mut self, rt: Arc<OidcRuntime>) -> Self {
        self.oidc = Some(rt);
        self
    }

    /// Where `token.create` and `token.revoke` events go.
    pub fn audit(mut self, audit: Arc<dyn AuditStore>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// The product's scopes; without one, any syntactically valid scope key is accepted and the
    /// options list the scopes named in the access file.
    pub fn scopes(mut self, scopes: Arc<dyn ScopeSource>) -> Self {
        self.scopes = Some(scopes);
        self
    }

    /// Settings.
    pub fn settings(mut self, settings: PlatformSettings) -> Self {
        self.settings = settings;
        self
    }

    /// Checks the combination and builds the platform. At least one way to sign in is needed:
    /// static tokens or OIDC (managed tokens are created by an authenticated caller).
    pub fn build(self) -> anyhow::Result<Platform> {
        if self.static_tokens.is_empty() && self.oidc.is_none() {
            anyhow::bail!(
                "no way to authenticate: configure static tokens or OIDC sign-in (managed tokens are created by an authenticated caller)"
            );
        }
        if self.settings.token_max_days == 0 {
            anyhow::bail!("the longest token lifetime must be at least one day");
        }
        let tokens = match (self.token_store, self.token_prefix) {
            (Some(store), Some(prefix)) => Some(Arc::new(TokenService::new(
                store,
                TokenFormat::new(&prefix)?,
                self.settings.token_cache_ttl,
            ))),
            _ => None,
        };
        let scopes = self.scopes.unwrap_or_else(|| {
            let mut keys = BTreeSet::new();
            for b in self.policy.bindings() {
                if let Scopes::List(l) = &b.scopes {
                    keys.extend(l.iter().cloned());
                }
            }
            Arc::new(AnyScope(keys.into_iter().collect()))
        });
        Ok(Platform {
            policy: self.policy,
            static_tokens: self.static_tokens,
            tokens,
            oidc: self.oidc,
            audit: self.audit,
            scopes,
            settings: self.settings,
        })
    }
}

struct AnyScope(Vec<String>);

#[async_trait]
impl ScopeSource for AnyScope {
    async fn exists(&self, key: &str) -> anyhow::Result<bool> {
        Ok(valid_scope_key(key))
    }

    async fn list(&self) -> anyhow::Result<Vec<String>> {
        Ok(self.0.clone())
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?
        .trim();
    (!token.is_empty()).then_some(token)
}

fn failure(reason: &'static str) {
    metrics::counter!("auth_failures_total", "reason" => reason).increment(1);
}

impl Platform {
    /// A builder over the access policy.
    pub fn builder(policy: Arc<AccessPolicy>) -> PlatformBuilder {
        PlatformBuilder {
            policy,
            static_tokens: StaticTokens::none(),
            token_store: None,
            token_prefix: None,
            oidc: None,
            audit: None,
            scopes: None,
            settings: PlatformSettings::default(),
        }
    }

    /// The access policy.
    pub fn policy(&self) -> &AccessPolicy {
        &self.policy
    }

    /// A registered permission; panics when it is not in the catalog (a wiring error).
    pub fn permission(&self, name: &str) -> Permission {
        self.policy.catalog().require(name)
    }

    /// Static tokens.
    pub fn static_tokens(&self) -> &StaticTokens {
        &self.static_tokens
    }

    /// Managed tokens, when configured.
    pub fn tokens(&self) -> Option<&Arc<TokenService>> {
        self.tokens.as_ref()
    }

    /// OIDC, when configured.
    pub fn oidc(&self) -> Option<&Arc<OidcRuntime>> {
        self.oidc.as_ref()
    }

    /// The product's scopes.
    pub fn scopes(&self) -> &Arc<dyn ScopeSource> {
        &self.scopes
    }

    /// Settings.
    pub fn settings(&self) -> &PlatformSettings {
        &self.settings
    }

    /// The `/auth/*` routes: OIDC sign-in when configured, 404 `sso_disabled` otherwise.
    pub fn oidc_router<S: Clone + Send + Sync + 'static>(&self) -> Router<S> {
        match &self.oidc {
            Some(rt) => franshub_oidc::router(rt.clone()),
            None => franshub_oidc::disabled_router(),
        }
    }

    /// Records an audit event; failures are logged, never returned.
    pub async fn audit(&self, event: AuditEvent) {
        if let Some(a) = &self.audit
            && let Err(e) = a.append(&event).await
        {
            metrics::counter!("store_errors_total", "store" => "audit").increment(1);
            tracing::error!(error = %e, action = %event.action, "recording an audit event failed");
        }
    }

    /// The audit store, when configured.
    pub fn audit_store(&self) -> Option<&Arc<dyn AuditStore>> {
        self.audit.as_ref()
    }

    /// The principal of a managed token, or `None` when its role no longer exists.
    pub fn token_principal(&self, t: &ApiToken) -> Option<Principal> {
        self.policy.role(&t.role)?;
        let mut bindings = vec![Binding {
            subject: Subject::Token(t.id),
            role: t.role.clone(),
            scopes: t.binding_scopes(),
        }];
        bindings.extend(self.policy.bindings_for_token(t.id));
        let mut p = self
            .policy
            .principal(PrincipalKind::ApiToken, &t.name, &bindings);
        p.token_id = Some(t.id);
        Some(p)
    }

    /// Authenticates a request. An `Authorization` header decides alone: static tokens (constant
    /// time), then OIDC bearer JWTs (when an API audience is configured), then managed tokens.
    /// Without the header, the OIDC session cookie; requests other than GET and HEAD then need
    /// `X-FransHub-Request: 1`. Every failure to authenticate is the same 401.
    pub async fn authenticate(
        &self,
        headers: &HeaderMap,
        method: &Method,
    ) -> Result<Auth, ApiError> {
        if !origin_allowed(headers, &self.settings.allowed_origins) {
            failure("origin");
            return Err(ApiError::forbidden("origin not allowed"));
        }
        if headers.contains_key(header::AUTHORIZATION) {
            return self.bearer_auth(headers).await;
        }
        let Some(rt) = &self.oidc else {
            failure("missing");
            return Err(ApiError::unauthorized());
        };
        if !rt.has_session_cookie(headers) {
            failure("missing");
            return Err(ApiError::unauthorized());
        }
        let identity = match rt.session_identity(headers).await {
            Ok(Some(i)) => i,
            Ok(None) => {
                failure("session");
                let mut e = ApiError::unauthorized();
                if let Ok(v) = HeaderValue::from_str(&rt.clear_session_cookie()) {
                    e = e.with_header(header::SET_COOKIE, v);
                }
                return Err(e);
            }
            Err(e) => {
                metrics::counter!("store_errors_total", "store" => "sessions").increment(1);
                tracing::error!(error = %e, "looking up a session failed");
                return Err(ApiError::unavailable("authentication is unavailable"));
            }
        };
        if method != Method::GET && method != Method::HEAD && !csrf_header_ok(headers) {
            failure("csrf");
            tracing::warn!(target: "audit", principal = %identity.name, "request rejected: cookie-authenticated change without the X-FransHub-Request header");
            return Err(ApiError::forbidden("missing X-FransHub-Request: 1 header"));
        }
        match self.policy.user_principal(&identity.name, &identity.groups) {
            Some(p) => Ok(Auth {
                principal: p,
                method: AuthMethod::Session,
            }),
            None => Err(self.no_binding(&identity.name)),
        }
    }

    fn no_binding(&self, name: &str) -> ApiError {
        failure("no_binding");
        tracing::warn!(target: "audit", principal = %name, kind = "user", "request rejected: no binding for the user or its groups");
        ApiError::forbidden("no access: no binding applies to the user or its groups")
    }

    async fn bearer_auth(&self, headers: &HeaderMap) -> Result<Auth, ApiError> {
        let Some(value) = bearer(headers) else {
            failure("token");
            return Err(ApiError::unauthorized());
        };
        if value.len() <= MAX_TOKEN_BYTES
            && let Some(p) = self.static_tokens.authenticate(value, &self.policy)
        {
            return Ok(Auth {
                principal: p,
                method: AuthMethod::StaticToken,
            });
        }
        if let Some(rt) = self.oidc.as_ref().filter(|o| o.oidc.api_enabled())
            && jwt::jwt_shaped(value)
        {
            return match rt.oidc.bearer_identity(value).await {
                Ok(id) => match self.policy.user_principal(&id.name, &id.groups) {
                    Some(p) => Ok(Auth {
                        principal: p,
                        method: AuthMethod::Bearer,
                    }),
                    None => Err(self.no_binding(&id.name)),
                },
                Err(e) => {
                    failure("jwt");
                    tracing::warn!(target: "audit", reason = %e, "request rejected: invalid bearer JWT");
                    Err(ApiError::unauthorized())
                }
            };
        }
        let Some(svc) = &self.tokens else {
            failure("token");
            return Err(ApiError::unauthorized());
        };
        match svc.lookup(value).await {
            Ok(Lookup::Valid(t)) => match self.token_principal(&t) {
                Some(p) => {
                    svc.touch(t.id);
                    Ok(Auth {
                        principal: p,
                        method: AuthMethod::ManagedToken,
                    })
                }
                None => {
                    failure("token");
                    tracing::warn!(target: "audit", token = %t.name, role = %t.role, "request rejected: the role of the managed token is not defined");
                    Err(ApiError::unauthorized())
                }
            },
            Ok(Lookup::Expired(t)) => {
                failure("expired");
                tracing::warn!(target: "audit", token = %t.name, "request rejected: token expired");
                Err(ApiError::unauthorized())
            }
            Ok(Lookup::Revoked(t)) => {
                failure("revoked");
                tracing::warn!(target: "audit", token = %t.name, "request rejected: token revoked");
                Err(ApiError::unauthorized())
            }
            Ok(Lookup::Unknown) => {
                failure("token");
                Err(ApiError::unauthorized())
            }
            Err(e) => {
                metrics::counter!("store_errors_total", "store" => "tokens").increment(1);
                tracing::error!(error = %e, "looking up a managed token failed");
                Err(ApiError::unavailable("authentication is unavailable"))
            }
        }
    }

    /// Deletes managed tokens revoked or expired more than [`KEEP_INACTIVE_DAYS`] ago and updates
    /// the `api_tokens_active` gauge. Run it periodically, for example hourly.
    pub async fn maintain(&self) {
        let Some(svc) = &self.tokens else { return };
        let cutoff = Utc::now() - chrono::Duration::days(KEEP_INACTIVE_DAYS);
        match svc.store().purge_inactive_before(cutoff).await {
            Ok(n) if n > 0 => tracing::info!(deleted = n, "old revoked and expired tokens deleted"),
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "token retention failed"),
        }
        self.refresh_gauge().await;
    }

    pub(crate) async fn refresh_gauge(&self) {
        let Some(svc) = &self.tokens else { return };
        match svc.store().count_active(Utc::now()).await {
            Ok(n) => metrics::gauge!("api_tokens_active").set(n as f64),
            Err(e) => {
                metrics::counter!("store_errors_total", "store" => "tokens").increment(1);
                tracing::warn!(error = %e, "counting active tokens failed");
            }
        }
    }
}
