//! `/auth/login`, `/auth/callback` and `/auth/logout`: the backend-for-frontend sign-in.

use std::sync::{Arc, Weak};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use franshub_access::{AccessPolicy, AuditEvent, AuditStore, Principal};
use franshub_http::{ApiError, origin_allowed};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::client::{Identity, Oidc, cookie_value};
use crate::session::{self, PendingLogin, SessionStore, Sessions, random_secret};

/// Header that cookie-authenticated requests other than GET and HEAD must send with the value
/// `1`. Browsers cannot add it to cross-site form posts, which stops CSRF.
pub const CSRF_HEADER: &str = "x-franshub-request";

/// Whether the request carries `X-FransHub-Request: 1`.
pub fn csrf_header_ok(headers: &HeaderMap) -> bool {
    headers
        .get(CSRF_HEADER)
        .is_some_and(|v| v.as_bytes() == b"1")
}

const PURGE_EVERY: Duration = Duration::from_secs(300);

/// Everything the sign-in routes and session authentication need: the OIDC client, the session
/// store, the access policy (a user needs a binding to sign in), and the audit store.
pub struct OidcRuntime {
    /// The OIDC client.
    pub oidc: Arc<Oidc>,
    sessions: Arc<dyn SessionStore>,
    policy: Arc<AccessPolicy>,
    audit: Option<Arc<dyn AuditStore>>,
    allowed_origins: Vec<String>,
}

impl std::fmt::Debug for OidcRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcRuntime")
            .field("settings", &self.oidc.settings)
            .finish_non_exhaustive()
    }
}

impl OidcRuntime {
    /// A runtime for a client, a session store and the access policy.
    pub fn new(
        oidc: Arc<Oidc>,
        sessions: Arc<dyn SessionStore>,
        policy: Arc<AccessPolicy>,
    ) -> Self {
        Self {
            oidc,
            sessions,
            policy,
            audit: None,
            allowed_origins: Vec::new(),
        }
    }

    /// Records `auth.login`, `auth.logout` and `auth.login_failed` events.
    pub fn with_audit(mut self, audit: Arc<dyn AuditStore>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Origins besides the request's own that may post to `/auth/logout`.
    pub fn with_allowed_origins(mut self, origins: Vec<String>) -> Self {
        self.allowed_origins = origins;
        self
    }

    /// Discovers the provider (see [`Oidc::start`]) and purges expired sessions and pending
    /// logins every five minutes in the background.
    pub async fn start(self: &Arc<Self>) -> anyhow::Result<()> {
        self.oidc.start().await?;
        tokio::spawn(purge(Arc::downgrade(self)));
        Ok(())
    }

    /// The session logic over the store.
    pub fn sessions(&self) -> Sessions<'_> {
        Sessions {
            store: self.sessions.as_ref(),
            life: self.oidc.lifetimes(),
        }
    }

    /// The access policy.
    pub fn policy(&self) -> &AccessPolicy {
        &self.policy
    }

    /// The user of the request's session cookie: `Ok(None)` without a cookie or for an unknown
    /// or expired session; `Err` when the store fails.
    pub async fn session_identity(&self, headers: &HeaderMap) -> anyhow::Result<Option<Identity>> {
        let Some(id) = self.oidc.session_id(headers) else {
            return Ok(None);
        };
        Ok(self.sessions().get(id).await?.map(|r| Identity {
            name: r.name,
            groups: r.groups,
        }))
    }

    /// Whether the request has a session cookie at all.
    pub fn has_session_cookie(&self, headers: &HeaderMap) -> bool {
        self.oidc.session_id(headers).is_some()
    }

    /// A `Set-Cookie` value that clears the session cookie.
    pub fn clear_session_cookie(&self) -> String {
        self.oidc
            .cookie(&self.oidc.session_cookie_name(), "", Duration::ZERO)
    }

    async fn audit(&self, e: AuditEvent) {
        if let Some(a) = &self.audit
            && let Err(err) = a.append(&e).await
        {
            tracing::error!(error = %err, action = %e.action, "recording an audit event failed");
        }
    }
}

async fn purge(weak: Weak<OidcRuntime>) {
    loop {
        tokio::time::sleep(PURGE_EVERY).await;
        let Some(rt) = weak.upgrade() else { return };
        match rt.sessions.purge_expired(chrono::Utc::now()).await {
            Ok(n) if n > 0 => tracing::debug!(deleted = n, "expired sessions purged"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "purging expired sessions failed"),
        }
    }
}

/// The JSON answer of `POST /auth/logout`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutResponse {
    /// A session was found and deleted.
    pub logged_out: bool,
    /// The provider's end-session URL; the UI navigates there to end the provider session too.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logout_url: Option<String>,
}

#[derive(Deserialize)]
struct LoginQuery {
    #[serde(rename = "return")]
    return_to: Option<String>,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn plain_path(s: &str, prefix: &str, raw: bool) -> bool {
    s.len() <= 2048
        && s.starts_with(prefix)
        && !s.contains("//")
        && !s.contains('\\')
        && !s
            .chars()
            .any(|c| c.is_control() || (raw && c.is_whitespace()))
        && !s
            .split(['/', '?', '#', ';'])
            .any(|seg| seg == ".." || seg == ".")
}

/// A return path is a relative path under `prefix`: no scheme, no `//`, no backslash, no dot
/// segments, also after percent-decoding (repeatedly).
pub fn safe_return(raw: &str, prefix: &str) -> bool {
    let mut cur = raw.to_string();
    for i in 0..4 {
        if !plain_path(&cur, prefix, i == 0) {
            return false;
        }
        match percent_decode(&cur) {
            Some(d) if d == cur => return true,
            Some(d) => cur = d,
            None => return false,
        }
    }
    false
}

fn redirect(location: &str, cookies: &[String]) -> Response {
    let mut r = StatusCode::FOUND.into_response();
    if let Ok(v) = HeaderValue::from_str(location) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    r
}

fn login_result(result: &'static str) {
    metrics::counter!("oidc_logins_total", "result" => result).increment(1);
}

fn store_error(what: &str, e: &anyhow::Error) {
    metrics::counter!("store_errors_total", "store" => "sessions").increment(1);
    tracing::error!(error = %e, "{what} failed");
}

async fn login(State(rt): State<Arc<OidcRuntime>>, Query(q): Query<LoginQuery>) -> Response {
    let oidc = &rt.oidc;
    let prefix = &oidc.settings.return_prefix;
    let return_to = q.return_to.unwrap_or_else(|| prefix.clone());
    if !safe_return(&return_to, prefix) {
        return ApiError::bad_request(format!("return must be a relative path under {prefix}"))
            .into_response();
    }
    let Some(provider) = oidc.provider() else {
        login_result("unavailable");
        return ApiError::unavailable("sign-in is not available yet").into_response();
    };
    if !oidc.admit_login() {
        login_result("rate_limited");
        return ApiError::too_many_requests("too many sign-in attempts").into_response();
    }
    let state = random_secret();
    let browser = random_secret();
    let pending = PendingLogin {
        nonce: random_secret(),
        verifier: random_secret(),
        return_to,
        browser: session::digest(&browser),
    };
    if let Err(e) = rt.sessions().put_login(&state, &pending).await {
        store_error("storing a pending login", &e);
        return ApiError::unavailable("session store unavailable").into_response();
    }
    let url = oidc.authorization_url(&provider, &state, &pending);
    redirect(
        url.as_str(),
        &[oidc.cookie(&oidc.login_cookie_name(), &browser, session::LOGIN_TTL)],
    )
}

fn failed_login(oidc: &Oidc, code: &'static str) -> Response {
    redirect(
        &format!("{}?loginError={code}", oidc.settings.return_prefix),
        &[oidc.cookie(&oidc.login_cookie_name(), "", Duration::ZERO)],
    )
}

async fn audit_failure(rt: &OidcRuntime, name: Option<&str>, reason: &str) {
    rt.audit(AuditEvent::anonymous(
        name.unwrap_or("unknown"),
        Some("user"),
        "auth.login_failed",
        json!({"reason": reason}),
    ))
    .await;
}

async fn callback(
    State(rt): State<Arc<OidcRuntime>>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let oidc = rt.oidc.as_ref();
    let pending = match q.state.as_deref() {
        Some(s) => match rt.sessions().take_login(s).await {
            Ok(p) => p,
            Err(e) => {
                store_error("reading a pending login", &e);
                login_result("unavailable");
                return failed_login(oidc, "unavailable");
            }
        },
        None => None,
    };
    let Some(pending) = pending else {
        login_result("invalid_state");
        tracing::warn!(target: "audit", "sign-in callback rejected: unknown, used or expired state");
        return failed_login(oidc, "invalid_state");
    };
    let browser_ok = cookie_value(&headers, &oidc.login_cookie_name())
        .is_some_and(|b| session::digest(b) == pending.browser);
    if !browser_ok {
        login_result("invalid_state");
        tracing::warn!(target: "audit", "sign-in callback rejected: the login cookie does not match the state");
        return failed_login(oidc, "invalid_state");
    }
    if let Some(e) = q.error.as_deref() {
        let code: String = e
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .take(64)
            .collect();
        login_result("idp_error");
        audit_failure(&rt, None, &format!("identity provider error {code}")).await;
        return failed_login(oidc, "idp_error");
    }
    let Some(provider) = oidc.provider() else {
        login_result("unavailable");
        return failed_login(oidc, "unavailable");
    };
    let Some(code) = q
        .code
        .as_deref()
        .filter(|c| !c.is_empty() && c.len() <= 4096)
    else {
        login_result("invalid_state");
        return failed_login(oidc, "invalid_state");
    };
    let (id_token, access_token) = match oidc.exchange(&provider, code, &pending.verifier).await {
        Ok(t) => t,
        Err(e) => {
            login_result("token_error");
            tracing::warn!(error = %e, "code exchange failed");
            audit_failure(&rt, None, "code exchange failed").await;
            return failed_login(oidc, "failed");
        }
    };
    let claims = match oidc
        .validate(
            &id_token,
            &oidc.settings.client_id,
            Some(&pending.nonce),
            true,
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            login_result("token_error");
            metrics::counter!("auth_failures_total", "reason" => "jwt").increment(1);
            tracing::warn!(error = %e, "ID token rejected");
            audit_failure(&rt, None, &format!("ID token rejected: {e}")).await;
            return failed_login(oidc, "failed");
        }
    };
    let (mut name, mut groups) = oidc.identity(&claims);
    if (name.is_none() || groups.is_none())
        && provider.userinfo.is_some()
        && let Some(at) = access_token.as_deref()
    {
        let sub = claims
            .get("sub")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        match oidc.userinfo(&provider, at, sub).await {
            Ok(info) => {
                let (n, g) = oidc.identity(&info);
                name = name.or(n);
                groups = groups.or(g);
            }
            Err(e) => tracing::warn!(error = %e, "userinfo request failed"),
        }
    }
    let Some(name) = name else {
        login_result("token_error");
        audit_failure(
            &rt,
            None,
            &format!("no {} claim", oidc.settings.username_claim),
        )
        .await;
        return failed_login(oidc, "failed");
    };
    let groups = groups.unwrap_or_default();
    let Some(principal) = rt.policy.user_principal(&name, &groups) else {
        login_result("no_binding");
        audit_failure(&rt, Some(&name), "no binding for the user or its groups").await;
        return failed_login(oidc, "no_access");
    };
    let id = match rt
        .sessions()
        .create(&principal.name, groups.clone(), Some(id_token))
        .await
    {
        Ok(id) => id,
        Err(e) => {
            store_error("storing a session", &e);
            login_result("unavailable");
            return failed_login(oidc, "unavailable");
        }
    };
    login_result("success");
    rt.audit(AuditEvent::new(
        &principal,
        "auth.login",
        None,
        json!({"groups": groups}),
    ))
    .await;
    redirect(
        &pending.return_to,
        &[
            oidc.cookie(&oidc.session_cookie_name(), &id, oidc.settings.session_ttl),
            oidc.cookie(&oidc.login_cookie_name(), "", Duration::ZERO),
        ],
    )
}

async fn logout(State(rt): State<Arc<OidcRuntime>>, headers: HeaderMap) -> Response {
    if !origin_allowed(&headers, &rt.allowed_origins) {
        metrics::counter!("auth_failures_total", "reason" => "origin").increment(1);
        return ApiError::forbidden("origin not allowed").into_response();
    }
    if !csrf_header_ok(&headers) {
        metrics::counter!("auth_failures_total", "reason" => "csrf").increment(1);
        return ApiError::forbidden("missing X-FransHub-Request: 1 header").into_response();
    }
    let mut logged_out = false;
    let mut id_token_hint = None;
    if let Some(id) = rt.oidc.session_id(&headers) {
        match rt.sessions().delete(id).await {
            Ok(Some(r)) => {
                logged_out = true;
                id_token_hint = r.id_token.clone();
                let p = rt
                    .policy
                    .user_principal(&r.name, &r.groups)
                    .unwrap_or_else(|| Principal {
                        kind: franshub_access::PrincipalKind::User,
                        name: r.name.clone(),
                        perms: Default::default(),
                        roles: vec![],
                        groups: r.groups.clone(),
                        token_id: None,
                    });
                rt.audit(AuditEvent::new(&p, "auth.logout", None, json!({})))
                    .await;
            }
            Ok(None) => {}
            Err(e) => {
                store_error("deleting a session", &e);
                return ApiError::unavailable("session store unavailable").into_response();
            }
        }
    }
    let mut r = Json(LogoutResponse {
        logged_out,
        logout_url: rt.oidc.logout_url(id_token_hint.as_deref()),
    })
    .into_response();
    if let Ok(v) = HeaderValue::from_str(&rt.clear_session_cookie()) {
        r.headers_mut().insert(header::SET_COOKIE, v);
    }
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// The sign-in routes: `GET /auth/login?return=<path>`, `GET /auth/callback`,
/// `POST /auth/logout` (needs `X-FransHub-Request: 1`). Mount them without authentication.
pub fn router<S: Clone + Send + Sync + 'static>(rt: Arc<OidcRuntime>) -> Router<S> {
    Router::new()
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", post(logout))
        .with_state(rt)
}

/// Routes answering 404 `not_found` (uniform body) for the sign-in paths when OIDC is not
/// configured, so the UI can tell.
pub fn disabled_router<S: Clone + Send + Sync + 'static>() -> Router<S> {
    let off = || async {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "sso_disabled",
            "single sign-on is not configured",
        )
    };
    Router::new()
        .route("/auth/login", get(off))
        .route("/auth/callback", get(off))
        .route("/auth/logout", post(off))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_paths() {
        for ok in [
            "/",
            "/launches",
            "/launches/0190e0d0-0000?scope=payments",
            "/runs#top",
            "/a%20b",
        ] {
            assert!(safe_return(ok, "/"), "{ok}");
        }
        assert!(safe_return("/ui/x", "/ui/"));
        assert!(!safe_return("/other", "/ui/"));
        for bad in [
            "",
            "//evil.example.com",
            "https://evil.example.com/",
            "/a//evil.example.com",
            "/\\evil.example.com",
            "/%2F%2Fevil.example.com",
            "/%252F%252Fevil.example.com",
            "/%25252F%25252Fevil",
            "%2F",
            "/%5Cevil",
            "/../api/v1/tokens",
            "/%2e%2e/api",
            "/a\nb",
            "/a b",
            "/%0d%0aSet-Cookie:x",
            "javascript:alert(1)",
            "/%zz",
            "\\\\evil.example.com",
            "/%E0%A4%A",
        ] {
            assert!(!safe_return(bad, "/"), "{bad}");
        }
        assert!(!safe_return(&format!("/{}", "a".repeat(3000)), "/"));
    }

    #[test]
    fn csrf_header() {
        let mut h = HeaderMap::new();
        assert!(!csrf_header_ok(&h));
        h.insert(CSRF_HEADER, HeaderValue::from_static("0"));
        assert!(!csrf_header_ok(&h));
        h.insert(CSRF_HEADER, HeaderValue::from_static("1"));
        assert!(csrf_header_ok(&h));
    }
}
