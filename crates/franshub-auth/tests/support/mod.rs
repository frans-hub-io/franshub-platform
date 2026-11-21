//! Test harness shared by the memory-backed tests of `franshub-auth` and the PostgreSQL-backed
//! tests of `franshub-store-pg` (included there with `#[path]`): a product-like app, a fake OIDC
//! provider, log capture and scenarios that run against any set of stores.

#![allow(dead_code, missing_docs)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use franshub_access::{AccessPolicy, AuditFilter, AuditStore, Catalog};
use franshub_auth::{
    Auth, Platform, PlatformSettings, ScopeSource, StaticTokens, TokenStore, hash_token, require,
    routes,
};
use franshub_http::ApiResult;
use franshub_oidc::{Oidc, OidcConfig, OidcRuntime, OidcSettings, SessionStore};
use http_body_util::BodyExt;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

pub const ADMIN: &str = "admin-static-token-value-0001";
pub const VIEWER: &str = "viewer-static-token-value-0001";
pub const CLIENT_ID: &str = "reports";
pub const CLIENT_SECRET: &str = "client-secret-value-0001";
pub const API_AUDIENCE: &str = "reports-api";

pub const ACCESS: &str = r#"
roles:
  - name: launch-author
    permissions: [launches:read, launches:write]
bindings:
  - subject: group:team-a-dev
    role: editor
    scopes: [team-a]
  - subject: group:platform
    role: admin
    global: true
  - subject: user:carol
    role: viewer
    global: true
  - subject: group:qa
    role: viewer
    scopes: ["*"]
  - subject: group:release
    role: editor
    scopes: ["*"]
"#;

pub struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

static LOGS: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

/// Everything logged by this test binary so far (debug level and up).
pub fn logs() -> String {
    let buf = LOGS.get_or_init(|| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let w = buf.clone();
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(move || LogBuf(w.clone()))
            .try_init();
        buf
    });
    String::from_utf8_lossy(&buf.lock().unwrap()).into_owned()
}

pub fn catalog() -> Arc<Catalog> {
    Arc::new(
        Catalog::builder()
            .permission("launches:read", "Read launches")
            .permission("launches:write", "Write launches")
            .permission("launches:delete", "Delete launches")
            .global_permission("settings:write", "Change server settings")
            .role("viewer", &["launches:read", "tokens:read"])
            .role("editor", &["launches:read", "launches:write", "tokens:*"])
            .role("admin", &["*"])
            .build()
            .unwrap(),
    )
}

pub fn policy() -> Arc<AccessPolicy> {
    Arc::new(AccessPolicy::parse(catalog(), ACCESS).unwrap())
}

#[derive(Default)]
pub struct DynScopes(pub RwLock<Vec<String>>);

#[async_trait]
impl ScopeSource for DynScopes {
    async fn exists(&self, key: &str) -> anyhow::Result<bool> {
        Ok(self.0.read().unwrap().iter().any(|s| s == key))
    }
    async fn list(&self) -> anyhow::Result<Vec<String>> {
        Ok(self.0.read().unwrap().clone())
    }
}

#[derive(Clone)]
pub struct Stores {
    pub tokens: Arc<dyn TokenStore>,
    pub sessions: Arc<dyn SessionStore>,
    pub audit: Arc<dyn AuditStore>,
}

pub fn memory_stores() -> Stores {
    Stores {
        tokens: Arc::new(franshub_auth::MemoryTokenStore::default()),
        sessions: Arc::new(franshub_oidc::MemorySessionStore::default()),
        audit: Arc::new(franshub_access::MemoryAuditStore::default()),
    }
}

#[derive(Clone)]
pub struct AppState {
    platform: Arc<Platform>,
}

impl franshub_auth::PlatformState for AppState {
    fn platform(&self) -> &Platform {
        &self.platform
    }
}

#[derive(serde::Deserialize)]
struct ScopeQ {
    scope: Option<String>,
}

async fn launches(
    State(s): State<AppState>,
    auth: Auth,
    Query(q): Query<ScopeQ>,
) -> ApiResult<axum::Json<Value>> {
    let p = s.platform.permission("launches:read");
    require(&auth, &p, q.scope.as_deref())?;
    Ok(axum::Json(json!({"launches": [], "scope": q.scope})))
}

async fn create_launch(
    State(s): State<AppState>,
    auth: Auth,
    Query(q): Query<ScopeQ>,
) -> ApiResult<StatusCode> {
    let p = s.platform.permission("launches:write");
    require(&auth, &p, q.scope.as_deref())?;
    Ok(StatusCode::CREATED)
}

async fn settings(State(s): State<AppState>, auth: Auth) -> ApiResult<StatusCode> {
    require(&auth, &s.platform.permission("settings:write"), None)?;
    Ok(StatusCode::NO_CONTENT)
}

pub struct App {
    pub router: Router,
    pub platform: Arc<Platform>,
    pub scopes: Arc<DynScopes>,
}

pub struct Resp {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Value,
    pub text: String,
}

pub struct Call<'a> {
    pub method: Method,
    pub path: &'a str,
    pub bearer: Option<&'a str>,
    pub cookie: Option<String>,
    pub csrf: bool,
    pub origin: Option<&'a str>,
    pub body: Option<Value>,
}

impl<'a> Call<'a> {
    pub fn new(method: Method, path: &'a str) -> Self {
        Self {
            method,
            path,
            bearer: None,
            cookie: None,
            csrf: false,
            origin: None,
            body: None,
        }
    }
    pub fn bearer(mut self, t: &'a str) -> Self {
        self.bearer = Some(t);
        self
    }
    pub fn cookie(mut self, c: String) -> Self {
        self.cookie = Some(c);
        self
    }
    pub fn csrf(mut self) -> Self {
        self.csrf = true;
        self
    }
    pub fn json(mut self, v: Value) -> Self {
        self.body = Some(v);
        self
    }
}

pub async fn app_with(stores: &Stores, oidc: Option<Arc<OidcRuntime>>, ttl: Duration) -> App {
    let policy = policy();
    let tokens = StaticTokens::parse(
        &format!(
            "ops:admin:sha256:{}\nci:viewer:{}\n",
            hash_token(ADMIN),
            hash_token(VIEWER)
        ),
        &policy,
    )
    .unwrap();
    let scopes = Arc::new(DynScopes(RwLock::new(vec![
        "team-a".into(),
        "team-b".into(),
    ])));
    let mut b = Platform::builder(policy)
        .static_tokens(tokens)
        .managed_tokens(stores.tokens.clone(), "fp_")
        .audit(stores.audit.clone())
        .scopes(scopes.clone())
        .settings(PlatformSettings {
            token_max_days: 365,
            token_cache_ttl: ttl,
            allowed_origins: vec!["https://ui.example.com".into()],
        });
    if let Some(o) = oidc {
        b = b.oidc(o);
    }
    let platform = Arc::new(b.build().unwrap());
    let state = AppState {
        platform: platform.clone(),
    };
    let router = routes::<AppState>()
        .route("/api/v1/launches", get(launches).post(create_launch))
        .route("/api/v1/settings", axum::routing::put(settings))
        .merge(platform.oidc_router())
        .with_state(state);
    App {
        router,
        platform,
        scopes,
    }
}

pub async fn app(stores: &Stores) -> App {
    app_with(stores, None, Duration::from_secs(10)).await
}

impl App {
    pub async fn send(&self, c: Call<'_>) -> Resp {
        let mut rb = Request::builder()
            .method(c.method)
            .uri(c.path)
            .header(header::HOST, "reports.example.com");
        if let Some(t) = c.bearer {
            rb = rb.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        if let Some(ck) = c.cookie {
            rb = rb.header(header::COOKIE, ck);
        }
        if c.csrf {
            rb = rb.header("x-franshub-request", "1");
        }
        if let Some(o) = c.origin {
            rb = rb.header(header::ORIGIN, o);
        }
        let req = match c.body {
            Some(b) => rb
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(b.to_string()))
                .unwrap(),
            None => rb.body(Body::empty()).unwrap(),
        };
        let r = self.router.clone().oneshot(req).await.unwrap();
        let status = r.status().as_u16();
        let headers = r.headers().clone();
        let bytes = r.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp {
            status,
            headers,
            body,
            text,
        }
    }

    pub async fn get(&self, path: &str, bearer: &str) -> Resp {
        self.send(Call::new(Method::GET, path).bearer(bearer)).await
    }

    pub async fn create_token(&self, bearer: &str, body: Value) -> Resp {
        self.send(
            Call::new(Method::POST, "/api/v1/tokens")
                .bearer(bearer)
                .json(body),
        )
        .await
    }

    pub async fn audit_text(&self) -> String {
        let page = self
            .platform
            .audit_store()
            .unwrap()
            .query(&AuditFilter {
                limit: Some(1000),
                ..Default::default()
            })
            .await
            .unwrap();
        serde_json::to_string(&page).unwrap()
    }
}

pub fn assert_uniform_401(r: &Resp, what: &str) {
    assert_eq!(r.status, 401, "{what}: {}", r.text);
    assert_eq!(
        r.body,
        json!({"code": "unauthorized", "message": "authentication required"}),
        "{what}"
    );
    assert_eq!(r.headers[header::WWW_AUTHENTICATE], "Bearer", "{what}");
}

pub struct Key {
    pub kid: String,
    kp: EcdsaKeyPair,
}

impl Key {
    pub fn new(kid: &str) -> Arc<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        Arc::new(Key {
            kid: kid.into(),
            kp: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap(),
        })
    }

    pub fn jwk(&self) -> Value {
        let p = self.kp.public_key().as_ref();
        json!({"kty": "EC", "crv": "P-256", "kid": self.kid, "use": "sig", "alg": "ES256",
            "x": URL_SAFE_NO_PAD.encode(&p[1..33]), "y": URL_SAFE_NO_PAD.encode(&p[33..65])})
    }

    pub fn sign(&self, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            b64(&json!({"alg": "ES256", "typ": "JWT", "kid": self.kid})),
            b64(claims)
        );
        let sig = self
            .kp
            .sign(&SystemRandom::new(), input.as_bytes())
            .unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
    }
}

pub fn b64(v: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
}

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[derive(Clone)]
pub struct User {
    pub sub: String,
    pub name: String,
    pub groups: Option<Vec<String>>,
    pub userinfo_groups: Vec<String>,
}

pub fn user(name: &str, groups: &[&str]) -> User {
    User {
        sub: format!("sub-{name}"),
        name: name.into(),
        groups: Some(groups.iter().map(|g| g.to_string()).collect()),
        userinfo_groups: vec![],
    }
}

struct Code {
    challenge: String,
    nonce: String,
    redirect_uri: String,
    user: User,
}

#[derive(Default)]
pub struct IdpState {
    pub next_user: Option<User>,
    codes: HashMap<String, Code>,
    pub authorize_params: Vec<HashMap<String, String>>,
    pub jwks_fetches: u32,
    pub published: Vec<Arc<Key>>,
    pub signing: Option<Arc<Key>>,
    pub wrong_nonce: bool,
    pub redirect_token: bool,
    pub moved_token_requests: u32,
    pub issued_id_tokens: Vec<String>,
}

#[derive(Clone)]
pub struct Idp {
    pub url: String,
    pub st: Arc<Mutex<IdpState>>,
}

impl Idp {
    pub async fn start() -> Idp {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let key = Key::new("k1");
        let st = Arc::new(Mutex::new(IdpState {
            published: vec![key.clone()],
            signing: Some(key),
            ..Default::default()
        }));
        let idp = Idp { url, st };
        let app = Router::new()
            .route(
                "/realms/test/.well-known/openid-configuration",
                get(discovery),
            )
            .route("/realms/test/authorize", get(authorize))
            .route("/realms/test/token", post(token))
            .route("/realms/test/token-moved", post(token_moved))
            .route("/realms/test/userinfo", get(userinfo))
            .route("/realms/test/jwks", get(jwks))
            .with_state(idp.clone());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        idp
    }

    pub fn issuer(&self) -> String {
        format!("{}/realms/test", self.url)
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut IdpState) -> R) -> R {
        f(&mut self.st.lock().unwrap())
    }

    pub fn jwt(&self, claims: &Value) -> String {
        self.with(|s| s.signing.clone().unwrap()).sign(claims)
    }

    pub fn api_token(&self, name: &str, groups: &[&str], aud: &str, exp_in: i64) -> String {
        self.jwt(&json!({
            "iss": self.issuer(), "aud": aud, "azp": "some-cli", "sub": format!("sub-{name}"),
            "preferred_username": name, "groups": groups, "iat": now(), "exp": now() + exp_in,
        }))
    }

    /// OIDC settings of the app: redirect URL on a loopback address (never contacted: tests call
    /// the app directly).
    pub fn config(&self) -> OidcConfig {
        OidcConfig {
            issuer: self.issuer(),
            client_id: CLIENT_ID.into(),
            client_secret: Some(CLIENT_SECRET.into()),
            redirect_url: "http://localhost:9/auth/callback".into(),
            api_audience: Some(API_AUDIENCE.into()),
            ..Default::default()
        }
    }

    pub async fn runtime(&self, cfg: OidcConfig, stores: &Stores) -> Arc<OidcRuntime> {
        let oidc = Oidc::new(OidcSettings::new(cfg).unwrap()).unwrap();
        let rt = Arc::new(
            OidcRuntime::new(oidc, stores.sessions.clone(), policy())
                .with_audit(stores.audit.clone())
                .with_allowed_origins(vec!["https://ui.example.com".into()]),
        );
        rt.start().await.unwrap();
        rt
    }
}

async fn discovery(State(idp): State<Idp>) -> axum::Json<Value> {
    let base = idp.issuer();
    axum::Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "userinfo_endpoint": format!("{base}/userinfo"),
        "jwks_uri": format!("{base}/jwks"),
        "end_session_endpoint": format!("{base}/logout"),
        "code_challenge_methods_supported": ["plain", "S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    }))
}

async fn authorize(State(idp): State<Idp>, Query(q): Query<HashMap<String, String>>) -> Response {
    let mut s = idp.st.lock().unwrap();
    s.authorize_params.push(q.clone());
    let ok = q.get("response_type").map(String::as_str) == Some("code")
        && q.get("client_id").map(String::as_str) == Some(CLIENT_ID)
        && q.get("code_challenge_method").map(String::as_str) == Some("S256")
        && q.get("code_challenge").is_some_and(|c| c.len() == 43)
        && q.contains_key("state")
        && q.contains_key("nonce");
    let redirect = q.get("redirect_uri").cloned().unwrap_or_default();
    let state = q.get("state").cloned().unwrap_or_default();
    if !ok {
        return (StatusCode::BAD_REQUEST, "bad authorization request").into_response();
    }
    let Some(user) = s.next_user.clone() else {
        let loc = format!("{redirect}?error=access_denied&state={state}");
        return (StatusCode::FOUND, [(header::LOCATION, loc)]).into_response();
    };
    let code = format!("code-{}", uuid::Uuid::new_v4().simple());
    s.codes.insert(
        code.clone(),
        Code {
            challenge: q["code_challenge"].clone(),
            nonce: q["nonce"].clone(),
            redirect_uri: redirect.clone(),
            user,
        },
    );
    let loc = format!("{redirect}?code={code}&state={state}&session_state=x");
    (StatusCode::FOUND, [(header::LOCATION, loc)]).into_response()
}

async fn token(
    State(idp): State<Idp>,
    headers: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let bad = |e: &str| (StatusCode::BAD_REQUEST, axum::Json(json!({"error": e}))).into_response();
    if idp.with(|s| s.redirect_token) {
        let to = format!("{}/token-moved", idp.issuer());
        return (StatusCode::TEMPORARY_REDIRECT, [(header::LOCATION, to)]).into_response();
    }
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
    );
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        != Some(basic.as_str())
    {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "invalid_client"})),
        )
            .into_response();
    }
    let (code, wrong_nonce) = {
        let mut s = idp.st.lock().unwrap();
        let Some(code) = f.get("code").and_then(|c| s.codes.remove(c)) else {
            return bad("invalid_grant");
        };
        (code, s.wrong_nonce)
    };
    if f.get("grant_type").map(String::as_str) != Some("authorization_code")
        || f.get("redirect_uri") != Some(&code.redirect_uri)
    {
        return bad("invalid_grant");
    }
    let verifier = f.get("code_verifier").cloned().unwrap_or_default();
    if URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) != code.challenge {
        return bad("invalid_grant");
    }
    let mut claims = json!({
        "iss": idp.issuer(), "aud": CLIENT_ID, "azp": CLIENT_ID, "sub": code.user.sub,
        "preferred_username": code.user.name, "iat": now(), "exp": now() + 300,
        "nonce": if wrong_nonce { "not-the-nonce".to_string() } else { code.nonce.clone() },
    });
    if let Some(g) = &code.user.groups {
        claims["groups"] = json!(g);
    }
    let id_token = idp.jwt(&claims);
    idp.with(|s| s.issued_id_tokens.push(id_token.clone()));
    let access = format!(
        "at.{}.{}",
        URL_SAFE_NO_PAD.encode(code.user.sub.as_bytes()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&code.user.userinfo_groups).unwrap())
    );
    axum::Json(json!({"access_token": access, "token_type": "Bearer", "expires_in": 300, "id_token": id_token}))
        .into_response()
}

async fn token_moved(State(idp): State<Idp>) -> Response {
    idp.with(|s| s.moved_token_requests += 1);
    (
        StatusCode::BAD_REQUEST,
        axum::Json(json!({"error": "invalid_grant"})),
    )
        .into_response()
}

async fn userinfo(headers: HeaderMap) -> Response {
    let Some(at) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer at."))
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let (sub, groups) = at.split_once('.').unwrap();
    let sub = String::from_utf8(URL_SAFE_NO_PAD.decode(sub).unwrap()).unwrap();
    let groups: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(groups).unwrap()).unwrap();
    axum::Json(json!({"sub": sub, "groups": groups})).into_response()
}

async fn jwks(State(idp): State<Idp>) -> axum::Json<Value> {
    let mut s = idp.st.lock().unwrap();
    s.jwks_fetches += 1;
    axum::Json(json!({"keys": s.published.iter().map(|k| k.jwk()).collect::<Vec<_>>()}))
}

pub fn set_cookies(h: &HeaderMap) -> Vec<String> {
    h.get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

pub fn cookie_named<'a>(cookies: &'a [String], name: &str) -> Option<&'a String> {
    cookies.iter().find(|c| c.starts_with(&format!("{name}=")))
}

pub fn cookie_val(c: &str) -> String {
    c.split(';')
        .next()
        .unwrap()
        .split_once('=')
        .unwrap()
        .1
        .to_string()
}

pub struct LoginResult {
    pub status: u16,
    pub location: String,
    pub cookies: Vec<String>,
    pub session: Option<String>,
    pub callback_query: String,
    pub login_cookie: String,
}

pub fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

impl App {
    pub fn session_cookie_name(&self) -> String {
        self.platform.oidc().unwrap().oidc.session_cookie_name()
    }

    pub fn login_cookie_name(&self) -> String {
        self.platform.oidc().unwrap().oidc.login_cookie_name()
    }

    pub fn session_cookie(&self, value: &str) -> String {
        format!("{}={value}", self.session_cookie_name())
    }

    pub async fn begin(&self, ret: &str) -> Resp {
        let path = format!(
            "/auth/login?return={}",
            url::form_urlencoded::byte_serialize(ret.as_bytes()).collect::<String>()
        );
        self.send(Call::new(Method::GET, &path)).await
    }

    pub async fn callback(&self, query: &str, login_cookie: Option<&str>) -> Resp {
        let path = format!("/auth/callback?{query}");
        let mut c = Call::new(Method::GET, &path);
        if let Some(lc) = login_cookie {
            c = c.cookie(lc.to_string());
        }
        self.send(c).await
    }

    /// The whole code flow for `u`; the callback may run on another app (replica).
    pub async fn login_via(
        &self,
        other: &App,
        idp: &Idp,
        u: Option<User>,
        ret: &str,
    ) -> LoginResult {
        idp.with(|s| s.next_user = u);
        let r = self.begin(ret).await;
        assert_eq!(r.status, 302, "{}", r.text);
        let idp_url = r.headers[header::LOCATION].to_str().unwrap().to_string();
        let cookies = set_cookies(&r.headers);
        let login_cookie = cookie_named(&cookies, &self.login_cookie_name())
            .unwrap()
            .clone();
        let back = http().get(&idp_url).send().await.unwrap();
        assert_eq!(back.status(), 302);
        let loc = back.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_string();
        let query = loc.split_once('?').unwrap().1.to_string();
        let cookie = format!("{}={}", self.login_cookie_name(), cookie_val(&login_cookie));
        let cb = other.callback(&query, Some(&cookie)).await;
        let cookies = set_cookies(&cb.headers);
        let session = cookie_named(&cookies, &self.session_cookie_name())
            .map(|c| cookie_val(c))
            .filter(|v| !v.is_empty());
        LoginResult {
            status: cb.status,
            location: cb
                .headers
                .get(header::LOCATION)
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default(),
            cookies,
            session,
            callback_query: query,
            login_cookie: cookie,
        }
    }

    pub async fn login(&self, idp: &Idp, u: Option<User>, ret: &str) -> LoginResult {
        self.login_via(self, idp, u, ret).await
    }
}

pub async fn token_lifecycle(stores: Stores) {
    let a = app(&stores).await;
    let r = a.get("/api/v1/me", ADMIN).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["kind"], "token");
    assert_eq!(r.body["authMethod"], "staticToken");
    assert_eq!(r.body["name"], "ops");
    let created = a
        .create_token(
            ADMIN,
            json!({"name": "ci-team-a", "role": "editor", "scopes": ["team-a"], "expiresInDays": 30, "description": "CI of team A"}),
        )
        .await;
    assert_eq!(created.status, 201, "{}", created.text);
    let value = created.body["token"].as_str().unwrap().to_string();
    assert!(value.starts_with("fp_") && value.len() == 67);
    let id = created.body["id"].as_str().unwrap().to_string();
    assert_eq!(created.body["status"], "active");
    assert_eq!(created.body["scopes"], json!(["team-a"]));
    assert_eq!(created.body["createdBy"], "ops");

    let me = a.get("/api/v1/me", &value).await;
    assert_eq!(me.status, 200, "{}", me.text);
    assert_eq!(me.body["kind"], "apiToken");
    assert_eq!(me.body["authMethod"], "managedToken");
    assert_eq!(me.body["tokenId"], json!(id));
    assert_eq!(
        me.body["permissions"]["scopes"]["team-a"],
        json!([
            "launches:read",
            "launches:write",
            "tokens:read",
            "tokens:write"
        ])
    );
    assert_eq!(me.body["permissions"]["global"], json!([]));
    assert_eq!(
        a.get("/api/v1/launches?scope=team-a", &value).await.status,
        200
    );
    let denied = a.get("/api/v1/launches?scope=team-b", &value).await;
    assert_eq!(denied.status, 403);
    assert_eq!(denied.body["code"], "forbidden");
    assert_eq!(
        denied.body["message"],
        "requires permission launches:read in scope team-b"
    );
    assert_eq!(denied.body["details"]["required"], "launches:read");
    assert_eq!(a.get("/api/v1/launches", &value).await.status, 403);

    let list = a.get("/api/v1/tokens", ADMIN).await;
    assert_eq!(list.status, 200);
    assert_eq!(list.body["tokens"].as_array().unwrap().len(), 1);
    assert!(!list.text.contains(&value));
    let filtered = a.get("/api/v1/tokens?scope=team-b", ADMIN).await;
    assert!(filtered.body["tokens"].as_array().unwrap().is_empty());
    assert_eq!(
        a.get("/api/v1/tokens?status=bogus", ADMIN).await.status,
        400
    );
    let own = a.get("/api/v1/tokens/self", &value).await;
    assert_eq!(own.body["id"], json!(id));
    assert_eq!(a.get("/api/v1/tokens/self", ADMIN).await.status, 404);
    let one = a.get(&format!("/api/v1/tokens/{id}"), &value).await;
    assert_eq!(one.status, 200);
    assert!(!one.text.contains(&value));
    assert_eq!(
        a.get(&format!("/api/v1/tokens/{id}"), VIEWER).await.status,
        200,
        "a global tokens:read sees it"
    );

    let dup = a
        .create_token(
            ADMIN,
            json!({"name": "ci-team-a", "role": "viewer", "global": true}),
        )
        .await;
    assert_eq!(dup.status, 409);
    let static_name = a
        .create_token(
            ADMIN,
            json!({"name": "ci", "role": "viewer", "global": true}),
        )
        .await;
    assert_eq!(static_name.status, 409);
    for (body, want) in [
        (
            json!({"name": "bad name", "role": "viewer", "global": true}),
            400,
        ),
        (json!({"name": "x", "role": "nobody", "global": true}), 400),
        (json!({"name": "x", "role": "viewer"}), 400),
        (
            json!({"name": "x", "role": "viewer", "global": true, "scopes": ["team-a"]}),
            400,
        ),
        (
            json!({"name": "x", "role": "viewer", "global": true, "expiresInDays": 0}),
            400,
        ),
        (
            json!({"name": "x", "role": "viewer", "global": true, "expiresInDays": 366}),
            400,
        ),
        (
            json!({"name": "x", "role": "viewer", "scopes": ["team-z"]}),
            404,
        ),
        (
            json!({"name": "x", "role": "viewer", "global": true, "extra": 1}),
            422,
        ),
    ] {
        let r = a.create_token(ADMIN, body.clone()).await;
        assert_eq!(r.status, want, "{body}: {}", r.text);
        assert!(r.body["code"].is_string(), "{}", r.text);
    }

    let revoke = a
        .send(Call::new(Method::DELETE, &format!("/api/v1/tokens/{id}")).bearer(&value))
        .await;
    assert_eq!(revoke.status, 200, "{}", revoke.text);
    assert_eq!(revoke.body["status"], "revoked");
    assert_uniform_401(&a.get("/api/v1/me", &value).await, "revoked token");
    let again = a
        .send(Call::new(Method::DELETE, &format!("/api/v1/tokens/{id}")).bearer(ADMIN))
        .await;
    assert_eq!(again.status, 200);
    let audit = a.audit_text().await;
    assert_eq!(audit.matches("token.revoke").count(), 1, "{audit}");
    assert_eq!(audit.matches("token.create").count(), 1, "{audit}");
    assert!(!audit.contains(&value));
    let reuse = a
        .create_token(
            ADMIN,
            json!({"name": "ci-team-a", "role": "viewer", "global": true}),
        )
        .await;
    assert_eq!(reuse.status, 201, "a revoked token frees its name");

    let expired = franshub_auth::ApiToken {
        id: uuid::Uuid::now_v7(),
        name: "old".into(),
        sha256: hash_token(&format!("fp_{}", "ab".repeat(32))),
        role: "viewer".into(),
        scopes: vec![],
        global: true,
        description: None,
        created_by: "ops".into(),
        created_at: chrono::Utc::now() - chrono::Duration::days(2),
        expires_at: chrono::Utc::now() - chrono::Duration::days(1),
        last_used_at: None,
        revoked_at: None,
        revoked: false,
        parent_id: None,
    };
    stores
        .tokens
        .create(&expired, chrono::Utc::now())
        .await
        .unwrap();
    assert_uniform_401(
        &a.get("/api/v1/me", &format!("fp_{}", "ab".repeat(32)))
            .await,
        "expired token",
    );
    let list = a.get("/api/v1/tokens?status=expired", ADMIN).await;
    assert_eq!(list.body["tokens"][0]["name"], "old");
}

pub async fn no_escalation(stores: Stores) {
    let a = app(&stores).await;
    let editor_a = a
        .create_token(
            ADMIN,
            json!({"name": "editor-a", "role": "editor", "scopes": ["team-a"]}),
        )
        .await
        .body["token"]
        .as_str()
        .unwrap()
        .to_string();
    let cases = [
        (
            json!({"name": "g", "role": "viewer", "global": true}),
            403,
            "requires permission tokens:write globally",
        ),
        (
            json!({"name": "b", "role": "viewer", "scopes": ["team-b"]}),
            404,
            "scope not found",
        ),
        (
            json!({"name": "adm", "role": "admin", "scopes": ["team-a"]}),
            403,
            "requires permission launches:delete in scope team-a to grant role admin there",
        ),
        (
            json!({"name": "all", "role": "viewer", "scopes": ["*"]}),
            403,
            "requires permission tokens:write in all scopes (globally or through scopes: [\"*\"])",
        ),
    ];
    for (body, status, msg) in cases {
        let r = a.create_token(&editor_a, body.clone()).await;
        assert_eq!(r.status, status, "{body}: {}", r.text);
        assert_eq!(r.body["message"], msg, "{body}");
    }
    let ok = a
        .create_token(
            &editor_a,
            json!({"name": "child", "role": "launch-author", "scopes": ["team-a"]}),
        )
        .await;
    assert_eq!(ok.status, 201, "{}", ok.text);
    let viewer = a
        .create_token(
            VIEWER,
            json!({"name": "v", "role": "viewer", "global": true}),
        )
        .await;
    assert_eq!(viewer.status, 403);
    assert_eq!(viewer.body["details"]["required"], "tokens:write");
    let admin_scoped = a
        .create_token(
            ADMIN,
            json!({"name": "admin-a", "role": "admin", "scopes": ["team-a"]}),
        )
        .await;
    let admin_a = admin_scoped.body["token"].as_str().unwrap();
    let me = a.get("/api/v1/me", admin_a).await;
    assert!(
        !me.text.contains("settings:write"),
        "a scoped admin never holds global-only permissions: {}",
        me.text
    );
    let put = a
        .send(Call::new(Method::PUT, "/api/v1/settings").bearer(admin_a))
        .await;
    assert_eq!(put.status, 403);
    let ops_settings = a
        .send(Call::new(Method::PUT, "/api/v1/settings").bearer(ADMIN))
        .await;
    assert_eq!(ops_settings.status, 204);
    let list = a.get("/api/v1/tokens", &editor_a).await;
    let names: Vec<&str> = list.body["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(!names.contains(&"v"));
    assert!(
        names.contains(&"child") && names.contains(&"editor-a"),
        "{names:?}"
    );
    let global_id = a
        .create_token(
            ADMIN,
            json!({"name": "glob", "role": "viewer", "global": true}),
        )
        .await
        .body["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        a.get(&format!("/api/v1/tokens/{global_id}"), &editor_a)
            .await
            .status,
        404,
        "tokens outside the caller's scopes look unknown"
    );
    let del = a
        .send(Call::new(Method::DELETE, &format!("/api/v1/tokens/{global_id}")).bearer(&editor_a))
        .await;
    assert_eq!(del.status, 404);
}

pub async fn token_options(stores: Stores) {
    let a = app(&stores).await;
    let editor_a = a
        .create_token(
            ADMIN,
            json!({"name": "e", "role": "editor", "scopes": ["team-a"]}),
        )
        .await
        .body["token"]
        .as_str()
        .unwrap()
        .to_string();
    let o = a.get("/api/v1/tokens/options", &editor_a).await;
    assert_eq!(o.status, 200, "{}", o.text);
    assert_eq!(o.body["maxDays"], 365);
    assert_eq!(o.body["defaultDays"], 90);
    assert_eq!(o.body["scopes"], json!(["team-a"]));
    let role = |name: &str| {
        o.body["roles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .cloned()
            .unwrap()
    };
    assert_eq!(role("viewer")["scopes"], json!(["team-a"]));
    assert_eq!(role("viewer")["global"], false);
    assert_eq!(role("viewer")["allScopes"], false);
    assert_eq!(role("admin")["scopes"], json!([]));
    assert_eq!(role("launch-author")["builtin"], false);
    let admin = a.get("/api/v1/tokens/options", ADMIN).await;
    let all: Vec<&Value> = admin.body["roles"].as_array().unwrap().iter().collect();
    assert!(
        all.iter()
            .all(|r| r["global"] == true && r["allScopes"] == true)
    );
    assert_eq!(admin.body["scopes"], json!(["team-a", "team-b"]));
    let viewer = a.get("/api/v1/tokens/options", VIEWER).await;
    assert_eq!(viewer.status, 403);
}

pub async fn children_never_outlive_their_parent(stores: Stores) {
    let a = app(&stores).await;
    let parent = a
        .create_token(
            ADMIN,
            json!({"name": "parent", "role": "editor", "global": true, "expiresInDays": 2}),
        )
        .await;
    let pv = parent.body["token"].as_str().unwrap().to_string();
    let pid = parent.body["id"].as_str().unwrap().to_string();
    let child = a
        .create_token(
            &pv,
            json!({"name": "child", "role": "viewer", "global": true, "expiresInDays": 300}),
        )
        .await;
    assert_eq!(child.status, 201, "{}", child.text);
    assert_eq!(child.body["parentId"], json!(pid));
    assert_eq!(child.body["expiresAt"], parent.body["expiresAt"]);
    let cv = child.body["token"].as_str().unwrap().to_string();
    let grandchild = a
        .create_token(
            &cv,
            json!({"name": "grandchild", "role": "viewer", "global": true}),
        )
        .await;
    assert_eq!(grandchild.status, 403, "a viewer cannot create tokens");
    let sibling = a
        .create_token(
            &pv,
            json!({"name": "sibling", "role": "editor", "global": true}),
        )
        .await;
    let sv = sibling.body["token"].as_str().unwrap().to_string();
    let nephew = a
        .create_token(
            &sv,
            json!({"name": "nephew", "role": "viewer", "global": true}),
        )
        .await;
    let nv = nephew.body["token"].as_str().unwrap().to_string();
    let r = a
        .send(Call::new(Method::DELETE, &format!("/api/v1/tokens/{pid}")).bearer(ADMIN))
        .await;
    assert_eq!(r.status, 200);
    for v in [&pv, &cv, &sv, &nv] {
        assert_uniform_401(
            &a.get("/api/v1/me", v).await,
            "descendant revoked with its parent",
        );
    }
    let audit = a.audit_text().await;
    assert!(audit.contains("revokedChildren"), "{audit}");
}

pub async fn uniform_401s(stores: Stores) {
    let a = app(&stores).await;
    let missing = a.send(Call::new(Method::GET, "/api/v1/me")).await;
    assert_uniform_401(&missing, "no credentials");
    for bad in [
        "garbage",
        "fp_0000000000000000000000000000000000000000000000000000000000000000",
        &format!("fp_{}", "z".repeat(64)),
        "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.",
        &"x".repeat(5000),
    ] {
        assert_uniform_401(&a.get("/api/v1/me", bad).await, bad);
    }
    let basic = a
        .send(Call::new(Method::GET, "/api/v1/me").cookie("x=1".into()))
        .await;
    assert_uniform_401(&basic, "cookie without OIDC");
    let origin = a
        .send(Call {
            origin: Some("https://evil.example.com"),
            ..Call::new(Method::GET, "/api/v1/me").bearer(ADMIN)
        })
        .await;
    assert_eq!(origin.status, 403);
    let allowed = a
        .send(Call {
            origin: Some("https://ui.example.com"),
            ..Call::new(Method::GET, "/api/v1/me").bearer(ADMIN)
        })
        .await;
    assert_eq!(allowed.status, 200);
}

pub async fn secrets_stay_out_of_logs_audit_and_responses(stores: Stores) {
    let _ = logs();
    let a = app(&stores).await;
    let created = a
        .create_token(
            ADMIN,
            json!({"name": "secret-check", "role": "viewer", "global": true}),
        )
        .await;
    let value = created.body["token"].as_str().unwrap().to_string();
    let id = created.body["id"].as_str().unwrap().to_string();
    assert_eq!(a.get("/api/v1/me", &value).await.status, 200);
    let _ = a.get("/api/v1/me", "fp_wrong-guess-value").await;
    a.send(Call::new(Method::DELETE, &format!("/api/v1/tokens/{id}")).bearer(ADMIN))
        .await;
    let _ = a.get("/api/v1/me", &value).await;
    for later in [
        a.get("/api/v1/tokens", ADMIN).await.text,
        a.get(&format!("/api/v1/tokens/{id}"), ADMIN).await.text,
        a.audit_text().await,
        format!("{:?}", a.platform),
    ] {
        assert!(!later.contains(&value));
        assert!(!later.contains(&value[3..20]));
        assert!(!later.contains(ADMIN));
    }
    let logged = logs();
    for secret in [value.as_str(), &value[3..], ADMIN, VIEWER] {
        assert!(!logged.contains(secret), "a secret reached the logs");
    }
}

pub async fn all_scopes_rules(stores: Stores, idp: &Idp) {
    let rt = idp.runtime(idp.config(), &stores).await;
    let a = app_with(&stores, Some(rt), Duration::from_secs(10)).await;
    let qa = idp.api_token("quinn", &["qa"], API_AUDIENCE, 300);
    let r = a.get("/api/v1/launches?scope=team-b", &qa).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = a.get("/api/v1/launches?scope=created-later", &qa).await;
    assert_eq!(r.status, 200, "* covers scopes added later");
    assert_eq!(
        a.get("/api/v1/launches", &qa).await.status,
        403,
        "* is not global"
    );
    let me = a.get("/api/v1/me", &qa).await;
    assert_eq!(
        me.body["permissions"]["allScopes"],
        json!(["launches:read", "tokens:read"])
    );
    assert_eq!(me.body["authMethod"], "bearer");
    assert_eq!(me.body["groups"], json!(["qa"]));

    let release = idp.api_token("rita", &["release"], API_AUDIENCE, 300);
    let star = a
        .create_token(
            &release,
            json!({"name": "star", "role": "launch-author", "scopes": ["*"]}),
        )
        .await;
    assert_eq!(star.status, 201, "{}", star.text);
    let sv = star.body["token"].as_str().unwrap().to_string();
    a.scopes.0.write().unwrap().push("team-c".into());
    assert_eq!(
        a.get("/api/v1/launches?scope=team-c", &sv).await.status,
        200
    );
    let star_admin = a
        .create_token(
            &release,
            json!({"name": "star-admin", "role": "admin", "scopes": ["*"]}),
        )
        .await;
    assert_eq!(star_admin.status, 403);
    assert!(
        star_admin.body["message"]
            .as_str()
            .unwrap()
            .contains("launches:delete in all scopes")
    );

    let team_a = idp.api_token("alice", &["team-a-dev"], API_AUDIENCE, 300);
    let not_star = a
        .create_token(
            &team_a,
            json!({"name": "a-star", "role": "viewer", "scopes": ["*"]}),
        )
        .await;
    assert_eq!(
        not_star.status, 403,
        "being bound to some scopes is not enough for *"
    );
    let sid = star.body["id"].as_str().unwrap();
    assert_eq!(
        a.get(&format!("/api/v1/tokens/{sid}"), &team_a)
            .await
            .status,
        404,
        "a * token needs tokens:read in all scopes"
    );
    let ops_star = a
        .create_token(
            ADMIN,
            json!({"name": "ops-star", "role": "admin", "scopes": ["*"]}),
        )
        .await;
    assert_eq!(ops_star.status, 201);
    let osv = ops_star.body["token"].as_str().unwrap();
    assert_eq!(
        a.send(Call::new(Method::PUT, "/api/v1/settings").bearer(osv))
            .await
            .status,
        403,
        "* never grants global-only permissions"
    );
}

pub async fn revocation_reaches_other_replicas(stores: Stores) {
    let a = app_with(&stores, None, Duration::from_millis(300)).await;
    let b = app_with(&stores, None, Duration::from_millis(300)).await;
    assert_eq!(
        b.get("/api/v1/me", &format!("fp_{}", "cd".repeat(32)))
            .await
            .status,
        401,
        "b caches that the store is empty"
    );
    let created = a
        .create_token(
            ADMIN,
            json!({"name": "shared", "role": "viewer", "global": true}),
        )
        .await;
    let v = created.body["token"].as_str().unwrap().to_string();
    let id = created.body["id"].as_str().unwrap().to_string();
    let mut ok = false;
    for _ in 0..20 {
        if b.get("/api/v1/me", &v).await.status == 200 {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        ok,
        "a first token reaches the other replica within the cache TTL"
    );
    a.send(Call::new(Method::DELETE, &format!("/api/v1/tokens/{id}")).bearer(ADMIN))
        .await;
    assert_uniform_401(&a.get("/api/v1/me", &v).await, "revoked on a");
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_uniform_401(&b.get("/api/v1/me", &v).await, "revoked on b after the TTL");
}

pub async fn code_flow_session_csrf_and_logout(stores: Stores, idp: &Idp) {
    let _ = logs();
    let rt = idp.runtime(idp.config(), &stores).await;
    let a = app_with(&stores, Some(rt), Duration::from_secs(10)).await;
    let ret = "/launches?scope=team-a";
    let res = a
        .login(idp, Some(user("alice", &["team-a-dev", "other"])), ret)
        .await;
    assert_eq!(res.status, 302);
    assert_eq!(res.location, ret);
    let params = idp.with(|s| s.authorize_params.last().cloned().unwrap());
    assert_eq!(params["client_id"], CLIENT_ID);
    assert_eq!(params["scope"], "openid profile email");
    assert_eq!(params["code_challenge_method"], "S256");
    assert_eq!(params["redirect_uri"], "http://localhost:9/auth/callback");
    assert_eq!(params["state"].len(), 43);
    assert_ne!(params["state"], params["nonce"]);
    let sc = cookie_named(&res.cookies, "__Host-franshub_session").unwrap();
    for attr in [
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Secure",
        "Max-Age=28800",
    ] {
        assert!(sc.split("; ").any(|x| x == attr), "{sc} lacks {attr}");
    }
    assert!(!sc.contains("Domain"));
    let lc = cookie_named(&res.cookies, "__Host-franshub_login").unwrap();
    assert!(lc.contains("Max-Age=0"));
    let session = res.session.clone().unwrap();
    let cookie = a.session_cookie(&session);

    let me = a
        .send(Call::new(Method::GET, "/api/v1/me").cookie(cookie.clone()))
        .await;
    assert_eq!(me.status, 200, "{}", me.text);
    assert_eq!(me.body["kind"], "user");
    assert_eq!(me.body["authMethod"], "session");
    assert_eq!(me.body["groups"], json!(["team-a-dev", "other"]));
    assert!(
        me.body["permissions"]["scopes"]["team-a"]
            .as_array()
            .unwrap()
            .contains(&json!("launches:write"))
    );

    let no_csrf = a
        .send(Call::new(Method::POST, "/api/v1/launches?scope=team-a").cookie(cookie.clone()))
        .await;
    assert_eq!(no_csrf.status, 403);
    assert_eq!(
        no_csrf.body["message"],
        "missing X-FransHub-Request: 1 header"
    );
    let with_csrf = a
        .send(
            Call::new(Method::POST, "/api/v1/launches?scope=team-a")
                .cookie(cookie.clone())
                .csrf(),
        )
        .await;
    assert_eq!(with_csrf.status, 201, "{}", with_csrf.text);
    let header_decides = a
        .send(
            Call::new(Method::GET, "/api/v1/me")
                .bearer("not-a-token")
                .cookie(cookie.clone()),
        )
        .await;
    assert_uniform_401(&header_decides, "an Authorization header decides alone");

    let replay = a
        .callback(&res.callback_query, Some(&res.login_cookie))
        .await;
    assert_eq!(
        replay.headers[header::LOCATION],
        "/?loginError=invalid_state"
    );

    let logout = |csrf: bool, origin: Option<&'static str>| {
        let c = Call {
            origin,
            csrf,
            ..Call::new(Method::POST, "/auth/logout").cookie(cookie.clone())
        };
        a.send(c)
    };
    let r = logout(false, None).await;
    assert_eq!(r.status, 403);
    assert_eq!(
        r.body,
        json!({"code": "forbidden", "message": "missing X-FransHub-Request: 1 header"})
    );
    assert_eq!(
        logout(true, Some("https://evil.example.com")).await.status,
        403
    );
    let r = logout(true, None).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let cleared = set_cookies(&r.headers);
    assert!(
        cleared[0].starts_with("__Host-franshub_session=;"),
        "{cleared:?}"
    );
    assert_eq!(r.body["loggedOut"], true);
    let lu = reqwest::Url::parse(r.body["logoutUrl"].as_str().unwrap()).unwrap();
    assert!(
        lu.as_str()
            .starts_with(&format!("{}/logout?client_id=reports", idp.issuer()))
    );
    let q: HashMap<String, String> = lu.query_pairs().into_owned().collect();
    assert_eq!(q["post_logout_redirect_uri"], "http://localhost:9/");
    let id_token = idp.with(|s| s.issued_id_tokens.last().cloned().unwrap());
    assert_eq!(q.get("id_token_hint"), Some(&id_token));
    assert!(!cleared.iter().any(|c| c.contains(&id_token)));
    let after = a
        .send(Call::new(Method::GET, "/api/v1/me").cookie(cookie.clone()))
        .await;
    assert_uniform_401(&after, "session gone after logout");
    assert!(set_cookies(&after.headers)[0].contains("Max-Age=0"));
    assert_eq!(logout(true, None).await.body["loggedOut"], false);

    let audit = a.audit_text().await;
    for want in ["auth.login", "auth.logout"] {
        assert!(audit.contains(want), "{want}: {audit}");
    }
    let logged = logs();
    let code = res
        .callback_query
        .split('&')
        .next()
        .unwrap()
        .trim_start_matches("code=");
    for secret in [
        session.as_str(),
        CLIENT_SECRET,
        code,
        params["state"].as_str(),
        params["nonce"].as_str(),
        id_token.as_str(),
    ] {
        assert!(!logged.contains(secret), "a secret leaked into the logs");
        assert!(
            !audit.contains(secret),
            "a secret leaked into the audit log"
        );
    }
}

pub async fn login_rejections(stores: Stores, idp: &Idp) {
    let rt = idp.runtime(idp.config(), &stores).await;
    let a = app_with(&stores, Some(rt), Duration::from_secs(10)).await;
    for bad in [
        "//evil.example.com",
        "https://evil.example.com/",
        "/a//evil.example.com",
        "/\\evil.example.com",
        "/%2F%2Fevil.example.com",
        "/../api/v1/tokens",
        "javascript:alert(1)",
    ] {
        let r = a.begin(bad).await;
        assert_eq!(r.status, 400, "{bad}");
        assert!(set_cookies(&r.headers).is_empty());
        assert_eq!(r.body["code"], "bad_request");
    }
    idp.with(|s| s.wrong_nonce = true);
    let res = a
        .login(idp, Some(user("alice", &["team-a-dev"])), "/")
        .await;
    idp.with(|s| s.wrong_nonce = false);
    assert_eq!(res.location, "/?loginError=failed");
    assert!(res.session.is_none());
    let res = a.login(idp, None, "/").await;
    assert_eq!(res.location, "/?loginError=idp_error");
    let res = a.login(idp, Some(user("bob", &["nobody"])), "/").await;
    assert_eq!(res.location, "/?loginError=no_access");
    assert!(res.session.is_none());

    let mut dave = user("dave", &[]);
    dave.groups = None;
    dave.userinfo_groups = vec!["team-a-dev".into()];
    let res = a.login(idp, Some(dave), "/").await;
    let s = res.session.expect("groups from userinfo");
    let me = a
        .send(Call::new(Method::GET, "/api/v1/me").cookie(a.session_cookie(&s)))
        .await;
    assert_eq!(me.body["groups"], json!(["team-a-dev"]));

    idp.with(|s| s.next_user = Some(user("alice", &["team-a-dev"])));
    let r = a.begin("/").await;
    let idp_url = r.headers[header::LOCATION].to_str().unwrap().to_string();
    let back = http().get(&idp_url).send().await.unwrap();
    let loc = back.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let query = loc.split_once('?').unwrap().1;
    let cb = a.callback(query, None).await;
    assert_eq!(
        cb.headers[header::LOCATION],
        "/?loginError=invalid_state",
        "no login cookie"
    );
    assert!(cookie_named(&set_cookies(&cb.headers), "__Host-franshub_session").is_none());
    let forged = format!("{}={}", a.login_cookie_name(), "A".repeat(43));
    let cb = a.callback(query, Some(&forged)).await;
    assert_eq!(
        cb.headers[header::LOCATION],
        "/?loginError=invalid_state",
        "state consumed"
    );
    let cb = a.callback("code=x&state=unknown", None).await;
    assert_eq!(cb.headers[header::LOCATION], "/?loginError=invalid_state");

    let audit = a.audit_text().await;
    assert!(audit.contains("auth.login_failed"));
    assert!(audit.contains("ID token rejected"));
    assert!(!audit.contains("not-the-nonce"));
}

pub async fn bearer_jwts(stores: Stores, idp: &Idp) {
    let _ = logs();
    let rt = idp.runtime(idp.config(), &stores).await;
    let a = app_with(&stores, Some(rt), Duration::from_secs(10)).await;
    let good = idp.api_token("alice", &["team-a-dev"], API_AUDIENCE, 300);
    let r = a.get("/api/v1/launches?scope=team-a", &good).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let nobody = idp.api_token("zed", &["nobody"], API_AUDIENCE, 300);
    let r = a.get("/api/v1/me", &nobody).await;
    assert_eq!(r.status, 403, "authenticated but no binding");
    let iss = idp.issuer();
    let base = |f: &dyn Fn(&mut Value)| {
        let mut c = json!({"iss": iss, "aud": API_AUDIENCE, "sub": "sub-alice",
            "preferred_username": "alice", "groups": ["team-a-dev"], "iat": now(), "exp": now() + 300});
        f(&mut c);
        idp.jwt(&c)
    };
    let hs256 = {
        let input = format!(
            "{}.{}",
            b64(&json!({"alg": "HS256", "kid": "k1"})),
            b64(&json!({"iss": iss, "aud": API_AUDIENCE, "sub": "s", "exp": now() + 300}))
        );
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"guessed-secret");
        let tag = ring::hmac::sign(&key, input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(tag.as_ref()))
    };
    let rogue = Key::new("k1")
        .sign(&json!({"iss": iss, "aud": API_AUDIENCE, "sub": "s", "exp": now() + 300}));
    let unknown_kid = Key::new("k9")
        .sign(&json!({"iss": iss, "aud": API_AUDIENCE, "sub": "s", "exp": now() + 300}));
    let cases = [
        (
            "wrong audience",
            idp.api_token("alice", &["team-a-dev"], "other-api", 300),
        ),
        (
            "ID token audience",
            idp.api_token("alice", &["team-a-dev"], CLIENT_ID, 300),
        ),
        (
            "wrong issuer",
            base(&|c| c["iss"] = json!("https://evil.example.com")),
        ),
        ("expired", base(&|c| c["exp"] = json!(now() - 120))),
        ("not yet valid", base(&|c| c["nbf"] = json!(now() + 600))),
        ("an ID token", base(&|c| c["nonce"] = json!("n"))),
        ("hs256", hs256),
        ("forged signature", rogue),
        ("unknown kid", unknown_kid),
    ];
    for (what, t) in &cases {
        assert_uniform_401(&a.get("/api/v1/me", t).await, what);
    }
    let rs_only = OidcConfig {
        allowed_algs: Some(vec!["RS256".into()]),
        ..idp.config()
    };
    let rt = idp.runtime(rs_only, &stores).await;
    let strict = app_with(&stores, Some(rt), Duration::from_secs(10)).await;
    assert_uniform_401(&strict.get("/api/v1/me", &good).await, "ES256 not allowed");
    let rotated = Key::new("k2");
    idp.with(|s| {
        s.published.push(rotated.clone());
        s.signing = Some(rotated.clone());
    });
    let fetches = idp.with(|s| s.jwks_fetches);
    tokio::time::sleep(franshub_oidc::JWKS_MIN_AGE).await;
    let fresh = idp.api_token("alice", &["team-a-dev"], API_AUDIENCE, 300);
    assert_eq!(
        a.get("/api/v1/me", &fresh).await.status,
        200,
        "key rotation"
    );
    assert_eq!(idp.with(|s| s.jwks_fetches), fetches + 1);
    for _ in 0..5 {
        let _ = a.get("/api/v1/me", &cases[8].1).await;
    }
    assert_eq!(
        idp.with(|s| s.jwks_fetches),
        fetches + 1,
        "unknown kids are rate limited"
    );
    idp.with(|s| {
        let k1 = s.published[0].clone();
        s.signing = Some(k1);
    });
    let logged = logs();
    for (_, t) in &cases {
        assert!(!logged.contains(t.as_str()));
    }
    assert!(!logged.contains(&good));
}

pub async fn sessions_expire(stores: Stores, idp: &Idp) {
    let cfg = OidcConfig {
        session_ttl: Some(Duration::from_millis(2500)),
        session_idle: Some(Duration::from_secs(1)),
        ..idp.config()
    };
    let rt = idp.runtime(cfg, &stores).await;
    let a = app_with(&stores, Some(rt), Duration::from_secs(10)).await;
    let s = a
        .login(idp, Some(user("alice", &["team-a-dev"])), "/")
        .await
        .session
        .unwrap();
    let cookie = a.session_cookie(&s);
    let start = std::time::Instant::now();
    let mut last_ok = Duration::ZERO;
    loop {
        let r = a
            .send(Call::new(Method::GET, "/api/v1/me").cookie(cookie.clone()))
            .await;
        if r.status != 200 {
            assert_uniform_401(&r, "absolute TTL");
            break;
        }
        last_ok = start.elapsed();
        assert!(last_ok < Duration::from_millis(2700), "outlived the TTL");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        last_ok > Duration::from_millis(1900),
        "ended early at {last_ok:?}"
    );
    let s = a
        .login(idp, Some(user("alice", &["team-a-dev"])), "/")
        .await
        .session
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let r = a
        .send(Call::new(Method::GET, "/api/v1/me").cookie(a.session_cookie(&s)))
        .await;
    assert_uniform_401(&r, "idle timeout");
}

pub async fn sessions_shared_by_replicas(stores: Stores, idp: &Idp) {
    let rt_a = idp.runtime(idp.config(), &stores).await;
    let rt_b = idp.runtime(idp.config(), &stores).await;
    let a = app_with(&stores, Some(rt_a), Duration::from_secs(10)).await;
    let b = app_with(&stores, Some(rt_b), Duration::from_secs(10)).await;
    let res = a
        .login_via(&b, idp, Some(user("alice", &["team-a-dev"])), "/")
        .await;
    assert_eq!(res.location, "/", "callback on the other replica");
    let cookie = a.session_cookie(&res.session.unwrap());
    for x in [&a, &b] {
        let r = x
            .send(Call::new(Method::GET, "/api/v1/me").cookie(cookie.clone()))
            .await;
        assert_eq!(r.status, 200);
    }
    let r = b
        .send(
            Call::new(Method::POST, "/auth/logout")
                .cookie(cookie.clone())
                .csrf(),
        )
        .await;
    assert_eq!(r.status, 200);
    let r = a
        .send(Call::new(Method::GET, "/api/v1/me").cookie(cookie.clone()))
        .await;
    assert_uniform_401(&r, "logged out on the other replica");
}

pub fn _assert_send(_: impl IntoResponse) {}
