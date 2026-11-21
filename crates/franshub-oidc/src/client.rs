//! The OIDC client: discovery, signing keys, token validation, code exchange and userinfo.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use axum::http::{HeaderMap, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use url::Url;

use crate::jwt::{self, Expect, JwkSet, JwtError};
use crate::session::{self, Lifetimes, PendingLogin};
use crate::settings::{self, OidcSettings};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const STARTUP_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const JWKS_REFRESH_EVERY: Duration = Duration::from_secs(3600);
/// The same unknown `kid` triggers at most one JWKS refresh per this interval.
pub const JWKS_MIN_REFRESH: Duration = Duration::from_secs(60);
/// Refreshes for unknown keys are at least this far apart, whatever the `kid`.
pub const JWKS_MIN_AGE: Duration = Duration::from_secs(5);
const MAX_UNKNOWN_KIDS: usize = 256;

/// Refreshes triggered by unknown keys: when the last one ran, and the `kid`s it did not find.
#[derive(Default)]
struct Refreshes {
    last: Option<Instant>,
    unknown: HashMap<String, Instant>,
}
const LOGIN_BURST: f64 = 100.0;
const LOGINS_PER_SECOND: f64 = 10.0;

/// The endpoints of the provider, from its discovery document.
#[derive(Debug)]
pub struct Provider {
    pub(crate) authorization: Url,
    pub(crate) token: Url,
    pub(crate) jwks_uri: Url,
    pub(crate) userinfo: Option<Url>,
    pub(crate) end_session: Option<Url>,
    /// `client_secret_basic` (default) or `client_secret_post`.
    pub(crate) basic_auth: bool,
}

#[derive(Debug)]
enum DiscoveryError {
    /// Network trouble or an error status: retried.
    Unreachable(anyhow::Error),
    /// The provider answers with a document that must not be used.
    Invalid(anyhow::Error),
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

/// An OIDC relying party: holds the provider's endpoints and signing keys, refreshed in the
/// background, and validates tokens.
pub struct Oidc {
    /// The checked settings.
    pub settings: OidcSettings,
    http: reqwest::Client,
    /// For the token endpoint: never follows redirects, so the client credentials go only to the
    /// discovered endpoint.
    token_http: reqwest::Client,
    hosts: Arc<Vec<String>>,
    provider: RwLock<Option<Arc<Provider>>>,
    jwks: RwLock<Arc<JwkSet>>,
    refreshed: tokio::sync::Mutex<Refreshes>,
    limiter: Mutex<Bucket>,
}

/// User identity from an ID token, userinfo or an API bearer token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// User name.
    pub name: String,
    /// Group names.
    pub groups: Vec<String>,
}

fn load_ca(path: &std::path::Path) -> anyhow::Result<Vec<reqwest::Certificate>> {
    let pem = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("reading the OIDC CA file {}: {e}", path.display()))?;
    let certs = reqwest::Certificate::from_pem_bundle(&pem)
        .map_err(|e| anyhow::anyhow!("parsing the OIDC CA file {}: {e}", path.display()))?;
    if certs.is_empty() {
        bail!(
            "the OIDC CA file {} contains no PEM certificates",
            path.display()
        );
    }
    Ok(certs)
}

fn host_of(u: &Url) -> Option<String> {
    u.host_str().map(str::to_ascii_lowercase)
}

/// Egress rule of the OIDC client: https to the issuer host or an allowed host; plain http only to
/// loopback addresses.
fn egress_ok(hosts: &[String], u: &Url) -> bool {
    let scheme_ok = match u.scheme() {
        "https" => true,
        "http" => settings::is_loopback(u),
        _ => false,
    };
    scheme_ok
        && u.username().is_empty()
        && u.password().is_none()
        && host_of(u).is_some_and(|h| hosts.contains(&h))
}

async fn read_limited(mut resp: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
    {
        bail!("response larger than {MAX_RESPONSE_BYTES} bytes");
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if out.len() + chunk.len() > MAX_RESPONSE_BYTES {
            bail!("response larger than {MAX_RESPONSE_BYTES} bytes");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// A value of `claims` by name, or by a dotted path into nested objects when no claim has that
/// exact name (so namespaced claims such as `https://example.com/groups` work too).
pub fn claim<'a>(claims: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    if let Some(v) = claims.get(name) {
        return Some(v);
    }
    let mut parts = name.split('.');
    let mut cur = claims.get(parts.next()?)?;
    for p in parts {
        cur = cur.as_object()?.get(p)?;
    }
    Some(cur)
}

fn clean_name(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty() && s.len() <= session::MAX_NAME_BYTES && !s.chars().any(char::is_control))
        .then(|| s.to_string())
}

/// Group names from a claim value: an array of strings or a single string.
pub fn groups_of(v: &Value) -> Vec<String> {
    let raw: Vec<&str> = match v {
        Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
        Value::String(s) => vec![s.as_str()],
        _ => vec![],
    };
    let mut out: Vec<String> = Vec::new();
    for g in raw.into_iter().filter_map(clean_name) {
        if !out.contains(&g) {
            out.push(g);
        }
    }
    if out.len() > session::MAX_GROUPS {
        tracing::warn!(
            groups = out.len(),
            kept = session::MAX_GROUPS,
            "the groups claim has too many entries; the rest are ignored"
        );
        out.truncate(session::MAX_GROUPS);
    }
    out
}

/// The PKCE S256 challenge of a verifier.
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn form_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// An OAuth error code from an IdP response, safe to log.
fn error_code(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(Value::as_str).map(String::from))
        .filter(|e| {
            e.len() <= 64
                && e.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
        .unwrap_or_else(|| "unknown".into())
}

impl Oidc {
    /// A client for checked settings; call [`Oidc::start`] to discover the provider.
    pub fn new(settings: OidcSettings) -> anyhow::Result<Arc<Self>> {
        let mut hosts: Vec<String> =
            vec![host_of(&settings.issuer_url).context("the OIDC issuer has no host")?];
        for h in &settings.allowed_hosts {
            if !hosts.contains(h) {
                hosts.push(h.clone());
            }
        }
        let hosts = Arc::new(hosts);
        let roots = match &settings.ca_file {
            Some(p) => load_ca(p)?,
            None => vec![],
        };
        let client = |policy: reqwest::redirect::Policy| {
            let mut builder = reqwest::Client::builder();
            for c in &roots {
                builder = builder.add_root_certificate(c.clone());
            }
            builder
                .redirect(policy)
                .timeout(HTTP_TIMEOUT)
                .connect_timeout(Duration::from_secs(5))
                .user_agent(concat!("franshub-oidc/", env!("CARGO_PKG_VERSION")))
                .build()
                .context("building the OIDC HTTP client")
        };
        let allowed = hosts.clone();
        let http = client(reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= 3 {
                attempt.error("too many redirects")
            } else if egress_ok(&allowed, attempt.url()) {
                attempt.follow()
            } else {
                attempt.error("redirect to a host outside the issuer and the allowed hosts")
            }
        }))?;
        let token_http = client(reqwest::redirect::Policy::none())?;
        metrics::gauge!("oidc_ready").set(0.0);
        Ok(Arc::new(Self {
            settings,
            http,
            token_http,
            hosts,
            provider: RwLock::new(None),
            jwks: RwLock::new(Arc::new(JwkSet::default())),
            refreshed: tokio::sync::Mutex::new(Refreshes::default()),
            limiter: Mutex::new(Bucket {
                tokens: LOGIN_BURST,
                at: Instant::now(),
            }),
        }))
    }

    /// Session lifetimes from the settings.
    pub fn lifetimes(&self) -> Lifetimes {
        Lifetimes {
            ttl: self.settings.session_ttl,
            idle: self.settings.session_idle,
        }
    }

    /// The discovered provider; `None` until discovery succeeds.
    pub fn provider(&self) -> Option<Arc<Provider>> {
        self.provider
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn keys(&self) -> Arc<JwkSet> {
        self.jwks.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Bearer JWTs are accepted on the API (an API audience is configured).
    pub fn api_enabled(&self) -> bool {
        self.settings.api_audience.is_some()
    }

    fn check_egress(&self, u: &Url) -> anyhow::Result<()> {
        if !egress_ok(&self.hosts, u) {
            bail!(
                "{} is outside the issuer host and the allowed hosts",
                u.host_str().unwrap_or_default()
            );
        }
        Ok(())
    }

    async fn get_json(&self, u: &Url, bearer: Option<&str>) -> anyhow::Result<(u16, Vec<u8>)> {
        self.check_egress(u)?;
        let mut rb = self
            .http
            .get(u.clone())
            .header(header::ACCEPT, "application/json");
        if let Some(t) = bearer {
            rb = rb.bearer_auth(t);
        }
        let resp = rb
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("{}", e.without_url()))?;
        let status = resp.status().as_u16();
        Ok((status, read_limited(resp).await?))
    }

    fn endpoint(
        &self,
        doc: &Value,
        name: &str,
        required: bool,
    ) -> Result<Option<Url>, DiscoveryError> {
        let Some(raw) = doc.get(name).and_then(Value::as_str) else {
            if required {
                return Err(DiscoveryError::Invalid(anyhow::anyhow!(
                    "the discovery document has no {name}"
                )));
            }
            return Ok(None);
        };
        let u = Url::parse(raw)
            .map_err(|e| DiscoveryError::Invalid(anyhow::anyhow!("{name} is not a URL: {e}")))?;
        if !egress_ok(&self.hosts, &u) {
            return Err(DiscoveryError::Invalid(anyhow::anyhow!(
                "{name} points to {}://{}, which is neither the issuer host nor an allowed host (plain http is accepted only on loopback addresses)",
                u.scheme(),
                u.host_str().unwrap_or_default()
            )));
        }
        Ok(Some(u))
    }

    async fn fetch_jwks(&self, uri: &Url) -> anyhow::Result<JwkSet> {
        let (status, body) = self.get_json(uri, None).await?;
        if status != 200 {
            bail!("the JWKS endpoint answered {status}");
        }
        JwkSet::parse(&body)
    }

    async fn discover(&self) -> Result<(), DiscoveryError> {
        let base = self.settings.issuer.trim_end_matches('/');
        let url = Url::parse(&format!("{base}/.well-known/openid-configuration"))
            .map_err(|e| DiscoveryError::Invalid(e.into()))?;
        let (status, body) = self
            .get_json(&url, None)
            .await
            .map_err(DiscoveryError::Unreachable)?;
        if status != 200 {
            return Err(DiscoveryError::Unreachable(anyhow::anyhow!(
                "the discovery endpoint answered {status}"
            )));
        }
        let doc: Value = serde_json::from_slice(&body).map_err(|e| {
            DiscoveryError::Unreachable(anyhow::anyhow!("the discovery document is not JSON: {e}"))
        })?;
        if doc.get("issuer").and_then(Value::as_str) != Some(self.settings.issuer.as_str()) {
            return Err(DiscoveryError::Invalid(anyhow::anyhow!(
                "the discovery document names issuer {:?}, not the configured issuer {:?}",
                doc.get("issuer")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                self.settings.issuer
            )));
        }
        let strings = |name: &str| -> Option<Vec<String>> {
            doc.get(name).and_then(Value::as_array).map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
        };
        if let Some(m) = strings("code_challenge_methods_supported")
            && !m.iter().any(|x| x == "S256")
        {
            return Err(DiscoveryError::Invalid(anyhow::anyhow!(
                "the provider does not support PKCE with S256"
            )));
        }
        let basic_auth = match strings("token_endpoint_auth_methods_supported") {
            None => true,
            Some(m) if m.iter().any(|x| x == "client_secret_basic") => true,
            Some(m) if m.iter().any(|x| x == "client_secret_post") => false,
            Some(_) => {
                return Err(DiscoveryError::Invalid(anyhow::anyhow!(
                    "the token endpoint supports neither client_secret_basic nor client_secret_post"
                )));
            }
        };
        let req = |n| self.endpoint(&doc, n, true).map(Option::unwrap);
        let provider = Provider {
            authorization: req("authorization_endpoint")?,
            token: req("token_endpoint")?,
            jwks_uri: req("jwks_uri")?,
            userinfo: self.endpoint(&doc, "userinfo_endpoint", false)?,
            end_session: self.endpoint(&doc, "end_session_endpoint", false)?,
            basic_auth,
        };
        let keys = self
            .fetch_jwks(&provider.jwks_uri)
            .await
            .map_err(DiscoveryError::Unreachable)?;
        tracing::info!(issuer = %self.settings.issuer, keys = keys.len(), "OIDC provider discovered");
        *self.jwks.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(keys);
        *self.provider.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(provider));
        metrics::gauge!("oidc_ready").set(1.0);
        Ok(())
    }

    /// First discovery at start-up: a provider document that must not be used stops the start; an
    /// unreachable provider is retried in the background while the server runs (SSO answers 503).
    pub async fn start(self: &Arc<Self>) -> anyhow::Result<()> {
        match tokio::time::timeout(STARTUP_DISCOVERY_TIMEOUT, self.discover()).await {
            Ok(Ok(())) => {}
            Ok(Err(DiscoveryError::Invalid(e))) => {
                return Err(e.context(format!(
                    "OIDC discovery for {} failed",
                    self.settings.issuer
                )));
            }
            Ok(Err(DiscoveryError::Unreachable(e))) => {
                tracing::warn!(issuer = %self.settings.issuer, error = %e, "OIDC provider unreachable; retrying in the background, SSO answers 503 until then");
            }
            Err(_) => {
                tracing::warn!(issuer = %self.settings.issuer, "OIDC discovery timed out; retrying in the background, SSO answers 503 until then");
            }
        }
        tokio::spawn(background(Arc::downgrade(self)));
        Ok(())
    }

    /// Refreshes the JWKS when the token's `kid` is unknown: a `kid` that a refresh did not find waits
    /// [`JWKS_MIN_REFRESH`], any other at most [`JWKS_MIN_AGE`], so unknown keys cannot hold back a
    /// real key rotation for long.
    async fn refresh_for(&self, kid: Option<&str>) -> bool {
        let mut st = self.refreshed.lock().await;
        if let Some(k) = kid
            && self.keys().knows(k)
        {
            return true;
        }
        let key = kid.unwrap_or_default().to_string();
        if st
            .unknown
            .get(&key)
            .is_some_and(|t| t.elapsed() < JWKS_MIN_REFRESH)
            || st.last.is_some_and(|t| t.elapsed() < JWKS_MIN_AGE)
        {
            return false;
        }
        let Some(p) = self.provider() else {
            return false;
        };
        st.last = Some(Instant::now());
        match self.fetch_jwks(&p.jwks_uri).await {
            Ok(keys) => {
                tracing::info!(keys = keys.len(), "OIDC signing keys refreshed");
                if kid.is_none_or(|k| !keys.knows(k)) {
                    if st.unknown.len() >= MAX_UNKNOWN_KIDS {
                        st.unknown.retain(|_, t| t.elapsed() < JWKS_MIN_REFRESH);
                        if st.unknown.len() >= MAX_UNKNOWN_KIDS {
                            st.unknown.clear();
                        }
                    }
                    st.unknown.insert(key, Instant::now());
                }
                *self.jwks.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(keys);
                true
            }
            Err(e) => {
                tracing::warn!(error = %e, "refreshing the OIDC signing keys failed");
                false
            }
        }
    }

    /// Validates a JWT; an unknown signing key triggers one rate-limited JWKS refresh.
    pub async fn validate(
        &self,
        token: &str,
        audience: &str,
        nonce: Option<&str>,
        id_token: bool,
    ) -> Result<Map<String, Value>, JwtError> {
        let expect = |now| Expect {
            issuer: &self.settings.issuer,
            audience,
            nonce,
            check_azp: id_token,
            require_iat: id_token,
            now,
            algs: &self.settings.allowed_algs,
        };
        let now = chrono::Utc::now().timestamp();
        match jwt::verify(token, &self.keys(), &expect(now)) {
            Err(JwtError::UnknownKey) => {
                if self.refresh_for(jwt::kid_of(token).as_deref()).await {
                    jwt::verify(token, &self.keys(), &expect(now))
                } else {
                    Err(JwtError::UnknownKey)
                }
            }
            r => r,
        }
    }

    /// The user name and groups of a set of claims. With `email` as the username claim, the address
    /// counts only when `email_verified` is true.
    pub fn identity(&self, claims: &Map<String, Value>) -> (Option<String>, Option<Vec<String>>) {
        let verified = self.settings.username_claim != "email"
            || claims.get("email_verified") == Some(&Value::Bool(true));
        let name = claim(claims, &self.settings.username_claim)
            .filter(|_| verified)
            .and_then(Value::as_str)
            .and_then(clean_name);
        let groups = claim(claims, &self.settings.groups_claim).map(groups_of);
        (name, groups)
    }

    /// The identity of an API bearer JWT (audience: the API audience). The user name claim falls
    /// back to `sub`.
    pub async fn bearer_identity(&self, token: &str) -> Result<Identity, JwtError> {
        let Some(audience) = self.settings.api_audience.as_deref() else {
            return Err(JwtError::Claims("aud"));
        };
        let claims = self.validate(token, audience, None, false).await?;
        let (name, groups) = self.identity(&claims);
        let name = name
            .or_else(|| {
                claims
                    .get("sub")
                    .and_then(Value::as_str)
                    .and_then(clean_name)
            })
            .ok_or(JwtError::Claims("sub"))?;
        Ok(Identity {
            name,
            groups: groups.unwrap_or_default(),
        })
    }

    /// Takes one login start from the per-replica budget (burst 100, 10 per second).
    pub fn admit_login(&self) -> bool {
        let mut b = self.limiter.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        b.tokens = (b.tokens + now.duration_since(b.at).as_secs_f64() * LOGINS_PER_SECOND)
            .min(LOGIN_BURST);
        b.at = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// The authorization request URL for a new pending login.
    pub fn authorization_url(&self, p: &Provider, state: &str, pending: &PendingLogin) -> Url {
        let mut u = p.authorization.clone();
        u.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.settings.client_id)
            .append_pair("redirect_uri", self.settings.redirect_url.as_str())
            .append_pair("scope", &self.settings.scopes.join(" "))
            .append_pair("state", state)
            .append_pair("nonce", &pending.nonce)
            .append_pair("code_challenge", &pkce_challenge(&pending.verifier))
            .append_pair("code_challenge_method", "S256");
        u
    }

    /// Exchanges the authorization code; returns the ID token and the access token.
    pub async fn exchange(
        &self,
        p: &Provider,
        code: &str,
        verifier: &str,
    ) -> anyhow::Result<(String, Option<String>)> {
        self.check_egress(&p.token)?;
        let redirect = self.settings.redirect_url.as_str();
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect),
            ("code_verifier", verifier),
        ];
        let mut rb = self
            .token_http
            .post(p.token.clone())
            .header(header::ACCEPT, "application/json");
        if p.basic_auth {
            rb = rb.basic_auth(
                form_encode(&self.settings.client_id),
                Some(form_encode(&self.settings.client_secret)),
            );
        } else {
            form.push(("client_id", &self.settings.client_id));
            form.push(("client_secret", &self.settings.client_secret));
        }
        let resp = rb
            .form(&form)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("token request failed: {}", e.without_url()))?;
        let status = resp.status().as_u16();
        let body = read_limited(resp).await?;
        if status != 200 {
            bail!(
                "the token endpoint answered {status} ({})",
                error_code(&body)
            );
        }
        let v: Value = serde_json::from_slice(&body).context("the token response is not JSON")?;
        if v.get("token_type")
            .and_then(Value::as_str)
            .is_some_and(|t| !t.eq_ignore_ascii_case("bearer"))
        {
            bail!("the token response has an unexpected token_type");
        }
        let id = v
            .get("id_token")
            .and_then(Value::as_str)
            .context("the token response has no id_token")?
            .to_string();
        let access = v
            .get("access_token")
            .and_then(Value::as_str)
            .map(String::from);
        Ok((id, access))
    }

    /// Userinfo claims; their `sub` must be the ID token's.
    pub async fn userinfo(
        &self,
        p: &Provider,
        access_token: &str,
        sub: &str,
    ) -> anyhow::Result<Map<String, Value>> {
        let u = p
            .userinfo
            .as_ref()
            .context("the provider has no userinfo endpoint")?;
        let (status, body) = self.get_json(u, Some(access_token)).await?;
        if status != 200 {
            bail!("the userinfo endpoint answered {status}");
        }
        let v: Map<String, Value> =
            serde_json::from_slice(&body).context("the userinfo response is not a JSON object")?;
        if v.get("sub").and_then(Value::as_str) != Some(sub) {
            bail!("the userinfo sub differs from the ID token");
        }
        Ok(v)
    }

    /// The provider's RP-initiated logout URL. With the ID token of the session as `id_token_hint` the
    /// provider ends its session without asking the user to confirm.
    pub fn logout_url(&self, id_token_hint: Option<&str>) -> Option<String> {
        let p = self.provider()?;
        let mut u = p.end_session.clone()?;
        let back = self.settings.post_logout_redirect.clone();
        {
            let mut q = u.query_pairs_mut();
            q.append_pair("client_id", &self.settings.client_id)
                .append_pair("post_logout_redirect_uri", back.as_str());
            if let Some(t) = id_token_hint {
                q.append_pair("id_token_hint", t);
            }
        }
        Some(u.to_string())
    }

    /// `__Host-<name>_session`, or `<name>_session` with insecure cookies.
    pub fn session_cookie_name(&self) -> String {
        self.cookie_name("session")
    }

    /// `__Host-<name>_login`, or `<name>_login` with insecure cookies.
    pub fn login_cookie_name(&self) -> String {
        self.cookie_name("login")
    }

    fn cookie_name(&self, kind: &str) -> String {
        if self.settings.insecure_cookie {
            format!("{}_{kind}", self.settings.cookie_name)
        } else {
            format!("__Host-{}_{kind}", self.settings.cookie_name)
        }
    }

    /// A `Set-Cookie` value: `Path=/; HttpOnly; SameSite=Lax`, `Secure` unless insecure cookies
    /// are configured. An empty value with a zero `max_age` clears the cookie.
    pub fn cookie(&self, name: &str, value: &str, max_age: Duration) -> String {
        format!(
            "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}",
            max_age.as_secs(),
            if self.settings.insecure_cookie {
                ""
            } else {
                "; Secure"
            }
        )
    }

    /// The session cookie value of a request.
    pub fn session_id<'h>(&self, headers: &'h HeaderMap) -> Option<&'h str> {
        cookie_value(headers, &self.session_cookie_name())
    }
}

/// The value of a cookie in the request headers.
pub fn cookie_value<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim())
}

async fn background(weak: Weak<Oidc>) {
    let mut attempt: u32 = 0;
    let mut first = true;
    loop {
        let wait = {
            let Some(o) = weak.upgrade() else { return };
            if o.provider().is_none() {
                first = false;
                match o.discover().await {
                    Ok(()) => {
                        attempt = 0;
                        JWKS_REFRESH_EVERY
                    }
                    Err(e) => {
                        attempt = attempt.saturating_add(1);
                        let (err, invalid) = match e {
                            DiscoveryError::Invalid(e) => (e, true),
                            DiscoveryError::Unreachable(e) => (e, false),
                        };
                        if invalid {
                            tracing::error!(issuer = %o.settings.issuer, error = %err, "OIDC discovery document rejected; SSO stays unavailable");
                        } else {
                            tracing::warn!(issuer = %o.settings.issuer, error = %err, attempt, "OIDC discovery failed; retrying");
                        }
                        let secs = 1u64 << attempt.saturating_sub(1).min(6);
                        Duration::from_secs(secs.min(60))
                    }
                }
            } else if std::mem::take(&mut first) {
                JWKS_REFRESH_EVERY
            } else {
                if let Some(p) = o.provider() {
                    match o.fetch_jwks(&p.jwks_uri).await {
                        Ok(keys) => {
                            *o.jwks.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(keys);
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "periodic OIDC key refresh failed")
                        }
                    }
                }
                JWKS_REFRESH_EVERY
            }
        };
        tokio::time::sleep(wait).await;
    }
}
