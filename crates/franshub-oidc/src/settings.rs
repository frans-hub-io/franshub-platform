//! OIDC client settings, checked at start-up.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use url::Url;

use crate::jwt::{ALL_ALGS, Alg};

/// Path of the sign-in callback; the redirect URL must end with it.
pub const CALLBACK_PATH: &str = "/auth/callback";

/// Raw OIDC settings as a product reads them (environment, file or code). [`OidcSettings::new`]
/// checks them.
#[derive(Clone, Default)]
pub struct OidcConfig {
    /// Issuer URL; compared with `iss` byte for byte.
    pub issuer: String,
    /// Client id; the audience of ID tokens.
    pub client_id: String,
    /// Client secret, inline. Set this or `client_secret_file`.
    pub client_secret: Option<String>,
    /// File holding the client secret (trailing whitespace trimmed).
    pub client_secret_file: Option<PathBuf>,
    /// Public URL of the callback: `<public origin>/auth/callback`.
    pub redirect_url: String,
    /// Requested scopes; must include `openid`. Default `openid profile email`.
    pub scopes: Option<Vec<String>>,
    /// Claim (or dotted path) holding the user name. Default `preferred_username`.
    pub username_claim: Option<String>,
    /// Claim (or dotted path such as `realm_access.roles`) holding the groups. Default `groups`.
    pub groups_claim: Option<String>,
    /// Accepted signature algorithms (`RS256`, `PS256`, `ES256`, `EdDSA`). Default all four.
    pub allowed_algs: Option<Vec<String>>,
    /// Audience of bearer JWTs accepted on the API; `None` turns bearer JWTs off. Must differ from
    /// the client id.
    pub api_audience: Option<String>,
    /// Extra CA bundle (PEM) for the provider's TLS certificate.
    pub ca_file: Option<PathBuf>,
    /// Absolute session lifetime. Default 8 hours.
    pub session_ttl: Option<Duration>,
    /// Idle timeout of a session. Default 1 hour.
    pub session_idle: Option<Duration>,
    /// Hosts besides the issuer's that discovery may point to.
    pub allowed_hosts: Vec<String>,
    /// Base name of the cookies (`<name>_session`, `<name>_login`). Default `franshub`.
    pub cookie_name: Option<String>,
    /// Cookies without `Secure` and without the `__Host-` prefix; only for a loopback redirect URL.
    pub insecure_cookie: bool,
    /// Where the provider sends the browser after logout; default the public origin plus
    /// `return_prefix`.
    pub post_logout_redirect: Option<String>,
    /// Sign-in return paths must start with it; failed sign-ins go to `<prefix>?loginError=<code>`.
    /// Default `/`.
    pub return_prefix: Option<String>,
}

impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("client_secret_file", &self.client_secret_file)
            .field("redirect_url", &self.redirect_url)
            .finish_non_exhaustive()
    }
}

/// Checked OIDC settings.
#[derive(Clone)]
pub struct OidcSettings {
    /// Exactly as configured: compared with `iss` byte for byte.
    pub issuer: String,
    /// The issuer as a URL.
    pub issuer_url: Url,
    /// Client id.
    pub client_id: String,
    pub(crate) client_secret: String,
    /// Callback URL.
    pub redirect_url: Url,
    /// Requested scopes.
    pub scopes: Vec<String>,
    /// User name claim.
    pub username_claim: String,
    /// Groups claim.
    pub groups_claim: String,
    /// Accepted algorithms.
    pub allowed_algs: Vec<Alg>,
    /// Audience of API bearer JWTs.
    pub api_audience: Option<String>,
    /// Extra CA bundle.
    pub ca_file: Option<PathBuf>,
    /// Absolute session lifetime.
    pub session_ttl: Duration,
    /// Session idle timeout.
    pub session_idle: Duration,
    /// Hosts besides the issuer's that discovery may point to (lowercase).
    pub allowed_hosts: Vec<String>,
    /// Cookie base name.
    pub cookie_name: String,
    /// Cookies without `Secure` and the `__Host-` prefix.
    pub insecure_cookie: bool,
    /// Post-logout redirect URL.
    pub post_logout_redirect: Url,
    /// Prefix of sign-in return paths.
    pub return_prefix: String,
}

impl std::fmt::Debug for OidcSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcSettings")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[redacted]")
            .field("redirect_url", &self.redirect_url.as_str())
            .field("scopes", &self.scopes)
            .field("username_claim", &self.username_claim)
            .field("groups_claim", &self.groups_claim)
            .field("allowed_algs", &self.allowed_algs)
            .field("api_audience", &self.api_audience)
            .field("ca_file", &self.ca_file)
            .field("session_ttl", &self.session_ttl)
            .field("session_idle", &self.session_idle)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("cookie_name", &self.cookie_name)
            .field("insecure_cookie", &self.insecure_cookie)
            .field("post_logout_redirect", &self.post_logout_redirect.as_str())
            .field("return_prefix", &self.return_prefix)
            .finish()
    }
}

/// `localhost`, `127.0.0.1` or `::1`: the only hosts that may use plain http.
pub fn is_loopback(u: &Url) -> bool {
    match u.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip == std::net::Ipv4Addr::LOCALHOST,
        Some(url::Host::Ipv6(ip)) => ip == std::net::Ipv6Addr::LOCALHOST,
        None => false,
    }
}

fn http_url(raw: &str, what: &str) -> anyhow::Result<Url> {
    let u = Url::parse(raw.trim()).with_context(|| format!("{what} is not a URL"))?;
    if !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() {
        bail!("{what} must not contain credentials or a fragment");
    }
    match u.scheme() {
        "https" => {}
        "http" if is_loopback(&u) => {}
        _ => bail!(
            "{what} must be an https URL (plain http is accepted only for localhost, 127.0.0.1 and ::1)"
        ),
    }
    if u.host_str().is_none_or(str::is_empty) {
        bail!("{what} has no host");
    }
    Ok(u)
}

fn claim_path(v: Option<String>, default: &str, what: &str) -> anyhow::Result<String> {
    let c = v
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| default.into());
    if c.is_empty() || c.split('.').any(str::is_empty) {
        bail!("{what} `{c}` has an empty path segment");
    }
    Ok(c)
}

impl OidcSettings {
    /// Checks a configuration and reads the client secret file.
    pub fn new(c: OidcConfig) -> anyhow::Result<Self> {
        let issuer = c.issuer.trim().to_string();
        let issuer_url = http_url(&issuer, "the OIDC issuer")?;
        if issuer_url.query().is_some() {
            bail!("the OIDC issuer must not contain a query");
        }
        let client_id = c.client_id.trim().to_string();
        if client_id.is_empty() {
            bail!("the OIDC client id is required");
        }
        let client_secret = match (c.client_secret, c.client_secret_file) {
            (Some(_), Some(_)) => {
                bail!("set either the OIDC client secret or the client secret file, not both")
            }
            (Some(s), None) => s.trim().to_string(),
            (None, Some(f)) => std::fs::read_to_string(&f)
                .map_err(|e| {
                    anyhow::anyhow!("reading the OIDC client secret file {}: {e}", f.display())
                })?
                .trim()
                .to_string(),
            (None, None) => bail!(
                "the OIDC client secret (or a file holding it) is required: the server is a confidential client"
            ),
        };
        if client_secret.is_empty() {
            bail!("the OIDC client secret is empty");
        }
        let redirect_url = http_url(&c.redirect_url, "the OIDC redirect URL")?;
        if redirect_url.path() != CALLBACK_PATH || redirect_url.query().is_some() {
            bail!(
                "the OIDC redirect URL must be the public origin followed by {CALLBACK_PATH}, without a query (for example https://reports.example.com{CALLBACK_PATH})"
            );
        }
        let scopes = c
            .scopes
            .unwrap_or_else(|| vec!["openid".into(), "profile".into(), "email".into()]);
        if !scopes.iter().any(|s| s == "openid") {
            bail!("the OIDC scopes must include openid");
        }
        if let Some(bad) = scopes.iter().find(|s| {
            s.is_empty()
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
        }) {
            bail!("invalid OIDC scope `{bad}`");
        }
        let username_claim = claim_path(
            c.username_claim,
            "preferred_username",
            "the OIDC username claim",
        )?;
        let groups_claim = claim_path(c.groups_claim, "groups", "the OIDC groups claim")?;
        let allowed_algs = match c.allowed_algs {
            None => ALL_ALGS.to_vec(),
            Some(list) => {
                let mut out = Vec::new();
                for a in &list {
                    let alg = Alg::parse(a.trim()).ok_or_else(|| {
                        anyhow::anyhow!(
                            "OIDC algorithm `{a}` is not supported: use RS256, PS256, ES256 or EdDSA"
                        )
                    })?;
                    if !out.contains(&alg) {
                        out.push(alg);
                    }
                }
                if out.is_empty() {
                    bail!("the OIDC algorithm list is empty");
                }
                out
            }
        };
        let api_audience = c.api_audience.map(|s| s.trim().to_string());
        match api_audience.as_deref() {
            Some("") => bail!(
                "the OIDC API audience is set but empty: set the audience of API tokens, or leave it unset to turn bearer JWTs off"
            ),
            Some(a) if a == client_id => bail!(
                "the OIDC API audience must differ from the client id: the client id is the audience of ID tokens, which are not API tokens"
            ),
            _ => {}
        }
        let session_ttl = c.session_ttl.unwrap_or(Duration::from_secs(8 * 3600));
        let session_idle = c.session_idle.unwrap_or(Duration::from_secs(3600));
        if session_ttl.is_zero() || session_idle.is_zero() {
            bail!("the session lifetime and idle timeout must be greater than zero");
        }
        let mut allowed_hosts = Vec::new();
        for h in &c.allowed_hosts {
            let h = h.trim().to_ascii_lowercase();
            if h.is_empty()
                || !h
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
            {
                bail!("OIDC allowed host `{h}` is not a host name");
            }
            allowed_hosts.push(h);
        }
        let cookie_name = c.cookie_name.unwrap_or_else(|| "franshub".into());
        if cookie_name.is_empty()
            || cookie_name.len() > 32
            || !cookie_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            bail!("the cookie name must be 1..32 characters of [A-Za-z0-9_-]");
        }
        if c.insecure_cookie && !is_loopback(&redirect_url) {
            bail!(
                "insecure cookies are allowed only when the redirect URL points to localhost, 127.0.0.1 or ::1"
            );
        }
        let return_prefix = c.return_prefix.unwrap_or_else(|| "/".into());
        if !return_prefix.starts_with('/')
            || !return_prefix.ends_with('/')
            || return_prefix.contains("//")
            || return_prefix.contains(['\\', '?', '#'])
        {
            bail!("the return prefix must be a path starting and ending with /");
        }
        let post_logout_redirect = match c.post_logout_redirect {
            Some(u) => http_url(&u, "the post-logout redirect URL")?,
            None => {
                let mut u = redirect_url.clone();
                u.set_path(&return_prefix);
                u.set_query(None);
                u
            }
        };
        Ok(Self {
            issuer,
            issuer_url,
            client_id,
            client_secret,
            redirect_url,
            scopes,
            username_claim,
            groups_claim,
            allowed_algs,
            api_audience,
            ca_file: c.ca_file,
            session_ttl,
            session_idle,
            allowed_hosts,
            cookie_name,
            insecure_cookie: c.insecure_cookie,
            post_logout_redirect,
            return_prefix,
        })
    }
}

fn parse_duration(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    let split = s
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| anyhow::anyhow!("`{s}` needs a unit: s, m, h or d"))?;
    let (n, unit) = s.split_at(split);
    let n: u64 = n
        .parse()
        .map_err(|_| anyhow::anyhow!("`{s}` is not a duration"))?;
    let secs = match unit {
        "s" => n,
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(3600),
        "d" => n.saturating_mul(86_400),
        _ => bail!("`{s}`: unknown unit, use s, m, h or d"),
    };
    Ok(Duration::from_secs(secs))
}

fn split(v: &str) -> Vec<String> {
    v.split([',', ' ', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn bool_of(name: &str, v: Option<String>) -> anyhow::Result<bool> {
    match v
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .as_deref()
    {
        None => Ok(false),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "no" | "off") => Ok(false),
        Some(other) => bail!("{name}: not a boolean: {other}"),
    }
}

const VARS: &[&str] = &[
    "OIDC_CLIENT_ID",
    "OIDC_CLIENT_SECRET",
    "OIDC_CLIENT_SECRET_FILE",
    "OIDC_REDIRECT_URL",
    "OIDC_SCOPES",
    "OIDC_USERNAME_CLAIM",
    "OIDC_GROUPS_CLAIM",
    "OIDC_ALLOWED_ALGS",
    "OIDC_API_AUDIENCE",
    "OIDC_CA_FILE",
    "OIDC_SESSION_TTL",
    "OIDC_SESSION_IDLE",
    "OIDC_ALLOWED_HOSTS",
    "OIDC_COOKIE_NAME",
    "OIDC_INSECURE_COOKIE",
    "OIDC_POST_LOGOUT_REDIRECT",
];

impl OidcConfig {
    /// Reads `<prefix>OIDC_*` variables through `env` (for example with prefix `FASTPROOF_`:
    /// `FASTPROOF_OIDC_ISSUER`, `..._CLIENT_ID`, `..._CLIENT_SECRET` or `..._CLIENT_SECRET_FILE`,
    /// `..._REDIRECT_URL`, `..._SCOPES`, `..._USERNAME_CLAIM`, `..._GROUPS_CLAIM`,
    /// `..._ALLOWED_ALGS`, `..._API_AUDIENCE`, `..._CA_FILE`, `..._SESSION_TTL` and
    /// `..._SESSION_IDLE` (`30m`, `8h`), `..._ALLOWED_HOSTS`, `..._COOKIE_NAME`,
    /// `..._INSECURE_COOKIE`, `..._POST_LOGOUT_REDIRECT`). `None` when the issuer is not set;
    /// then no other OIDC variable may be set either.
    pub fn from_env(
        prefix: &str,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Option<Self>> {
        let var = |k: &str| env(&format!("{prefix}{k}")).filter(|v| !v.trim().is_empty());
        let Some(issuer) = var("OIDC_ISSUER") else {
            if let Some(v) = VARS.iter().find(|v| var(v).is_some()) {
                bail!("{prefix}{v} is set but {prefix}OIDC_ISSUER is not: OIDC needs an issuer");
            }
            return Ok(None);
        };
        let dur = |k: &str| -> anyhow::Result<Option<Duration>> {
            var(k)
                .map(|v| parse_duration(&v).with_context(|| format!("{prefix}{k}")))
                .transpose()
        };
        Ok(Some(Self {
            issuer,
            client_id: var("OIDC_CLIENT_ID").unwrap_or_default(),
            client_secret: var("OIDC_CLIENT_SECRET"),
            client_secret_file: var("OIDC_CLIENT_SECRET_FILE").map(|f| PathBuf::from(f.trim())),
            redirect_url: var("OIDC_REDIRECT_URL").unwrap_or_default(),
            scopes: var("OIDC_SCOPES").map(|s| split(&s)),
            username_claim: var("OIDC_USERNAME_CLAIM"),
            groups_claim: var("OIDC_GROUPS_CLAIM"),
            allowed_algs: var("OIDC_ALLOWED_ALGS").map(|s| split(&s)),
            api_audience: env(&format!("{prefix}OIDC_API_AUDIENCE")),
            ca_file: var("OIDC_CA_FILE").map(|f| PathBuf::from(f.trim())),
            session_ttl: dur("OIDC_SESSION_TTL")?,
            session_idle: dur("OIDC_SESSION_IDLE")?,
            allowed_hosts: var("OIDC_ALLOWED_HOSTS")
                .map(|s| split(&s))
                .unwrap_or_default(),
            cookie_name: var("OIDC_COOKIE_NAME"),
            insecure_cookie: bool_of(
                &format!("{prefix}OIDC_INSECURE_COOKIE"),
                var("OIDC_INSECURE_COOKIE"),
            )?,
            post_logout_redirect: var("OIDC_POST_LOGOUT_REDIRECT"),
            return_prefix: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn base() -> OidcConfig {
        OidcConfig {
            issuer: "https://idp.example.com/realms/test".into(),
            client_id: "reports".into(),
            client_secret: Some("s3cret-value".into()),
            redirect_url: "https://reports.example.com/auth/callback".into(),
            ..Default::default()
        }
    }

    fn err(c: OidcConfig) -> String {
        format!("{:#}", OidcSettings::new(c).unwrap_err())
    }

    #[test]
    fn defaults_and_redaction() {
        let s = OidcSettings::new(base()).unwrap();
        assert_eq!(s.scopes, ["openid", "profile", "email"]);
        assert_eq!(s.username_claim, "preferred_username");
        assert_eq!(s.groups_claim, "groups");
        assert_eq!(s.allowed_algs, ALL_ALGS.to_vec());
        assert_eq!(s.session_ttl, Duration::from_secs(8 * 3600));
        assert_eq!(s.session_idle, Duration::from_secs(3600));
        assert_eq!(s.cookie_name, "franshub");
        assert_eq!(
            s.post_logout_redirect.as_str(),
            "https://reports.example.com/"
        );
        assert!(!format!("{s:?}").contains("s3cret"));
        assert!(!format!("{:?}", base()).contains("s3cret"));
    }

    #[test]
    fn validation() {
        let with = |f: &dyn Fn(&mut OidcConfig)| {
            let mut c = base();
            f(&mut c);
            c
        };
        assert!(err(with(&|c| c.issuer = "http://idp.example.com".into())).contains("https"));
        assert!(OidcSettings::new(with(&|c| c.issuer = "http://127.0.0.1:8081/x".into())).is_ok());
        assert!(err(with(&|c| c.issuer = "ftp://idp.example.com".into())).contains("https"));
        assert!(
            err(with(
                &|c| c.redirect_url = "https://reports.example.com/cb".into()
            ))
            .contains("/auth/callback")
        );
        assert!(
            err(with(
                &|c| c.redirect_url = "http://reports.example.com/auth/callback".into()
            ))
            .contains("https")
        );
        assert!(err(with(&|c| c.scopes = Some(vec!["profile".into()]))).contains("openid"));
        assert!(
            err(with(
                &|c| c.groups_claim = Some("realm_access..roles".into())
            ))
            .contains("empty")
        );
        assert!(err(with(&|c| c.allowed_algs = Some(vec!["HS256".into()]))).contains("HS256"));
        assert!(err(with(&|c| c.allowed_algs = Some(vec![]))).contains("empty"));
        let rs = OidcSettings::new(with(&|c| {
            c.allowed_algs = Some(vec!["RS256".into(), "RS256".into()])
        }))
        .unwrap();
        assert_eq!(rs.allowed_algs, vec![Alg::Rs256]);
        assert!(err(with(&|c| c.api_audience = Some(" ".into()))).contains("empty"));
        assert!(err(with(&|c| c.api_audience = Some("reports".into()))).contains("must differ"));
        assert!(err(with(&|c| c.insecure_cookie = true)).contains("localhost"));
        assert!(err(with(&|c| c.client_secret = None)).contains("client secret"));
        assert!(
            err(with(&|c| c.client_secret_file = Some("/nonexistent".into()))).contains("not both")
        );
        assert!(err(with(&|c| c.client_id = String::new())).contains("client id"));
        assert!(err(with(&|c| c.session_idle = Some(Duration::ZERO))).contains("greater"));
        assert!(err(with(&|c| c.cookie_name = Some("a b".into()))).contains("cookie name"));
        assert!(err(with(&|c| c.return_prefix = Some("ui".into()))).contains("return prefix"));
        let local = OidcSettings::new(with(&|c| {
            c.insecure_cookie = true;
            c.redirect_url = "http://localhost:9090/auth/callback".into();
        }))
        .unwrap();
        assert!(local.insecure_cookie);
    }

    #[test]
    fn from_env_with_a_prefix() {
        let f = std::env::temp_dir().join(format!("franshub-oidc-{}", rand::random::<u64>()));
        std::fs::write(&f, "from-file\n").unwrap();
        let m: HashMap<String, String> = [
            ("FP_OIDC_ISSUER", "https://idp.example.com/realms/test"),
            ("FP_OIDC_CLIENT_ID", "reports"),
            ("FP_OIDC_CLIENT_SECRET_FILE", f.to_str().unwrap()),
            (
                "FP_OIDC_REDIRECT_URL",
                "https://reports.example.com/auth/callback",
            ),
            ("FP_OIDC_SESSION_IDLE", "30m"),
            ("FP_OIDC_GROUPS_CLAIM", "realm_access.roles"),
            ("FP_OIDC_ALLOWED_ALGS", "RS256, ES256"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let c = OidcConfig::from_env("FP_", &|k| m.get(k).cloned())
            .unwrap()
            .unwrap();
        let s = OidcSettings::new(c).unwrap();
        assert_eq!(s.client_secret, "from-file");
        assert_eq!(s.session_idle, Duration::from_secs(1800));
        assert_eq!(s.groups_claim, "realm_access.roles");
        assert_eq!(s.allowed_algs, vec![Alg::Rs256, Alg::Es256]);
        std::fs::remove_file(f).unwrap();
        assert!(OidcConfig::from_env("FP_", &|_| None).unwrap().is_none());
        let only_id = |k: &str| (k == "FP_OIDC_CLIENT_ID").then(|| "x".to_string());
        assert!(
            format!("{:#}", OidcConfig::from_env("FP_", &only_id).unwrap_err())
                .contains("FP_OIDC_ISSUER is not")
        );
        let bad_ttl = |k: &str| match k {
            "FP_OIDC_ISSUER" => Some("https://idp.example.com".to_string()),
            "FP_OIDC_SESSION_TTL" => Some("8x".to_string()),
            _ => None,
        };
        assert!(
            format!("{:#}", OidcConfig::from_env("FP_", &bad_ttl).unwrap_err())
                .contains("FP_OIDC_SESSION_TTL")
        );
    }
}
