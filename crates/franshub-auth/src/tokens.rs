//! Managed API tokens: the record, the store trait, value generation and the cached lookup service.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, SubsecRound, Utc};
use franshub_access::{ALL_SCOPES, Scopes};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const CACHE_MAX: usize = 16_384;
const NEGATIVE_MAX: usize = 4_096;
const TOUCHED_MAX: usize = 16_384;
const TOUCH_EVERY: Duration = Duration::from_secs(60);

/// A token managed through the API. Only the SHA-256 of the value is stored.
#[derive(Clone, Debug, PartialEq)]
pub struct ApiToken {
    /// Token id (UUIDv7).
    pub id: Uuid,
    /// Name, unique among active tokens.
    pub name: String,
    /// Lowercase hex SHA-256 of the value.
    pub sha256: String,
    /// Role granted.
    pub role: String,
    /// Scope keys; `["*"]` for every scope; empty for a global token.
    pub scopes: Vec<String>,
    /// Granted globally.
    pub global: bool,
    /// Free text.
    pub description: Option<String>,
    /// Name of the principal that created it.
    pub created_by: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Expiry; mandatory.
    pub expires_at: DateTime<Utc>,
    /// Last use, recorded at most once a minute.
    pub last_used_at: Option<DateTime<Utc>>,
    /// When it was revoked, or, for a token retired after expiry, its expiry.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Set by an explicit revocation.
    pub revoked: bool,
    /// The managed token that created this one.
    pub parent_id: Option<Uuid>,
}

/// State of a token at a point in time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenStatus {
    /// Usable.
    Active,
    /// Past its expiry.
    Expired,
    /// Revoked.
    Revoked,
}

impl ApiToken {
    /// The status at `now`.
    pub fn status(&self, now: DateTime<Utc>) -> TokenStatus {
        if self.revoked {
            TokenStatus::Revoked
        } else if self.expires_at <= now {
            TokenStatus::Expired
        } else {
            TokenStatus::Active
        }
    }

    /// The scopes of the token as a binding scope.
    pub fn binding_scopes(&self) -> Scopes {
        if self.global {
            Scopes::Global
        } else if self.scopes.len() == 1 && self.scopes[0] == ALL_SCOPES {
            Scopes::All
        } else {
            Scopes::List(self.scopes.clone())
        }
    }
}

/// Persistence of managed tokens.
#[async_trait]
pub trait TokenStore: Send + Sync {
    /// Stores a new token. Returns false when an active token already has the name; expired
    /// tokens with the name are retired first, so the name can be reused.
    async fn create(&self, token: &ApiToken, now: DateTime<Utc>) -> anyhow::Result<bool>;
    /// A token by id.
    async fn get(&self, id: Uuid) -> anyhow::Result<Option<ApiToken>>;
    /// A token by the SHA-256 of its value.
    async fn by_hash(&self, sha256: &str) -> anyhow::Result<Option<ApiToken>>;
    /// Every stored token, newest first (at most 10 000).
    async fn list(&self) -> anyhow::Result<Vec<ApiToken>>;
    /// Marks the token revoked; false when it does not exist, is already revoked or retired, or
    /// has expired by `at`.
    async fn revoke(&self, id: Uuid, at: DateTime<Utc>) -> anyhow::Result<bool>;
    /// Whether the store holds any token at all, whatever its status.
    async fn has_any(&self) -> anyhow::Result<bool> {
        Ok(!self.list().await?.is_empty())
    }
    /// Records a use, unless one was recorded less than a minute before `at`.
    async fn touch(&self, id: Uuid, at: DateTime<Utc>) -> anyhow::Result<()>;
    /// Number of active tokens at `now`.
    async fn count_active(&self, now: DateTime<Utc>) -> anyhow::Result<i64>;
    /// Deletes tokens revoked or expired before `at`; returns how many.
    async fn purge_inactive_before(&self, at: DateTime<Utc>) -> anyhow::Result<u64>;
}

/// An in-process [`TokenStore`] for tests and development.
#[derive(Default)]
pub struct MemoryTokenStore {
    tokens: Mutex<Vec<ApiToken>>,
}

#[async_trait]
impl TokenStore for MemoryTokenStore {
    async fn create(&self, t: &ApiToken, now: DateTime<Utc>) -> anyhow::Result<bool> {
        let mut v = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        for x in v.iter_mut() {
            if x.name == t.name && x.revoked_at.is_none() && x.expires_at <= now {
                x.revoked_at = Some(x.expires_at);
            }
        }
        if v.iter().any(|x| x.name == t.name && x.revoked_at.is_none()) {
            return Ok(false);
        }
        if v.iter().any(|x| x.sha256 == t.sha256 || x.id == t.id) {
            anyhow::bail!("duplicate token");
        }
        v.push(t.clone());
        Ok(true)
    }

    async fn get(&self, id: Uuid) -> anyhow::Result<Option<ApiToken>> {
        let v = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        Ok(v.iter().find(|t| t.id == id).cloned())
    }

    async fn by_hash(&self, sha256: &str) -> anyhow::Result<Option<ApiToken>> {
        let v = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        Ok(v.iter().find(|t| t.sha256 == sha256).cloned())
    }

    async fn list(&self) -> anyhow::Result<Vec<ApiToken>> {
        let v = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = v.clone();
        out.sort_by_key(|t| std::cmp::Reverse((t.created_at, t.id)));
        out.truncate(10_000);
        Ok(out)
    }

    async fn revoke(&self, id: Uuid, at: DateTime<Utc>) -> anyhow::Result<bool> {
        let mut v = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        match v
            .iter_mut()
            .find(|t| t.id == id && t.revoked_at.is_none() && t.expires_at > at)
        {
            Some(t) => {
                t.revoked = true;
                t.revoked_at = Some(at);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn touch(&self, id: Uuid, at: DateTime<Utc>) -> anyhow::Result<()> {
        let mut v = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = v.iter_mut().find(|t| t.id == id)
            && t.last_used_at
                .is_none_or(|l| l <= at - chrono::Duration::minutes(1))
        {
            t.last_used_at = Some(at);
        }
        Ok(())
    }

    async fn count_active(&self, now: DateTime<Utc>) -> anyhow::Result<i64> {
        let v = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        Ok(v.iter()
            .filter(|t| t.status(now) == TokenStatus::Active)
            .count() as i64)
    }

    async fn purge_inactive_before(&self, at: DateTime<Utc>) -> anyhow::Result<u64> {
        let mut v = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        let before = v.len();
        v.retain(|t| !(t.revoked_at.is_some_and(|r| r < at) || t.expires_at < at));
        Ok((before - v.len()) as u64)
    }
}

/// Lowercase hex SHA-256 of a token value.
pub fn hash_token(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// A token value. `Debug` and `Display` never show it; [`TokenSecret::expose`] does.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenSecret(String);

impl TokenSecret {
    /// The value, for the one response that returns it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for TokenSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenSecret([redacted])")
    }
}

impl std::fmt::Display for TokenSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

/// The managed token format of a product: a prefix such as `fp_` and 64 lowercase hex digits
/// (256 random bits). Values of another shape never reach the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenFormat {
    prefix: String,
}

impl TokenFormat {
    /// A format with this prefix: 1..=8 lowercase letters or digits followed by `_`.
    pub fn new(prefix: &str) -> anyhow::Result<Self> {
        let body = prefix.strip_suffix('_').unwrap_or_default();
        if body.is_empty()
            || body.len() > 8
            || !body
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            anyhow::bail!(
                "token prefix `{prefix}` must be 1..8 lowercase letters or digits followed by `_` (for example fp_)"
            );
        }
        Ok(Self {
            prefix: prefix.to_string(),
        })
    }

    /// The prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// A new random value.
    pub fn generate(&self) -> TokenSecret {
        let bytes: [u8; 32] = rand::random();
        TokenSecret(format!("{}{}", self.prefix, hex::encode(bytes)))
    }

    /// Whether a value has the managed format.
    pub fn matches(&self, value: &str) -> bool {
        value.len() == self.prefix.len() + 64
            && value.starts_with(&self.prefix)
            && value[self.prefix.len()..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}

/// Token times at the precision PostgreSQL stores (microseconds), so responses and later reads
/// agree.
pub fn stored_precision(t: DateTime<Utc>) -> DateTime<Utc> {
    t.trunc_subsecs(6)
}

/// Result of [`TokenService::lookup`].
#[derive(Debug)]
pub enum Lookup {
    /// Active.
    Valid(Arc<ApiToken>),
    /// Past its expiry.
    Expired(Arc<ApiToken>),
    /// Revoked.
    Revoked(Arc<ApiToken>),
    /// No such token.
    Unknown,
}

#[derive(Default)]
struct Cache {
    known: HashMap<String, (Instant, Arc<ApiToken>)>,
    unknown: HashMap<String, Instant>,
}

/// Managed tokens: the store plus a per-replica cache of lookups by hash. Cache entries live at
/// most `ttl`, so a revocation on another replica takes effect within it; expiry is checked on
/// every use. Unknown hashes are cached separately and bounded, since anyone can present them.
pub struct TokenService {
    store: Arc<dyn TokenStore>,
    format: TokenFormat,
    ttl: Duration,
    cache: Mutex<Cache>,
    touched: Mutex<HashMap<Uuid, Instant>>,
    any: Mutex<Option<(Instant, bool)>>,
}

impl std::fmt::Debug for TokenService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenService")
            .field("format", &self.format)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl TokenService {
    /// A service over a store, with a cache TTL (10 seconds is a good default).
    pub fn new(store: Arc<dyn TokenStore>, format: TokenFormat, ttl: Duration) -> Self {
        Self {
            store,
            format,
            ttl,
            cache: Mutex::new(Cache::default()),
            touched: Mutex::new(HashMap::new()),
            any: Mutex::new(None),
        }
    }

    /// The store.
    pub fn store(&self) -> &Arc<dyn TokenStore> {
        &self.store
    }

    /// The token format.
    pub fn format(&self) -> &TokenFormat {
        &self.format
    }

    /// The cache TTL: how long a revocation may take to reach this replica.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    async fn store_has_tokens(&self) -> anyhow::Result<bool> {
        let last = *self.any.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, any)) = last
            && at.elapsed() < self.ttl
        {
            return Ok(any);
        }
        match self.store.has_any().await {
            Ok(any) => {
                *self.any.lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), any));
                Ok(any)
            }
            Err(e) => match last {
                Some((_, false)) => {
                    tracing::warn!(error = %e, "checking for managed tokens failed; the store held none");
                    Ok(false)
                }
                _ => Err(e),
            },
        }
    }

    /// Records that the store now holds a token.
    pub fn note_created(&self) {
        *self.any.lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), true));
    }

    fn cached(&self, hash: &str) -> Option<Option<Arc<ApiToken>>> {
        let c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, t)) = c.known.get(hash)
            && at.elapsed() < self.ttl
        {
            return Some(Some(t.clone()));
        }
        c.unknown
            .get(hash)
            .filter(|at| at.elapsed() < self.ttl)
            .map(|_| None)
    }

    fn remember(&self, hash: String, token: Option<Arc<ApiToken>>) {
        let ttl = self.ttl;
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        match token {
            Some(t) => {
                c.unknown.remove(&hash);
                if c.known.len() >= CACHE_MAX {
                    c.known.retain(|_, (at, _)| at.elapsed() < ttl);
                    if c.known.len() >= CACHE_MAX {
                        c.known.clear();
                    }
                }
                c.known.insert(hash, (Instant::now(), t));
            }
            None => {
                c.known.remove(&hash);
                if c.unknown.len() >= NEGATIVE_MAX {
                    c.unknown.retain(|_, at| at.elapsed() < ttl);
                    if c.unknown.len() >= NEGATIVE_MAX {
                        c.unknown.clear();
                    }
                }
                c.unknown.insert(hash, Instant::now());
            }
        }
    }

    /// Drops a hash from this replica's cache.
    pub fn forget(&self, hash: &str) {
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        c.known.remove(hash);
        c.unknown.remove(hash);
    }

    /// Looks a presented value up: values not in the managed format are unknown without a store
    /// read; while the store holds no token at all, nothing is read either.
    pub async fn lookup(&self, value: &str) -> anyhow::Result<Lookup> {
        if !self.format.matches(value) {
            return Ok(Lookup::Unknown);
        }
        let hash = hash_token(value);
        let token = match self.cached(&hash) {
            Some(t) => t,
            None if !self.store_has_tokens().await? => None,
            None => {
                let t = self.store.by_hash(&hash).await?.map(Arc::new);
                self.remember(hash, t.clone());
                t
            }
        };
        Ok(match token {
            None => Lookup::Unknown,
            Some(t) => match t.status(Utc::now()) {
                TokenStatus::Active => Lookup::Valid(t),
                TokenStatus::Expired => Lookup::Expired(t),
                TokenStatus::Revoked => Lookup::Revoked(t),
            },
        })
    }

    /// Records the use of a token in the background, at most once a minute per token and replica.
    pub fn touch(&self, id: Uuid) {
        {
            let mut m = self.touched.lock().unwrap_or_else(|e| e.into_inner());
            if m.get(&id).is_some_and(|t| t.elapsed() < TOUCH_EVERY) {
                return;
            }
            if m.len() >= TOUCHED_MAX {
                m.retain(|_, t| t.elapsed() < TOUCH_EVERY);
                if m.len() >= TOUCHED_MAX {
                    m.clear();
                }
            }
            m.insert(id, Instant::now());
        }
        let store = self.store.clone();
        tokio::spawn(async move {
            if let Err(e) = store.touch(id, stored_precision(Utc::now())).await {
                metrics::counter!("store_errors_total", "store" => "tokens").increment(1);
                tracing::warn!(error = %e, token_id = %id, "recording the last use of a token failed");
            }
        });
    }

    #[cfg(test)]
    fn cache_sizes(&self) -> (usize, usize) {
        let c = self.cache.lock().unwrap();
        (c.known.len(), c.unknown.len())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

    use super::*;

    fn fmt() -> TokenFormat {
        TokenFormat::new("fp_").unwrap()
    }

    fn token(name: &str, value: &TokenSecret, expires_in: chrono::Duration) -> ApiToken {
        let now = Utc::now();
        ApiToken {
            id: Uuid::now_v7(),
            name: name.into(),
            sha256: hash_token(value.expose()),
            role: "viewer".into(),
            scopes: vec![],
            global: true,
            description: None,
            created_by: "ops".into(),
            created_at: now,
            expires_at: now + expires_in,
            last_used_at: None,
            revoked_at: None,
            revoked: false,
            parent_id: None,
        }
    }

    #[test]
    fn format_and_secrets() {
        let f = fmt();
        let v = f.generate();
        assert_eq!(v.expose().len(), 67);
        assert!(f.matches(v.expose()));
        assert_ne!(v, f.generate());
        assert!(!f.matches("fp_admin_token_for_tests_0123456789"));
        assert!(!f.matches(&v.expose().to_uppercase()));
        assert!(!f.matches(&format!("{}0", v.expose())));
        assert!(!TokenFormat::new("fm_").unwrap().matches(v.expose()));
        assert!(!format!("{v:?} {v}").contains(&v.expose()[3..]));
        for bad in ["", "fp", "_", "FP_", "toolongprefix_", "f-p_"] {
            assert!(TokenFormat::new(bad).is_err(), "{bad}");
        }
        assert_eq!(hash_token("abc").len(), 64);
    }

    #[tokio::test]
    async fn cache_honours_ttl_and_bounds_negatives() {
        let store = Arc::new(MemoryTokenStore::default());
        let svc = TokenService::new(store.clone(), fmt(), Duration::from_millis(200));
        let v = fmt().generate();
        let t = token("a", &v, chrono::Duration::days(1));
        store.create(&t, Utc::now()).await.unwrap();
        assert!(matches!(
            svc.lookup(v.expose()).await.unwrap(),
            Lookup::Valid(_)
        ));
        store.revoke(t.id, Utc::now()).await.unwrap();
        assert!(matches!(
            svc.lookup(v.expose()).await.unwrap(),
            Lookup::Valid(_)
        ));
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(matches!(
            svc.lookup(v.expose()).await.unwrap(),
            Lookup::Revoked(_)
        ));
        for _ in 0..(NEGATIVE_MAX + 10) {
            assert!(matches!(
                svc.lookup(fmt().generate().expose()).await.unwrap(),
                Lookup::Unknown
            ));
        }
        let (known, unknown) = svc.cache_sizes();
        assert!(unknown <= NEGATIVE_MAX);
        assert_eq!(known, 1);
        assert!(matches!(
            svc.lookup("not-a-token").await.unwrap(),
            Lookup::Unknown
        ));
    }

    #[derive(Default)]
    struct Probe {
        inner: MemoryTokenStore,
        lookups: AtomicUsize,
        down: AtomicBool,
    }

    impl Probe {
        fn check(&self) -> anyhow::Result<()> {
            if self.down.load(SeqCst) {
                anyhow::bail!("store down");
            }
            Ok(())
        }
    }

    #[async_trait]
    impl TokenStore for Probe {
        async fn create(&self, t: &ApiToken, now: DateTime<Utc>) -> anyhow::Result<bool> {
            self.inner.create(t, now).await
        }
        async fn get(&self, id: Uuid) -> anyhow::Result<Option<ApiToken>> {
            self.inner.get(id).await
        }
        async fn by_hash(&self, h: &str) -> anyhow::Result<Option<ApiToken>> {
            self.lookups.fetch_add(1, SeqCst);
            self.check()?;
            self.inner.by_hash(h).await
        }
        async fn list(&self) -> anyhow::Result<Vec<ApiToken>> {
            self.inner.list().await
        }
        async fn revoke(&self, id: Uuid, at: DateTime<Utc>) -> anyhow::Result<bool> {
            self.inner.revoke(id, at).await
        }
        async fn touch(&self, id: Uuid, at: DateTime<Utc>) -> anyhow::Result<()> {
            self.inner.touch(id, at).await
        }
        async fn count_active(&self, now: DateTime<Utc>) -> anyhow::Result<i64> {
            self.inner.count_active(now).await
        }
        async fn purge_inactive_before(&self, at: DateTime<Utc>) -> anyhow::Result<u64> {
            self.inner.purge_inactive_before(at).await
        }
        async fn has_any(&self) -> anyhow::Result<bool> {
            self.check()?;
            self.inner.has_any().await
        }
    }

    #[tokio::test]
    async fn unknown_values_skip_the_store_while_it_holds_no_tokens() {
        let probe = Arc::new(Probe::default());
        let svc = TokenService::new(probe.clone(), fmt(), Duration::from_millis(100));
        for _ in 0..5 {
            assert!(matches!(
                svc.lookup(fmt().generate().expose()).await.unwrap(),
                Lookup::Unknown
            ));
        }
        assert_eq!(probe.lookups.load(SeqCst), 0);
        probe.down.store(true, SeqCst);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            matches!(
                svc.lookup(fmt().generate().expose()).await.unwrap(),
                Lookup::Unknown
            ),
            "the store held no tokens, so a failed check still rejects"
        );
        probe.down.store(false, SeqCst);
        let v = fmt().generate();
        probe
            .create(&token("c", &v, chrono::Duration::days(1)), Utc::now())
            .await
            .unwrap();
        svc.note_created();
        assert!(matches!(
            svc.lookup(v.expose()).await.unwrap(),
            Lookup::Valid(_)
        ));
        assert_eq!(probe.lookups.load(SeqCst), 1);
        probe.down.store(true, SeqCst);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            svc.lookup(fmt().generate().expose()).await.is_err(),
            "with tokens in the store, an outage is reported"
        );
    }

    #[tokio::test]
    async fn expiry_is_checked_on_every_use_and_names_are_reused() {
        let store = Arc::new(MemoryTokenStore::default());
        let svc = TokenService::new(store.clone(), fmt(), Duration::from_secs(10));
        let v = fmt().generate();
        let t = token("b", &v, chrono::Duration::milliseconds(300));
        store.create(&t, Utc::now()).await.unwrap();
        assert!(matches!(
            svc.lookup(v.expose()).await.unwrap(),
            Lookup::Valid(_)
        ));
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert!(matches!(
            svc.lookup(v.expose()).await.unwrap(),
            Lookup::Expired(_)
        ));
        let again = token("b", &fmt().generate(), chrono::Duration::days(1));
        assert!(store.create(&again, Utc::now()).await.unwrap());
        let dup = token("b", &fmt().generate(), chrono::Duration::days(1));
        assert!(!store.create(&dup, Utc::now()).await.unwrap());
        assert_eq!(
            store.get(t.id).await.unwrap().unwrap().status(Utc::now()),
            TokenStatus::Expired
        );
        assert_eq!(store.count_active(Utc::now()).await.unwrap(), 1);
    }
}
