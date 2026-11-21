//! Server-side sessions and pending logins. Stores only see SHA-256 hashes of the secrets the
//! browser holds (session id, login state).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How long a pending login waits for its callback.
pub const LOGIN_TTL: Duration = Duration::from_secs(600);
/// Most groups kept per user.
pub const MAX_GROUPS: usize = 256;
/// Longest user or group name kept.
pub const MAX_NAME_BYTES: usize = 256;
/// Longest ID token kept for the logout hint; a larger one is dropped.
pub const MAX_ID_TOKEN_BYTES: usize = 16 * 1024;

/// 256 random bits, base64url (43 characters).
pub fn random_secret() -> String {
    let b: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(b)
}

/// Whether a value has the shape of [`random_secret`].
pub fn looks_like_secret(v: &str) -> bool {
    v.len() == 43
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Lowercase hex SHA-256: the store key of a secret.
pub fn digest(v: &str) -> String {
    hex::encode(Sha256::digest(v.as_bytes()))
}

/// A signed-in user's session.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    /// User name.
    pub name: String,
    /// Group names at sign-in.
    pub groups: Vec<String>,
    /// Sign-in time.
    pub created_at: DateTime<Utc>,
    /// Last use (written at most every [`Lifetimes::touch_every`]).
    pub last_seen: DateTime<Utc>,
    /// The ID token of the sign-in, sent back as `id_token_hint` on logout. Never in a cookie, a
    /// log line or a response other than the logout URL.
    pub id_token: Option<String>,
}

impl std::fmt::Debug for SessionRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionRecord")
            .field("name", &self.name)
            .field("groups", &self.groups)
            .field("created_at", &self.created_at)
            .field("last_seen", &self.last_seen)
            .field("id_token", &self.id_token.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// A login between the redirect to the provider and the callback.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingLogin {
    /// `nonce` sent to the provider.
    pub nonce: String,
    /// PKCE code verifier.
    pub verifier: String,
    /// Where the browser goes after sign-in.
    pub return_to: String,
    /// SHA-256 of the login cookie that ties the callback to the browser that started the login.
    pub browser: String,
}

impl std::fmt::Debug for PendingLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingLogin")
            .field("return_to", &self.return_to)
            .finish_non_exhaustive()
    }
}

/// Persistence of sessions and pending logins. Keys are [`digest`]s of the browser's secrets.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Stores a new session that may be deleted after `expires_at`.
    async fn create_session(
        &self,
        key: &str,
        record: &SessionRecord,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()>;
    /// A session by key, expired or not (the caller checks the lifetimes).
    async fn session(&self, key: &str) -> anyhow::Result<Option<SessionRecord>>;
    /// Records a later use: `last_seen` and `expires_at` only move forward.
    async fn touch_session(
        &self,
        key: &str,
        last_seen: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()>;
    /// Deletes a session and returns it when it existed.
    async fn delete_session(&self, key: &str) -> anyhow::Result<Option<SessionRecord>>;
    /// Stores a pending login.
    async fn put_login(
        &self,
        key: &str,
        login: &PendingLogin,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()>;
    /// Removes and returns a pending login that has not expired at `now`: only one caller gets it.
    async fn take_login(
        &self,
        key: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Option<PendingLogin>>;
    /// Deletes expired sessions and pending logins; returns how many.
    async fn purge_expired(&self, now: DateTime<Utc>) -> anyhow::Result<u64>;
}

/// Session lifetimes.
#[derive(Clone, Copy, Debug)]
pub struct Lifetimes {
    /// Absolute lifetime.
    pub ttl: Duration,
    /// Idle timeout.
    pub idle: Duration,
}

fn chrono_dur(d: Duration) -> chrono::Duration {
    chrono::Duration::from_std(d).unwrap_or(chrono::Duration::MAX)
}

impl Lifetimes {
    /// How often `last_seen` is written back: at most once a minute, and often enough that the idle
    /// timeout is not overshot by more than a quarter.
    pub fn touch_every(&self) -> Duration {
        (self.idle / 4).min(Duration::from_secs(60))
    }

    /// When the session ends unless used again.
    pub fn expires_at(&self, r: &SessionRecord) -> DateTime<Utc> {
        let abs = r
            .created_at
            .checked_add_signed(chrono_dur(self.ttl))
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        let idle = r
            .last_seen
            .checked_add_signed(chrono_dur(self.idle))
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        abs.min(idle)
    }
}

/// The session logic on top of a [`SessionStore`]: creation, lifetimes, throttled touches.
pub struct Sessions<'a> {
    /// The store.
    pub store: &'a dyn SessionStore,
    /// Lifetimes.
    pub life: Lifetimes,
}

impl Sessions<'_> {
    /// Creates a session and returns its id (the cookie value).
    pub async fn create(
        &self,
        name: &str,
        groups: Vec<String>,
        id_token: Option<String>,
    ) -> anyhow::Result<String> {
        let id = random_secret();
        let now = Utc::now();
        let r = SessionRecord {
            name: name.to_string(),
            groups,
            created_at: now,
            last_seen: now,
            id_token: id_token.filter(|t| t.len() <= MAX_ID_TOKEN_BYTES),
        };
        self.store
            .create_session(&digest(&id), &r, self.life.expires_at(&r))
            .await?;
        Ok(id)
    }

    /// The live session of a cookie value; `None` when unknown or expired (expired ones are
    /// deleted). Updates `last_seen`, throttled.
    pub async fn get(&self, id: &str) -> anyhow::Result<Option<SessionRecord>> {
        if !looks_like_secret(id) {
            return Ok(None);
        }
        let key = digest(id);
        let Some(mut r) = self.store.session(&key).await? else {
            return Ok(None);
        };
        let now = Utc::now();
        if self.life.expires_at(&r) <= now {
            self.store.delete_session(&key).await?;
            return Ok(None);
        }
        let every = chrono_dur(self.life.touch_every());
        if now - r.last_seen >= every {
            r.last_seen = now;
            self.store
                .touch_session(&key, now, self.life.expires_at(&r))
                .await?;
        }
        Ok(Some(r))
    }

    /// Deletes a session; returns it when it existed.
    pub async fn delete(&self, id: &str) -> anyhow::Result<Option<SessionRecord>> {
        if !looks_like_secret(id) {
            return Ok(None);
        }
        self.store.delete_session(&digest(id)).await
    }

    /// Stores a pending login under the digest of its `state`.
    pub async fn put_login(&self, state: &str, p: &PendingLogin) -> anyhow::Result<()> {
        self.store
            .put_login(&digest(state), p, Utc::now() + chrono_dur(LOGIN_TTL))
            .await
    }

    /// Takes the pending login of a `state`: single use.
    pub async fn take_login(&self, state: &str) -> anyhow::Result<Option<PendingLogin>> {
        if !looks_like_secret(state) {
            return Ok(None);
        }
        self.store.take_login(&digest(state), Utc::now()).await
    }
}

/// An in-process [`SessionStore`] for tests, development and single-replica servers. Bounded:
/// when full, expired entries are purged and new ones refused if it is still full.
pub struct MemorySessionStore {
    max_sessions: usize,
    max_logins: usize,
    sessions: Mutex<HashMap<String, (SessionRecord, DateTime<Utc>)>>,
    logins: Mutex<HashMap<String, (PendingLogin, DateTime<Utc>)>>,
}

impl MemorySessionStore {
    /// A store holding at most these many sessions and pending logins.
    pub fn new(max_sessions: usize, max_logins: usize) -> Self {
        Self {
            max_sessions: max_sessions.max(1),
            max_logins: max_logins.max(1),
            sessions: Mutex::new(HashMap::new()),
            logins: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MemorySessionStore {
    fn default() -> Self {
        Self::new(100_000, 10_000)
    }
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn create_session(
        &self,
        key: &str,
        record: &SessionRecord,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let mut m = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() >= self.max_sessions {
            let now = Utc::now();
            m.retain(|_, (_, exp)| *exp > now);
            if m.len() >= self.max_sessions {
                anyhow::bail!("the session store is full");
            }
        }
        m.insert(key.to_string(), (record.clone(), expires_at));
        Ok(())
    }

    async fn session(&self, key: &str) -> anyhow::Result<Option<SessionRecord>> {
        let m = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        Ok(m.get(key).map(|(r, _)| r.clone()))
    }

    async fn touch_session(
        &self,
        key: &str,
        last_seen: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let mut m = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((r, exp)) = m.get_mut(key) {
            r.last_seen = r.last_seen.max(last_seen);
            *exp = (*exp).max(expires_at);
        }
        Ok(())
    }

    async fn delete_session(&self, key: &str) -> anyhow::Result<Option<SessionRecord>> {
        let mut m = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        Ok(m.remove(key).map(|(r, _)| r))
    }

    async fn put_login(
        &self,
        key: &str,
        login: &PendingLogin,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let mut m = self.logins.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() >= self.max_logins {
            let now = Utc::now();
            m.retain(|_, (_, exp)| *exp > now);
            if m.len() >= self.max_logins {
                anyhow::bail!("too many pending logins");
            }
        }
        m.insert(key.to_string(), (login.clone(), expires_at));
        Ok(())
    }

    async fn take_login(
        &self,
        key: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Option<PendingLogin>> {
        let mut m = self.logins.lock().unwrap_or_else(|e| e.into_inner());
        Ok(m.remove(key).filter(|(_, exp)| *exp > now).map(|(p, _)| p))
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> anyhow::Result<u64> {
        let mut n = 0;
        {
            let mut m = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            let before = m.len();
            m.retain(|_, (_, exp)| *exp > now);
            n += before - m.len();
        }
        let mut m = self.logins.lock().unwrap_or_else(|e| e.into_inner());
        let before = m.len();
        m.retain(|_, (_, exp)| *exp > now);
        n += before - m.len();
        Ok(n as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn idle_and_absolute_expiry() {
        let store = MemorySessionStore::default();
        let s = Sessions {
            store: &store,
            life: Lifetimes {
                ttl: Duration::from_millis(900),
                idle: Duration::from_millis(400),
            },
        };
        let id = s.create("alice", vec!["g".into()], None).await.unwrap();
        assert!(looks_like_secret(&id));
        assert_eq!(s.get(&id).await.unwrap().unwrap().name, "alice");
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert!(s.get(&id).await.unwrap().is_some());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(s.get(&id).await.unwrap().is_none(), "absolute lifetime");
        let id = s.create("bob", vec![], None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(450)).await;
        assert!(s.get(&id).await.unwrap().is_none(), "idle timeout");
        let id = s
            .create("carol", vec![], Some("x".repeat(MAX_ID_TOKEN_BYTES + 1)))
            .await
            .unwrap();
        let r = s.delete(&id).await.unwrap().unwrap();
        assert_eq!(r.name, "carol");
        assert!(r.id_token.is_none(), "oversized ID tokens are dropped");
        assert!(s.get(&id).await.unwrap().is_none());
        assert!(s.get("short").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn pending_logins_are_single_use_and_bounded() {
        let store = MemorySessionStore::new(2, 2);
        let s = Sessions {
            store: &store,
            life: Lifetimes {
                ttl: Duration::from_secs(60),
                idle: Duration::from_secs(60),
            },
        };
        let state = random_secret();
        let p = PendingLogin {
            nonce: "n".into(),
            verifier: "secret-verifier".into(),
            return_to: "/".into(),
            browser: "b".into(),
        };
        assert!(!format!("{p:?}").contains("secret-verifier"));
        s.put_login(&state, &p).await.unwrap();
        assert!(s.take_login(&state).await.unwrap().is_some());
        assert!(s.take_login(&state).await.unwrap().is_none());
        assert!(s.take_login("x").await.unwrap().is_none());
        s.put_login(&random_secret(), &p).await.unwrap();
        s.put_login(&random_secret(), &p).await.unwrap();
        assert!(s.put_login(&random_secret(), &p).await.is_err());
        s.create("a", vec![], None).await.unwrap();
        s.create("b", vec![], None).await.unwrap();
        assert!(s.create("c", vec![], None).await.is_err());
        let past = store
            .purge_expired(Utc::now() + chrono::Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(past, 4);
        let r = SessionRecord {
            name: "n".into(),
            groups: vec![],
            created_at: Utc::now(),
            last_seen: Utc::now(),
            id_token: Some("eyJsecret".into()),
        };
        assert!(!format!("{r:?}").contains("eyJsecret"));
    }
}
