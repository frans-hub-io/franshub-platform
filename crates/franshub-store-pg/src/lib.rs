//! PostgreSQL stores for FransHub products: [`TokenStore`], [`SessionStore`] and [`AuditStore`]
//! on one [`PgPlatformStore`].
//!
//! Tables are prefixed `platform_`. Migrations are embedded and tracked in their own table,
//! `platform_schema_migrations`, so they never collide with the product's own sqlx migrations
//! (`_sqlx_migrations`). They are additive only; indexes on existing tables are built with
//! `CREATE INDEX CONCURRENTLY` in separate no-transaction migrations.
//!
//! ```no_run
//! # async fn run() -> anyhow::Result<()> {
//! use std::sync::Arc;
//! use franshub_store_pg::PgPlatformStore;
//!
//! let pool = sqlx::postgres::PgPoolOptions::new()
//!     .max_connections(10)
//!     .connect("postgres://reports@db.example.com/reports")
//!     .await?;
//! franshub_store_pg::migrate(&pool).await?;
//! let store = Arc::new(PgPlatformStore::new(pool));
//! // store implements TokenStore, SessionStore and AuditStore.
//! # Ok(()) }
//! ```

use std::sync::LazyLock;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use franshub_access::{AuditEvent, AuditFilter, AuditPage, AuditStore};
use franshub_auth::{ApiToken, TokenStore};
use franshub_oidc::{PendingLogin, SessionRecord, SessionStore};
use sqlx::migrate::Migrator;
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, QueryBuilder, Row};
use uuid::Uuid;

/// The table that records which platform migrations ran.
pub const MIGRATIONS_TABLE: &str = "platform_schema_migrations";

static MIGRATOR: LazyLock<Migrator> = LazyLock::new(|| {
    let mut m = sqlx::migrate!("./migrations");
    m.dangerous_set_table_name(MIGRATIONS_TABLE);
    m.set_ignore_missing(true);
    m.set_locking(false);
    m
});

/// The embedded platform migrations, tracked in [`MIGRATIONS_TABLE`]. Its own locking is off:
/// run it through [`migrate`], which takes a polled advisory lock, so that replicas starting
/// together never wait on a lock inside a statement while another builds an index concurrently.
pub fn migrator() -> &'static Migrator {
    &MIGRATOR
}

/// Advisory lock key of the platform migrations (distinct from sqlx's per-database key).
const LOCK_KEY: i64 = 0x6672_6e68_7562_706c;

/// A migration applied by [`migrate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedMigration {
    /// Version.
    pub version: i64,
    /// Description from the file name.
    pub name: String,
    /// How long it took.
    pub duration: Duration,
}

async fn applied_versions(conn: &mut sqlx::PgConnection) -> anyhow::Result<Vec<i64>> {
    let present: bool =
        sqlx::query_scalar("select to_regclass('platform_schema_migrations') is not null")
            .fetch_one(&mut *conn)
            .await?;
    if !present {
        return Ok(Vec::new());
    }
    Ok(
        sqlx::query_scalar("select version from platform_schema_migrations where success")
            .fetch_all(&mut *conn)
            .await?,
    )
}

/// Applies pending platform migrations under an advisory lock that is polled rather than waited
/// for, and returns the ones this call applied (each also logged).
pub async fn migrate(pool: &PgPool) -> anyhow::Result<Vec<AppliedMigration>> {
    let mut conn = pool.acquire().await?;
    while !sqlx::query_scalar::<_, bool>("select pg_try_advisory_lock($1)")
        .bind(LOCK_KEY)
        .fetch_one(&mut *conn)
        .await?
    {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let result = async {
        let before = applied_versions(&mut conn).await?;
        MIGRATOR.run_direct(None, &mut *conn, false).await?;
        let rows: Vec<(i64, String, i64)> = sqlx::query_as(
            "select version, description, execution_time from platform_schema_migrations where success order by version",
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok::<_, anyhow::Error>(
            rows.into_iter()
                .filter(|(v, _, _)| !before.contains(v))
                .map(|(version, name, nanos)| AppliedMigration {
                    version,
                    name,
                    duration: Duration::from_nanos(nanos.max(0) as u64),
                })
                .collect::<Vec<_>>(),
        )
    }
    .await;
    let unlocked = sqlx::query("select pg_advisory_unlock($1)")
        .bind(LOCK_KEY)
        .execute(&mut *conn)
        .await;
    let applied = result?;
    unlocked?;
    for m in &applied {
        tracing::info!(
            version = m.version,
            name = %m.name,
            duration_ms = m.duration.as_millis() as u64,
            "applied platform migration"
        );
    }
    Ok(applied)
}

/// Checks that every embedded migration ran unchanged, for servers started without migrating.
pub async fn check_schema(pool: &PgPool) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    let applied = applied_versions(&mut conn).await?;
    let missing: Vec<String> = MIGRATOR
        .iter()
        .filter(|m| !m.migration_type.is_down_migration() && !applied.contains(&m.version))
        .map(|m| format!("{} ({})", m.version, m.description))
        .collect();
    if !missing.is_empty() {
        anyhow::bail!(
            "platform migration(s) {} not applied: run the migrations first",
            missing.join(", ")
        );
    }
    let rows: Vec<(i64, Vec<u8>)> =
        sqlx::query_as("select version, checksum from platform_schema_migrations")
            .fetch_all(&mut *conn)
            .await?;
    for (v, sum) in rows {
        if let Some(m) = MIGRATOR.iter().find(|m| m.version == v)
            && sum.as_slice() != &*m.checksum
        {
            anyhow::bail!(
                "platform migration {v} ({}) differs from the one built into this version: applied migrations must never be edited",
                m.description
            );
        }
    }
    Ok(())
}

fn no_nul(s: &str) -> String {
    if s.contains('\0') {
        s.replace('\0', "\u{FFFD}")
    } else {
        s.to_string()
    }
}

/// Managed tokens, sessions and audit records in PostgreSQL.
#[derive(Clone, Debug)]
pub struct PgPlatformStore {
    pool: PgPool,
}

impl PgPlatformStore {
    /// A store on a pool; run [`migrate`] first.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

macro_rules! token_columns {
    () => {
        "id, name, sha256, role, scopes, global, description, created_by, created_at, expires_at, last_used_at, revoked_at, revoked, parent_id"
    };
}

fn row_to_token(r: &PgRow) -> anyhow::Result<ApiToken> {
    Ok(ApiToken {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        sha256: r.try_get("sha256")?,
        role: r.try_get("role")?,
        scopes: r.try_get("scopes")?,
        global: r.try_get("global")?,
        description: r.try_get("description")?,
        created_by: r.try_get("created_by")?,
        created_at: r.try_get("created_at")?,
        expires_at: r.try_get("expires_at")?,
        last_used_at: r.try_get("last_used_at")?,
        revoked_at: r.try_get("revoked_at")?,
        revoked: r.try_get("revoked")?,
        parent_id: r.try_get("parent_id")?,
    })
}

#[async_trait]
impl TokenStore for PgPlatformStore {
    async fn create(&self, t: &ApiToken, now: DateTime<Utc>) -> anyhow::Result<bool> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("update platform_api_tokens set revoked_at = expires_at where name = $1 and revoked_at is null and expires_at <= $2")
            .bind(&t.name)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        let inserted = sqlx::query(concat!(
            "insert into platform_api_tokens (",
            token_columns!(),
            ") values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) on conflict (name) where revoked_at is null do nothing"
        ))
        .bind(t.id)
        .bind(no_nul(&t.name))
        .bind(&t.sha256)
        .bind(&t.role)
        .bind(&t.scopes)
        .bind(t.global)
        .bind(t.description.as_deref().map(no_nul))
        .bind(no_nul(&t.created_by))
        .bind(t.created_at)
        .bind(t.expires_at)
        .bind(t.last_used_at)
        .bind(t.revoked_at)
        .bind(t.revoked)
        .bind(t.parent_id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        tx.commit().await?;
        Ok(inserted)
    }

    async fn get(&self, id: Uuid) -> anyhow::Result<Option<ApiToken>> {
        let r = sqlx::query(concat!(
            "select ",
            token_columns!(),
            " from platform_api_tokens where id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        r.as_ref().map(row_to_token).transpose()
    }

    async fn by_hash(&self, sha256: &str) -> anyhow::Result<Option<ApiToken>> {
        let r = sqlx::query(concat!(
            "select ",
            token_columns!(),
            " from platform_api_tokens where sha256 = $1"
        ))
        .bind(sha256)
        .fetch_optional(&self.pool)
        .await?;
        r.as_ref().map(row_to_token).transpose()
    }

    async fn list(&self) -> anyhow::Result<Vec<ApiToken>> {
        let rows = sqlx::query(concat!(
            "select ",
            token_columns!(),
            " from platform_api_tokens order by created_at desc, id desc limit 10000"
        ))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_token).collect()
    }

    async fn revoke(&self, id: Uuid, at: DateTime<Utc>) -> anyhow::Result<bool> {
        Ok(sqlx::query(
            "update platform_api_tokens set revoked = true, revoked_at = $2 where id = $1 and revoked_at is null and expires_at > $2",
        )
        .bind(id)
        .bind(at)
        .execute(&self.pool)
        .await?
        .rows_affected()
            == 1)
    }

    async fn has_any(&self) -> anyhow::Result<bool> {
        Ok(
            sqlx::query_scalar("select exists (select 1 from platform_api_tokens)")
                .fetch_one(&self.pool)
                .await?,
        )
    }

    async fn touch(&self, id: Uuid, at: DateTime<Utc>) -> anyhow::Result<()> {
        sqlx::query("update platform_api_tokens set last_used_at = $2 where id = $1 and (last_used_at is null or last_used_at <= $2 - interval '1 minute')")
            .bind(id)
            .bind(at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn count_active(&self, now: DateTime<Utc>) -> anyhow::Result<i64> {
        Ok(sqlx::query_scalar(
            "select count(*) from platform_api_tokens where not revoked and expires_at > $1",
        )
        .bind(now)
        .fetch_one(&self.pool)
        .await?)
    }

    async fn purge_inactive_before(&self, at: DateTime<Utc>) -> anyhow::Result<u64> {
        Ok(
            sqlx::query("delete from platform_api_tokens where revoked_at < $1 or expires_at < $1")
                .bind(at)
                .execute(&self.pool)
                .await?
                .rows_affected(),
        )
    }
}

fn row_to_session(r: &PgRow) -> anyhow::Result<SessionRecord> {
    Ok(SessionRecord {
        name: r.try_get("name")?,
        groups: r.try_get("groups")?,
        created_at: r.try_get("created_at")?,
        last_seen: r.try_get("last_seen")?,
        id_token: r.try_get("id_token")?,
    })
}

#[async_trait]
impl SessionStore for PgPlatformStore {
    async fn create_session(
        &self,
        key: &str,
        r: &SessionRecord,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        sqlx::query("insert into platform_sessions (key, name, groups, created_at, last_seen, expires_at, id_token) values ($1, $2, $3, $4, $5, $6, $7)")
            .bind(key)
            .bind(no_nul(&r.name))
            .bind(r.groups.iter().map(|g| no_nul(g)).collect::<Vec<_>>())
            .bind(r.created_at)
            .bind(r.last_seen)
            .bind(expires_at)
            .bind(r.id_token.as_deref().map(no_nul))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn session(&self, key: &str) -> anyhow::Result<Option<SessionRecord>> {
        let r = sqlx::query("select name, groups, created_at, last_seen, id_token from platform_sessions where key = $1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        r.as_ref().map(row_to_session).transpose()
    }

    async fn touch_session(
        &self,
        key: &str,
        last_seen: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        sqlx::query("update platform_sessions set last_seen = greatest(last_seen, $2), expires_at = greatest(expires_at, $3) where key = $1")
            .bind(key)
            .bind(last_seen)
            .bind(expires_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_session(&self, key: &str) -> anyhow::Result<Option<SessionRecord>> {
        let r = sqlx::query("delete from platform_sessions where key = $1 returning name, groups, created_at, last_seen, id_token")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        r.as_ref().map(row_to_session).transpose()
    }

    async fn put_login(
        &self,
        key: &str,
        p: &PendingLogin,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        sqlx::query("insert into platform_pending_logins (key, nonce, verifier, return_to, browser, expires_at) values ($1, $2, $3, $4, $5, $6)")
            .bind(key)
            .bind(&p.nonce)
            .bind(&p.verifier)
            .bind(no_nul(&p.return_to))
            .bind(&p.browser)
            .bind(expires_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn take_login(
        &self,
        key: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Option<PendingLogin>> {
        let r = sqlx::query("delete from platform_pending_logins where key = $1 returning nonce, verifier, return_to, browser, expires_at")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        let Some(r) = r else { return Ok(None) };
        let expires_at: DateTime<Utc> = r.try_get("expires_at")?;
        if expires_at <= now {
            return Ok(None);
        }
        Ok(Some(PendingLogin {
            nonce: r.try_get("nonce")?,
            verifier: r.try_get("verifier")?,
            return_to: r.try_get("return_to")?,
            browser: r.try_get("browser")?,
        }))
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> anyhow::Result<u64> {
        let a = sqlx::query("delete from platform_sessions where expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await?
            .rows_affected();
        let b = sqlx::query("delete from platform_pending_logins where expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(a + b)
    }
}

fn row_to_audit(r: &PgRow) -> anyhow::Result<AuditEvent> {
    Ok(AuditEvent {
        id: r.try_get("id")?,
        at: r.try_get("at")?,
        principal: r.try_get("principal")?,
        principal_kind: r.try_get("principal_kind")?,
        roles: r.try_get("roles")?,
        scope: r.try_get("scope")?,
        action: r.try_get("action")?,
        detail: r.try_get("detail")?,
    })
}

fn like_prefix(p: &str) -> String {
    let mut out = String::with_capacity(p.len() + 1);
    for c in p.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

#[async_trait]
impl AuditStore for PgPlatformStore {
    async fn append(&self, e: &AuditEvent) -> anyhow::Result<i64> {
        Ok(sqlx::query_scalar("insert into platform_audit (at, principal, principal_kind, roles, scope, action, detail) values ($1, $2, $3, $4, $5, $6, $7) returning id")
            .bind(e.at)
            .bind(no_nul(&e.principal))
            .bind(&e.principal_kind)
            .bind(no_nul(&e.roles))
            .bind(e.scope.as_deref().map(no_nul))
            .bind(no_nul(&e.action))
            .bind(&e.detail)
            .fetch_one(&self.pool)
            .await?)
    }

    async fn query(&self, f: &AuditFilter) -> anyhow::Result<AuditPage> {
        let size = f.page_size();
        let mut qb = QueryBuilder::<Postgres>::new(
            "select id, at, principal, principal_kind, roles, scope, action, detail from platform_audit where true",
        );
        match (f.action_prefix(), &f.action) {
            (Some(p), _) => {
                qb.push(" and action like ").push_bind(like_prefix(p));
            }
            (None, Some(a)) => {
                qb.push(" and action = ").push_bind(a.clone());
            }
            (None, None) => {}
        }
        if let Some(p) = &f.principal {
            qb.push(" and principal = ").push_bind(p.clone());
        }
        if let Some(s) = &f.scope {
            qb.push(" and scope = ").push_bind(s.clone());
        }
        if let Some(s) = f.since {
            qb.push(" and at >= ").push_bind(s);
        }
        if let Some(u) = f.until {
            qb.push(" and at < ").push_bind(u);
        }
        if let Some(b) = f.before {
            qb.push(" and id < ").push_bind(b);
        }
        qb.push(" order by id desc limit ")
            .push_bind(i64::from(size) + 1);
        let rows = qb.build().fetch_all(&self.pool).await?;
        let events = rows
            .iter()
            .map(row_to_audit)
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(AuditPage::from_rows(events, size))
    }

    async fn purge_older_than(&self, at: DateTime<Utc>) -> anyhow::Result<u64> {
        Ok(sqlx::query("delete from platform_audit where at < $1")
            .bind(at)
            .execute(&self.pool)
            .await?
            .rows_affected())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn like_prefixes_are_escaped() {
        assert_eq!(super::like_prefix("token."), "token.%");
        assert_eq!(super::like_prefix("a_b%c\\"), "a\\_b\\%c\\\\%");
    }

    #[test]
    fn migrations_are_tracked_in_their_own_table() {
        let m = super::migrator();
        assert_eq!(m.table_name, super::MIGRATIONS_TABLE);
        assert!(!m.locking);
        let no_tx: Vec<i64> = m.iter().filter(|x| x.no_tx).map(|x| x.version).collect();
        assert_eq!(no_tx, (4..=11).collect::<Vec<_>>());
        for x in m.iter() {
            let sql = x.sql.as_str().to_ascii_lowercase();
            assert!(!sql.contains("select *"), "{}", x.version);
            assert!(
                !sql.contains("drop "),
                "{}: migrations are additive",
                x.version
            );
            if sql.contains("create index") && x.version > 3 {
                assert!(x.no_tx && sql.contains("concurrently"), "{}", x.version);
            }
        }
    }
}
