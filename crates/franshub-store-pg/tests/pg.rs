//! PostgreSQL tests: migrations, the three stores, and the platform scenarios on PostgreSQL.
//! They need `FRANSHUB_TEST_DATABASE_URL` (a role that may create databases); without it they
//! pass without doing anything. Each test creates its own `platform_test_*` database and drops
//! it afterwards, also when the test fails.

#[path = "../../franshub-auth/tests/support/mod.rs"]
mod support;

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use franshub_access::{AuditEvent, AuditFilter};
use franshub_oidc::{PendingLogin, SessionRecord};
use franshub_store_pg::{PgPlatformStore, check_schema, migrate};
use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, PgPool};
use support::Stores;

struct TestDb {
    admin: PgConnectOptions,
    name: String,
    pool: PgPool,
}

impl TestDb {
    async fn new() -> Option<Self> {
        let Ok(url) = std::env::var("FRANSHUB_TEST_DATABASE_URL") else {
            eprintln!("FRANSHUB_TEST_DATABASE_URL is not set: skipped");
            return None;
        };
        let admin: PgConnectOptions = url.parse().expect("FRANSHUB_TEST_DATABASE_URL");
        let name = format!("platform_test_{:016x}", rand::random::<u64>());
        let mut conn = admin
            .connect()
            .await
            .expect("connecting to the test server");
        sqlx::query(sqlx::AssertSqlSafe(format!("create database {name}")))
            .execute(&mut conn)
            .await
            .unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(admin.clone().database(&name))
            .await
            .unwrap();
        Some(Self { admin, name, pool })
    }

    async fn migrated() -> Option<(Self, Stores)> {
        let db = Self::new().await?;
        migrate(&db.pool).await.unwrap();
        let store = Arc::new(PgPlatformStore::new(db.pool.clone()));
        let stores = Stores {
            tokens: store.clone(),
            sessions: store.clone(),
            audit: store,
        };
        Some((db, stores))
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let admin = self.admin.clone();
        let name = self.name.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Ok(mut c) = admin.connect().await {
                    let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
                        "drop database if exists {name} with (force)"
                    )))
                    .execute(&mut c)
                    .await;
                }
            });
        })
        .join()
        .unwrap();
    }
}

#[tokio::test]
async fn migrations_run_once_under_a_lock_in_their_own_table() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let (a, b) = tokio::join!(migrate(&db.pool), migrate(&db.pool));
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(
        a.len() + b.len(),
        11,
        "every migration applied exactly once"
    );
    assert!(migrate(&db.pool).await.unwrap().is_empty());
    check_schema(&db.pool).await.unwrap();
    let sqlx_table: bool = sqlx::query_scalar("select to_regclass('_sqlx_migrations') is not null")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(
        !sqlx_table,
        "the product's own migrations table stays untouched"
    );
    let tables: Vec<String> = sqlx::query_scalar(
        "select tablename::text from pg_tables where schemaname = 'public' order by tablename",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert_eq!(
        tables,
        [
            "platform_api_tokens",
            "platform_audit",
            "platform_pending_logins",
            "platform_schema_migrations",
            "platform_sessions"
        ]
    );
    let invalid: i64 = sqlx::query_scalar("select count(*) from pg_index where not indisvalid")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(invalid, 0);
    let indexes: i64 = sqlx::query_scalar(
        "select count(*) from pg_indexes where schemaname = 'public' and indexname like 'platform_%'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert!(indexes >= 10, "{indexes}");
    sqlx::query("update platform_schema_migrations set checksum = '\\x00' where version = 3")
        .execute(&db.pool)
        .await
        .unwrap();
    let e = check_schema(&db.pool).await.unwrap_err().to_string();
    assert!(e.contains("must never be edited"), "{e}");
}

#[tokio::test]
async fn sessions_and_pending_logins() {
    let Some((_db, stores)) = TestDb::migrated().await else {
        return;
    };
    let s = stores.sessions.as_ref();
    let now = Utc::now();
    let r = SessionRecord {
        name: "alice".into(),
        groups: vec!["qa".into(), "team-a-dev".into()],
        created_at: franshub_auth::stored_precision(now),
        last_seen: franshub_auth::stored_precision(now),
        id_token: Some("eyJ.header.sig".into()),
    };
    s.create_session("k1", &r, now + chrono::Duration::hours(1))
        .await
        .unwrap();
    assert_eq!(s.session("k1").await.unwrap(), Some(r.clone()));
    let later = franshub_auth::stored_precision(now + chrono::Duration::minutes(5));
    s.touch_session("k1", later, now + chrono::Duration::hours(2))
        .await
        .unwrap();
    s.touch_session("k1", now, now).await.unwrap();
    assert_eq!(
        s.session("k1").await.unwrap().unwrap().last_seen,
        later,
        "only forward"
    );
    let deleted = s.delete_session("k1").await.unwrap().unwrap();
    assert_eq!((deleted.name.as_str(), deleted.last_seen), ("alice", later));
    assert_eq!(deleted.id_token, r.id_token);
    assert!(s.delete_session("k1").await.unwrap().is_none());

    let p = PendingLogin {
        nonce: "n".into(),
        verifier: "v".into(),
        return_to: "/launches".into(),
        browser: "b".into(),
    };
    s.put_login("st", &p, now + chrono::Duration::minutes(10))
        .await
        .unwrap();
    let (x, y) = tokio::join!(s.take_login("st", now), s.take_login("st", now));
    assert_eq!(
        [x.unwrap(), y.unwrap()]
            .iter()
            .filter(|v| v.is_some())
            .count(),
        1,
        "a pending login is taken once"
    );
    s.put_login("old", &p, now - chrono::Duration::seconds(1))
        .await
        .unwrap();
    assert!(s.take_login("old", now).await.unwrap().is_none());
    s.put_login("gone", &p, now - chrono::Duration::seconds(1))
        .await
        .unwrap();
    s.create_session(
        "expired",
        &SessionRecord {
            name: "x".into(),
            groups: vec![],
            created_at: now,
            last_seen: now,
            id_token: None,
        },
        now - chrono::Duration::seconds(1),
    )
    .await
    .unwrap();
    assert_eq!(s.purge_expired(now).await.unwrap(), 2);
}

#[tokio::test]
async fn audit_filters_and_pages() {
    let Some((_db, stores)) = TestDb::migrated().await else {
        return;
    };
    let a = stores.audit.as_ref();
    for i in 0..30 {
        let action = match i % 3 {
            0 => "token.create",
            1 => "token_x.other",
            _ => "auth.login",
        };
        let mut e = AuditEvent::anonymous(
            &format!("p{}", i % 2),
            Some("user"),
            action,
            json!({"i": i}),
        );
        e.scope = (i % 5 == 0).then(|| "team-a".to_string());
        e.at = Utc::now() - chrono::Duration::minutes(60 - i);
        assert!(a.append(&e).await.unwrap() > 0);
    }
    let page = |f: AuditFilter| async move { a.query(&f).await.unwrap() };
    let first = page(AuditFilter {
        limit: Some(7),
        ..Default::default()
    })
    .await;
    assert_eq!(first.events.len(), 7);
    let mut seen = first.events.len();
    let mut before = first.next_before;
    while let Some(b) = before {
        let p = page(AuditFilter {
            limit: Some(7),
            before: Some(b),
            ..Default::default()
        })
        .await;
        assert!(p.events.iter().all(|e| e.id < b));
        seen += p.events.len();
        before = p.next_before;
    }
    assert_eq!(seen, 30);
    let tokens = page(AuditFilter {
        action: Some("token.*".into()),
        limit: Some(100),
        ..Default::default()
    })
    .await;
    assert_eq!(tokens.events.len(), 10, "`_` in a prefix is literal");
    let exact = page(AuditFilter {
        action: Some("auth.login".into()),
        principal: Some("p1".into()),
        ..Default::default()
    })
    .await;
    assert!(
        exact
            .events
            .iter()
            .all(|e| e.action == "auth.login" && e.principal == "p1")
    );
    let scoped = page(AuditFilter {
        scope: Some("team-a".into()),
        ..Default::default()
    })
    .await;
    assert_eq!(scoped.events.len(), 6);
    let window = page(AuditFilter {
        since: Some(Utc::now() - chrono::Duration::minutes(40)),
        until: Some(Utc::now() - chrono::Duration::minutes(35)),
        ..Default::default()
    })
    .await;
    assert_eq!(window.events.len(), 5);
    assert_eq!(
        a.purge_older_than(
            Utc::now() - chrono::Duration::minutes(45) - chrono::Duration::seconds(30)
        )
        .await
        .unwrap(),
        15
    );
}

macro_rules! pg_scenario {
    ($name:ident, $f:path) => {
        #[tokio::test]
        async fn $name() {
            let Some((_db, stores)) = TestDb::migrated().await else {
                return;
            };
            $f(stores).await;
        }
    };
    ($name:ident, $f:path, idp) => {
        #[tokio::test]
        async fn $name() {
            let Some((_db, stores)) = TestDb::migrated().await else {
                return;
            };
            let idp = support::Idp::start().await;
            $f(stores, &idp).await;
        }
    };
}

pg_scenario!(pg_token_lifecycle, support::token_lifecycle);
pg_scenario!(pg_no_escalation, support::no_escalation);
pg_scenario!(pg_token_options, support::token_options);
pg_scenario!(pg_children, support::children_never_outlive_their_parent);
pg_scenario!(pg_uniform_401s, support::uniform_401s);
pg_scenario!(
    pg_secrets,
    support::secrets_stay_out_of_logs_audit_and_responses
);
pg_scenario!(
    pg_revocation_across_replicas,
    support::revocation_reaches_other_replicas
);
pg_scenario!(pg_all_scopes, support::all_scopes_rules, idp);
pg_scenario!(
    pg_code_flow,
    support::code_flow_session_csrf_and_logout,
    idp
);
pg_scenario!(pg_login_rejections, support::login_rejections, idp);
pg_scenario!(pg_sessions_expire, support::sessions_expire, idp);
pg_scenario!(
    pg_sessions_shared_by_replicas,
    support::sessions_shared_by_replicas,
    idp
);

#[tokio::test]
async fn token_times_round_trip_at_stored_precision() {
    let Some((_db, stores)) = TestDb::migrated().await else {
        return;
    };
    let a = support::app(&stores).await;
    let created = a
        .create_token(
            support::ADMIN,
            json!({"name": "t", "role": "viewer", "global": true}),
        )
        .await;
    let id = created.body["id"].as_str().unwrap().to_string();
    let read = a.get(&format!("/api/v1/tokens/{id}"), support::ADMIN).await;
    assert_eq!(created.body["createdAt"], read.body["createdAt"]);
    assert_eq!(created.body["expiresAt"], read.body["expiresAt"]);
    let v = created.body["token"].as_str().unwrap().to_string();
    assert_eq!(a.get("/api/v1/me", &v).await.status, 200);
    let mut used = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if a.get(&format!("/api/v1/tokens/{id}"), support::ADMIN)
            .await
            .body["lastUsedAt"]
            .is_string()
        {
            used = true;
            break;
        }
    }
    assert!(used, "the last use is recorded");
}

/// Drops `platform_test_*` databases left behind by interrupted runs. Run alone:
/// `cargo test -p franshub-store-pg --test pg -- --ignored drop_leftover_test_databases`.
#[tokio::test]
#[ignore]
async fn drop_leftover_test_databases() {
    let Ok(url) = std::env::var("FRANSHUB_TEST_DATABASE_URL") else {
        return;
    };
    let admin: PgConnectOptions = url.parse().unwrap();
    let mut conn = admin.connect().await.unwrap();
    let names: Vec<String> = sqlx::query_scalar(
        "select datname::text from pg_database where datname like 'platform\\_test\\_%'",
    )
    .fetch_all(&mut conn)
    .await
    .unwrap();
    for n in names {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "drop database if exists {n} with (force)"
        )))
        .execute(&mut conn)
        .await
        .unwrap();
    }
}
