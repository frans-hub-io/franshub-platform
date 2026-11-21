//! Managed tokens, access decisions and OIDC sign-in against the in-memory stores. The same
//! scenarios run against PostgreSQL in `franshub-store-pg`.

mod support;

use support::*;

#[tokio::test]
async fn token_lifecycle_in_memory() {
    token_lifecycle(memory_stores()).await;
}

#[tokio::test]
async fn no_escalation_through_tokens() {
    no_escalation(memory_stores()).await;
}

#[tokio::test]
async fn token_options_follow_the_escalation_rule() {
    token_options(memory_stores()).await;
}

#[tokio::test]
async fn tokens_created_by_tokens_never_outlive_their_parent() {
    children_never_outlive_their_parent(memory_stores()).await;
}

#[tokio::test]
async fn every_authentication_failure_is_the_same_401() {
    uniform_401s(memory_stores()).await;
}

#[tokio::test]
async fn token_values_never_appear_in_logs_audit_or_later_responses() {
    secrets_stay_out_of_logs_audit_and_responses(memory_stores()).await;
}

#[tokio::test]
async fn revocation_reaches_other_replicas_within_the_cache_ttl() {
    revocation_reaches_other_replicas(memory_stores()).await;
}

#[tokio::test]
async fn all_scopes_bindings_and_tokens() {
    let idp = Idp::start().await;
    all_scopes_rules(memory_stores(), &idp).await;
}

#[tokio::test]
async fn oidc_code_flow_session_csrf_and_logout() {
    let idp = Idp::start().await;
    code_flow_session_csrf_and_logout(memory_stores(), &idp).await;
}

#[tokio::test]
async fn oidc_login_rejections() {
    let idp = Idp::start().await;
    login_rejections(memory_stores(), &idp).await;
}

#[tokio::test]
async fn oidc_bearer_jwts() {
    let idp = Idp::start().await;
    bearer_jwts(memory_stores(), &idp).await;
}

#[tokio::test]
async fn oidc_sessions_expire_when_idle_and_after_the_absolute_ttl() {
    let idp = Idp::start().await;
    sessions_expire(memory_stores(), &idp).await;
}

#[tokio::test]
async fn oidc_sessions_are_shared_by_replicas() {
    let idp = Idp::start().await;
    sessions_shared_by_replicas(memory_stores(), &idp).await;
}

#[tokio::test]
async fn the_token_request_follows_no_redirect_and_oidc_off_answers_404() {
    let idp = Idp::start().await;
    let stores = memory_stores();
    let rt = idp.runtime(idp.config(), &stores).await;
    let a = app_with(&stores, Some(rt), std::time::Duration::from_secs(10)).await;
    idp.with(|s| s.redirect_token = true);
    let res = a
        .login(&idp, Some(user("alice", &["team-a-dev"])), "/")
        .await;
    idp.with(|s| s.redirect_token = false);
    assert_eq!(res.location, "/?loginError=failed");
    assert_eq!(idp.with(|s| s.moved_token_requests), 0);
    let off = app(&stores).await;
    let r = off
        .send(Call::new(axum::http::Method::GET, "/auth/login"))
        .await;
    assert_eq!(r.status, 404);
    assert_eq!(r.body["code"], "sso_disabled");
}

#[tokio::test]
async fn insecure_cookies_for_local_http() {
    let idp = Idp::start().await;
    let stores = memory_stores();
    let cfg = franshub_oidc::OidcConfig {
        insecure_cookie: true,
        cookie_name: Some("fastproof".into()),
        ..idp.config()
    };
    let rt = idp.runtime(cfg, &stores).await;
    let a = app_with(&stores, Some(rt), std::time::Duration::from_secs(10)).await;
    let res = a.login(&idp, Some(user("carol", &[])), "/").await;
    let c = cookie_named(&res.cookies, "fastproof_session").unwrap();
    assert!(!c.contains("Secure"), "{c}");
    assert!(res.session.is_some());
}

#[tokio::test]
async fn provider_down_at_start_and_bad_discovery_documents() {
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = closed.local_addr().unwrap();
    drop(closed);
    let stores = memory_stores();
    let cfg = franshub_oidc::OidcConfig {
        issuer: format!("http://{addr}/realms/test"),
        client_id: CLIENT_ID.into(),
        client_secret: Some(CLIENT_SECRET.into()),
        redirect_url: "http://localhost:9/auth/callback".into(),
        ..Default::default()
    };
    let oidc = franshub_oidc::Oidc::new(franshub_oidc::OidcSettings::new(cfg).unwrap()).unwrap();
    let rt = std::sync::Arc::new(franshub_oidc::OidcRuntime::new(
        oidc,
        stores.sessions.clone(),
        policy(),
    ));
    rt.start()
        .await
        .expect("an unreachable provider does not stop the start");
    let a = app_with(&stores, Some(rt), std::time::Duration::from_secs(10)).await;
    let r = a.begin("/").await;
    assert_eq!(r.status, 503);
    assert_eq!(r.body["code"], "unavailable");

    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/realms/test", l.local_addr().unwrap());
    let doc = serde_json::json!({
        "issuer": "https://other.example.com/realms/test",
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
    });
    let evil = serde_json::json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": "https://evil.example.com/token",
        "jwks_uri": format!("{base}/jwks"),
    });
    let docs = std::sync::Arc::new(std::sync::Mutex::new(vec![evil, doc]));
    let d = docs.clone();
    let router = axum::Router::new().route(
        "/realms/test/.well-known/openid-configuration",
        axum::routing::get(move || {
            let d = d.clone();
            async move { axum::Json(d.lock().unwrap().last().cloned().unwrap()) }
        }),
    );
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    for want in [
        "not the configured issuer",
        "neither the issuer host nor an allowed host",
    ] {
        let cfg = franshub_oidc::OidcConfig {
            issuer: base.clone(),
            client_id: CLIENT_ID.into(),
            client_secret: Some(CLIENT_SECRET.into()),
            redirect_url: "http://localhost:9/auth/callback".into(),
            ..Default::default()
        };
        let oidc =
            franshub_oidc::Oidc::new(franshub_oidc::OidcSettings::new(cfg).unwrap()).unwrap();
        let e = format!("{:#}", oidc.start().await.unwrap_err());
        assert!(e.contains(want), "{e}");
        assert!(!e.contains(CLIENT_SECRET));
        docs.lock().unwrap().pop();
    }
}
