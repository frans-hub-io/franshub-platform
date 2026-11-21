//! Integration tests: SPA serving, uniform errors, security headers, timeouts and TLS serving.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use axum::{Router, middleware};
use franshub_http::{
    ApiError, ApiJson, ClientCertFingerprint, Csp, ErrorBody, IMMUTABLE, NO_CACHE, SecurityHeaders,
    ServeOptions, SpaConfig, TlsFiles, body_limit, request_timeout, security_headers, serve,
    server_config, spa_router,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[derive(rust_embed::RustEmbed)]
#[folder = "tests/fixtures/spa"]
struct Fixture;

#[derive(rust_embed::RustEmbed)]
#[folder = "tests/fixtures/none"]
#[allow_missing = true]
struct Missing;

async fn get_path(app: &Router, path: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let r = app
        .clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = r.status();
    let headers = r.headers().clone();
    let body = r.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn spa_caching_fallback_and_reserved_paths() {
    let cfg = SpaConfig {
        nonce_placeholder: Some("__NONCE__".into()),
        ..SpaConfig::default()
    };
    let app: Router = Router::new()
        .route("/api/v1/ping", get(|| async { "pong" }))
        .merge(spa_router::<Fixture, ()>(cfg));

    let (st, h, body) = get_path(&app, "/").await;
    assert_eq!(st, 200);
    assert_eq!(h[header::CACHE_CONTROL], NO_CACHE);
    let csp = h[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .to_string();
    assert!(!body.contains("__NONCE__"));
    let nonce = body
        .split("nonce=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    assert!(csp.contains(&format!("'nonce-{nonce}'")), "{csp}");
    let (_, _, again) = get_path(&app, "/index.html").await;
    assert!(!again.contains(nonce), "a fresh nonce per response");

    let (st, h, body) = get_path(&app, "/assets/app-3f9c0d5e.js").await;
    assert_eq!(st, 200);
    assert_eq!(h[header::CACHE_CONTROL], IMMUTABLE);
    assert_eq!(h[header::CONTENT_TYPE], "text/javascript; charset=utf-8");
    assert!(body.contains("console.log"));

    let (st, h, _) = get_path(&app, "/favicon.svg").await;
    assert_eq!(st, 200);
    assert_eq!(h[header::CACHE_CONTROL], NO_CACHE);
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");

    let (st, _, body) = get_path(&app, "/launches/42").await;
    assert_eq!(st, 200, "client-side routes get index.html");
    assert!(body.contains("id=\"root\""));

    for missing in ["/assets/gone.js", "/missing.png"] {
        let (st, _, _) = get_path(&app, missing).await;
        assert_eq!(st, 404, "{missing}");
    }
    for traversal in ["/assets/../index.html", "/assets/%2e%2e/Cargo.toml"] {
        let (st, _, body) = get_path(&app, traversal).await;
        assert!(
            st == 404 || (st == 200 && body.contains("id=\"root\"")),
            "{traversal}"
        );
        assert!(!body.contains("[package]"));
    }

    let (st, _, body) = get_path(&app, "/api/v1/ping").await;
    assert_eq!((st, body.as_str()), (StatusCode::OK, "pong"));
    let (st, h, body) = get_path(&app, "/api/v1/unknown").await;
    assert_eq!(st, 404);
    assert_eq!(h[header::CONTENT_TYPE], "application/json");
    let e: ErrorBody = serde_json::from_str(&body).unwrap();
    assert_eq!(e.code, "not_found");
}

#[tokio::test]
async fn spa_under_a_prefix_and_without_a_build() {
    let app: Router = spa_router::<Fixture, ()>(SpaConfig {
        base: "/ui".into(),
        ..SpaConfig::default()
    });
    for p in ["/ui", "/ui/", "/ui/runs"] {
        let (st, _, body) = get_path(&app, p).await;
        assert_eq!(st, 200, "{p}");
        assert!(body.contains("id=\"root\""));
    }
    let (st, _, _) = get_path(&app, "/ui/assets/app-3f9c0d5e.js").await;
    assert_eq!(st, 200);
    let none: Router = spa_router::<Missing, ()>(SpaConfig::default());
    let (st, _, body) = get_path(&none, "/").await;
    assert_eq!(st, 404);
    assert!(body.contains("not available"));
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct Input {
    name: String,
}

async fn echo(ApiJson(i): ApiJson<Input>) -> Result<String, ApiError> {
    if i.name == "boom" {
        return Err(anyhow::anyhow!("store failed: password=hunter2").into());
    }
    Ok(i.name)
}

#[tokio::test]
async fn errors_have_one_shape_and_hide_internal_causes() {
    let app: Router = Router::new()
        .route("/echo", axum::routing::post(echo))
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                "late"
            }),
        )
        .layer(body_limit(64))
        .layer(middleware::from_fn_with_state(
            Duration::from_millis(100),
            request_timeout,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::new(SecurityHeaders::default()),
            security_headers,
        ));
    let post = |body: &str, ct: &str| {
        Request::post("/echo")
            .header(header::CONTENT_TYPE, ct)
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let cases = [
        (post("{", "application/json"), 400, "bad_request"),
        (post("{}", "application/json"), 422, "bad_request"),
        (
            post("{\"name\":\"x\"}", "text/plain"),
            415,
            "unsupported_media_type",
        ),
        (
            post(
                &format!("{{\"name\":\"{}\"}}", "a".repeat(100)),
                "application/json",
            ),
            413,
            "payload_too_large",
        ),
        (
            post("{\"name\":\"boom\"}", "application/json"),
            500,
            "internal",
        ),
        (
            Request::get("/slow").body(Body::empty()).unwrap(),
            503,
            "timeout",
        ),
    ];
    for (req, status, code) in cases {
        let r = app.clone().oneshot(req).await.unwrap();
        assert_eq!(r.status().as_u16(), status, "{code}");
        assert_eq!(r.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(r.headers()[header::X_FRAME_OPTIONS], "DENY");
        assert!(r.headers().contains_key(header::CONTENT_SECURITY_POLICY));
        let body = r.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body);
        assert!(!text.contains("hunter2"), "{text}");
        let e: ErrorBody = serde_json::from_slice(&body).unwrap();
        assert_eq!(e.code, code, "{text}");
    }
    let r = ApiError::unauthorized();
    let resp = axum::response::IntoResponse::into_response(r);
    assert_eq!(resp.headers()[header::WWW_AUTHENTICATE], "Bearer");
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
    assert!(Csp::strict().build().contains("object-src 'none'"));
}

#[tokio::test]
async fn tls_with_client_certificates_and_graceful_shutdown() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = std::env::temp_dir().join(format!("franshub-http-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let srv_key = rcgen::KeyPair::generate().unwrap();
    let srv = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .signed_by(&srv_key, &issuer)
        .unwrap();
    let cli_key = rcgen::KeyPair::generate().unwrap();
    let cli = rcgen::CertificateParams::new(vec!["client.example.com".into()])
        .unwrap()
        .signed_by(&cli_key, &issuer)
        .unwrap();
    std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
    std::fs::write(dir.join("srv.pem"), srv.pem()).unwrap();
    std::fs::write(dir.join("srv.key"), srv_key.serialize_pem()).unwrap();
    let files = TlsFiles {
        cert_file: dir.join("srv.pem"),
        key_file: dir.join("srv.key"),
        client_ca_file: Some(dir.join("ca.pem")),
        client_auth_required: false,
    };
    let cfg = server_config(&files).unwrap();
    let app = Router::new().route(
        "/who",
        get(
            |fp: Option<axum::Extension<ClientCertFingerprint>>| async move {
                fp.map(|f| f.0.0).unwrap_or_else(|| "anonymous".into())
            },
        ),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve(
        l,
        app,
        Some(cfg),
        async {
            let _ = rx.await;
        },
        ServeOptions::default(),
    ));
    let ca_cert = reqwest::Certificate::from_pem(ca.pem().as_bytes()).unwrap();
    let plain = reqwest::Client::builder()
        .add_root_certificate(ca_cert.clone())
        .build()
        .unwrap();
    let url = format!("https://localhost:{port}/who");
    assert_eq!(
        plain.get(&url).send().await.unwrap().text().await.unwrap(),
        "anonymous"
    );
    let identity =
        reqwest::Identity::from_pem(format!("{}{}", cli.pem(), cli_key.serialize_pem()).as_bytes())
            .unwrap();
    let with_cert = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .build()
        .unwrap();
    let fp = with_cert
        .get(&url)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(fp.len(), 64);
    assert!(fp.bytes().all(|b| b.is_ascii_hexdigit()));
    tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();

    let required = server_config(&TlsFiles {
        client_auth_required: true,
        ..files.clone()
    });
    assert!(required.is_ok());
    let bad = server_config(&TlsFiles {
        cert_file: dir.join("missing.pem"),
        ..files
    })
    .unwrap_err();
    assert!(format!("{bad:#}").contains("missing.pem"));
    std::fs::remove_dir_all(&dir).unwrap();
}
