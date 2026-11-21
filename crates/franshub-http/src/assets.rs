//! Serving a single-page application embedded with `rust_embed`.

use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine as _;
use rust_embed::RustEmbed;

use crate::{ApiError, Csp};

/// `Cache-Control` of content-hashed assets.
pub const IMMUTABLE: &str = "public, max-age=31536000, immutable";
/// `Cache-Control` of `index.html` and other unhashed files.
pub const NO_CACHE: &str = "no-cache";

/// How [`spa_router`] serves the embedded files.
#[derive(Clone, Debug)]
pub struct SpaConfig {
    /// Where the UI is mounted: `/` or a path such as `/ui` (no trailing slash).
    pub base: String,
    /// Policy sent with every UI response.
    pub csp: Csp,
    /// Files under this prefix carry a content hash in their names and are cached for a year.
    pub immutable_prefix: String,
    /// Text in `index.html` replaced with a fresh per-response nonce that is also added to
    /// `style-src`; `None` for no nonce.
    pub nonce_placeholder: Option<String>,
    /// Paths (relative to `base`) that belong to the API, not the UI: unknown ones answer a JSON
    /// 404 instead of `index.html`.
    pub reserved_prefixes: Vec<String>,
    /// Page served when the build has no `index.html`.
    pub not_built_html: String,
}

impl Default for SpaConfig {
    fn default() -> Self {
        Self {
            base: "/".into(),
            csp: Csp::strict(),
            immutable_prefix: "assets/".into(),
            nonce_placeholder: None,
            reserved_prefixes: vec!["api/".into(), "auth/".into()],
            not_built_html: "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>UI not available</title></head><body><h1>The web UI is not available</h1><p>This binary was built without the web UI.</p></body></html>".into(),
        }
    }
}

/// The content type of a file name.
pub fn content_type(path: &str) -> &'static str {
    let ext = path.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("webmanifest") => "application/manifest+json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("ttf") => "font/ttf",
        Some("txt") => "text/plain; charset=utf-8",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

struct Spa<E> {
    cfg: SpaConfig,
    _assets: PhantomData<fn() -> E>,
}

impl<E: RustEmbed> Spa<E> {
    fn respond(
        &self,
        status: StatusCode,
        ctype: &'static str,
        cache: &'static str,
        csp: &Csp,
        body: Cow<'static, [u8]>,
    ) -> Response {
        let mut r = (status, body).into_response();
        let h = r.headers_mut();
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
        if let Ok(v) = HeaderValue::from_str(&csp.build()) {
            h.insert(header::CONTENT_SECURITY_POLICY, v);
        }
        h.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        h.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        );
        h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
        r
    }

    fn index(&self) -> Response {
        metrics::counter!("ui_requests_total", "kind" => "index").increment(1);
        let Some(f) = E::get("index.html") else {
            return self.respond(
                StatusCode::NOT_FOUND,
                "text/html; charset=utf-8",
                NO_CACHE,
                &self.cfg.csp,
                Cow::Owned(self.cfg.not_built_html.clone().into_bytes()),
            );
        };
        match &self.cfg.nonce_placeholder {
            Some(placeholder) => {
                let nonce = new_nonce();
                let html = String::from_utf8_lossy(&f.data).replace(placeholder, &nonce);
                self.respond(
                    StatusCode::OK,
                    "text/html; charset=utf-8",
                    NO_CACHE,
                    &self.cfg.csp.with_style_nonce(&nonce),
                    Cow::Owned(html.into_bytes()),
                )
            }
            None => self.respond(
                StatusCode::OK,
                "text/html; charset=utf-8",
                NO_CACHE,
                &self.cfg.csp,
                f.data,
            ),
        }
    }

    fn looks_like_file(&self, path: &str) -> bool {
        path.starts_with(&self.cfg.immutable_prefix) || (!path.contains('/') && path.contains('.'))
    }

    fn serve(&self, path: &str) -> Response {
        if path.is_empty() || path == "index.html" {
            return self.index();
        }
        if self
            .cfg
            .reserved_prefixes
            .iter()
            .any(|p| path.starts_with(p.as_str()) || path == p.trim_end_matches('/'))
        {
            return ApiError::not_found("resource").into_response();
        }
        let clean = !path
            .split('/')
            .any(|seg| seg == ".." || seg == "." || seg.is_empty())
            && !path.contains('\\');
        if clean && let Some(f) = E::get(path) {
            metrics::counter!("ui_requests_total", "kind" => "asset").increment(1);
            let cache = if path.starts_with(&self.cfg.immutable_prefix) {
                IMMUTABLE
            } else {
                NO_CACHE
            };
            return self.respond(
                StatusCode::OK,
                content_type(path),
                cache,
                &self.cfg.csp,
                f.data,
            );
        }
        if self.looks_like_file(path) {
            metrics::counter!("ui_requests_total", "kind" => "missing").increment(1);
            return self.respond(
                StatusCode::NOT_FOUND,
                "text/plain; charset=utf-8",
                NO_CACHE,
                &self.cfg.csp,
                Cow::Borrowed(b"not found"),
            );
        }
        self.index()
    }
}

fn new_nonce() -> String {
    let bytes: [u8; 18] = rand::random();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A router serving the embedded single-page application `E` under `cfg.base`: files by path
/// (hashed assets `immutable`, the rest `no-cache`), `index.html` for client-side routes, 404 for
/// missing files and for unknown paths under the reserved API prefixes. Merge it after the API
/// routes; static API routes take precedence over its catch-all.
///
/// ```no_run
/// # use franshub_http::{spa_router, SpaConfig};
/// #[derive(rust_embed::RustEmbed)]
/// #[folder = "ui/dist"]
/// #[allow_missing = true]
/// struct Ui;
///
/// let app: axum::Router = axum::Router::new()
///     .merge(spa_router::<Ui, ()>(SpaConfig::default()));
/// ```
pub fn spa_router<E, S>(cfg: SpaConfig) -> Router<S>
where
    E: RustEmbed + Send + Sync + 'static,
    S: Clone + Send + Sync + 'static,
{
    let base = cfg.base.trim_end_matches('/').to_string();
    let spa = Arc::new(Spa::<E> {
        cfg,
        _assets: PhantomData,
    });
    let index = |State(s): State<Arc<Spa<E>>>| async move { s.index() };
    let file = |State(s): State<Arc<Spa<E>>>, Path(p): Path<String>| async move { s.serve(&p) };
    let r = if base.is_empty() {
        Router::new()
            .route("/", get(index))
            .route("/{*path}", get(file))
    } else {
        Router::new()
            .route(&base, get(index))
            .route(&format!("{base}/"), get(index))
            .route(&format!("{base}/{{*path}}"), get(file))
    };
    r.with_state(spa)
}
