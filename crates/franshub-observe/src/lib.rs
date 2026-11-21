//! Observability for FransHub products: tracing (JSON or text) with optional OTLP export of traces
//! and logs, a Prometheus recorder, HTTP metrics and request-id middleware, and W3C
//! `traceparent` helpers.
//!
//! ```no_run
//! use axum::{Router, middleware, routing::get};
//! use franshub_observe::{LogFormat, TelemetryConfig, http_metrics, init, metrics_router, request_id};
//!
//! # fn main() -> anyhow::Result<()> {
//! let telemetry = init(TelemetryConfig::new("fastproof", LogFormat::Json))?;
//! let app: Router = Router::new()
//!     .route("/api/v1/ping", get(|| async { "pong" }))
//!     .layer(middleware::from_fn(http_metrics))
//!     .layer(middleware::from_fn(request_id))
//!     .merge(metrics_router(telemetry.prometheus.clone()));
//! # Ok(()) }
//! ```

use std::collections::HashMap;
use std::time::Instant;

use axum::Router;
use axum::extract::{MatchedPath, Request};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use opentelemetry::propagation::{Extractor, Injector};
use opentelemetry::trace::{TraceContextExt, TracerProvider as _};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// Request and response header carrying the request id.
pub const REQUEST_ID_HEADER: &str = "x-request-id";
const MAX_REQUEST_ID: usize = 128;

/// Log line format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    /// One JSON object per line.
    Json,
    /// Human-readable text.
    Text,
}

impl std::str::FromStr for LogFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(LogFormat::Json),
            "text" | "plain" => Ok(LogFormat::Text),
            other => Err(format!("unknown log format `{other}`: use json or text")),
        }
    }
}

/// Settings of [`init`].
#[derive(Clone, Debug)]
pub struct TelemetryConfig {
    /// `service.name` of exported traces and logs (overridden by `OTEL_SERVICE_NAME`).
    pub service_name: String,
    /// Log line format.
    pub log_format: LogFormat,
    /// Filter used when `RUST_LOG` is not set.
    pub default_filter: String,
    /// OTLP export: `None` turns it on when an `OTEL_EXPORTER_OTLP_*ENDPOINT` variable is set and
    /// `OTEL_SDK_DISABLED` is not `true`; `Some(false)` keeps it off.
    pub otlp: Option<bool>,
    /// Name of the `build_info` gauge (set to 1 with a `version` label); `None` for no gauge.
    pub build_info: Option<(String, String)>,
}

impl TelemetryConfig {
    /// Defaults for a service: `info` with noisy dependencies at `warn`, OTLP from the environment.
    pub fn new(service_name: &str, log_format: LogFormat) -> Self {
        Self {
            service_name: service_name.to_string(),
            log_format,
            default_filter: "info,sqlx=warn,hyper=warn,h2=warn,reqwest=warn,opentelemetry=warn"
                .into(),
            otlp: None,
            build_info: None,
        }
    }
}

/// Handles returned by [`init`].
pub struct Telemetry {
    /// Renders the Prometheus text format.
    pub prometheus: PrometheusHandle,
    /// Traces and logs are exported over OTLP.
    pub otel_enabled: bool,
    tracer: Option<SdkTracerProvider>,
    logger: Option<SdkLoggerProvider>,
}

impl std::fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Telemetry")
            .field("otel_enabled", &self.otel_enabled)
            .finish()
    }
}

impl Telemetry {
    /// Flushes and stops the OTLP exporters.
    pub fn shutdown(&self) {
        if let Some(t) = &self.tracer {
            let _ = t.shutdown();
        }
        if let Some(l) = &self.logger {
            let _ = l.shutdown();
        }
    }
}

fn otel_requested() -> bool {
    let disabled = std::env::var("OTEL_SDK_DISABLED")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    !disabled
        && [
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
        ]
        .iter()
        .any(|k| std::env::var(k).map(|v| !v.is_empty()).unwrap_or(false))
}

/// A Prometheus recorder builder with latency buckets for every `_seconds` histogram.
pub fn prometheus_builder() -> anyhow::Result<PrometheusBuilder> {
    let buckets = [
        0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
        300.0,
    ];
    Ok(PrometheusBuilder::new()
        .set_buckets_for_metric(Matcher::Suffix("_seconds".into()), &buckets)?)
}

/// Installs the global Prometheus recorder; once per process.
pub fn install_prometheus() -> anyhow::Result<PrometheusHandle> {
    Ok(prometheus_builder()?.install_recorder()?)
}

/// Installs the Prometheus recorder and the global tracing subscriber (JSON or text logs, plus
/// OTLP traces and logs when requested). Once per process.
pub fn init(cfg: TelemetryConfig) -> anyhow::Result<Telemetry> {
    let prometheus = install_prometheus()?;
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
    let default_filter = cfg.default_filter.clone();
    let filter = move || {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&default_filter))
    };
    let fmt_layer = match cfg.log_format {
        LogFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(false)
            .with_filter(filter())
            .boxed(),
        LogFormat::Text => tracing_subscriber::fmt::layer()
            .with_filter(filter())
            .boxed(),
    };
    let (tracer, logger) = if cfg.otlp.unwrap_or_else(otel_requested) {
        let resource = Resource::builder()
            .with_service_name(
                std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| cfg.service_name.clone()),
            )
            .build();
        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .build()?;
        let tracer = SdkTracerProvider::builder()
            .with_batch_exporter(span_exporter)
            .with_resource(resource.clone())
            .build();
        let log_exporter = opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .build()?;
        let logger = SdkLoggerProvider::builder()
            .with_batch_exporter(log_exporter)
            .with_resource(resource)
            .build();
        opentelemetry::global::set_tracer_provider(tracer.clone());
        (Some(tracer), Some(logger))
    } else {
        (None, None)
    };
    let service = cfg.service_name.clone();
    let otel_trace_layer = tracer.as_ref().map(|t| {
        tracing_opentelemetry::layer()
            .with_tracer(t.tracer(service))
            .with_filter(filter())
    });
    let otel_log_layer = logger.as_ref().map(|l| {
        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(l)
            .with_filter(filter())
    });
    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(otel_trace_layer)
        .with(otel_log_layer)
        .try_init()?;
    if let Some((name, version)) = cfg.build_info {
        metrics::gauge!(name, "version" => version).set(1.0);
    }
    Ok(Telemetry {
        prometheus,
        otel_enabled: tracer.is_some(),
        tracer,
        logger,
    })
}

/// A router answering `GET /metrics` with the Prometheus text format. Mount it on a listener
/// that is not public, or protect it.
pub fn metrics_router<S: Clone + Send + Sync + 'static>(handle: PrometheusHandle) -> Router<S> {
    Router::new().route(
        "/metrics",
        get(move || {
            let h = handle.clone();
            async move {
                (
                    [(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("text/plain; version=0.0.4"),
                    )],
                    h.render(),
                )
                    .into_response()
            }
        }),
    )
}

/// Middleware recording `http_requests_total{method, route, status}` and
/// `http_request_duration_seconds{method, route}`. `route` is the matched route template (such
/// as `/api/v1/tokens/{id}`) or `unmatched`, so label cardinality stays bounded.
pub async fn http_metrics(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = method_label(req.method());
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "unmatched".into());
    let resp = next.run(req).await;
    let status = resp.status().as_u16().to_string();
    metrics::counter!("http_requests_total", "method" => method, "route" => route.clone(), "status" => status)
        .increment(1);
    metrics::histogram!("http_request_duration_seconds", "method" => method, "route" => route)
        .record(start.elapsed().as_secs_f64());
    resp
}

fn method_label(m: &axum::http::Method) -> &'static str {
    match m.as_str() {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "DELETE" => "DELETE",
        "OPTIONS" => "OPTIONS",
        _ => "OTHER",
    }
}

/// The id of the current request, a request extension set by [`request_id`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestId(pub String);

fn valid_request_id(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_REQUEST_ID
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

/// Middleware giving every request an id: the incoming `X-Request-Id` when it is at most 128
/// characters of `[A-Za-z0-9._:-]`, otherwise a new UUIDv7. The id is a [`RequestId`]
/// extension, the `X-Request-Id` response header and a field of the `http_request` span, whose
/// parent is the incoming `traceparent` when OTLP is on.
pub async fn request_id(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| valid_request_id(v))
        .map(String::from)
        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
    let span = tracing::info_span!(
        "http_request",
        request_id = %id,
        method = %req.method(),
        path = %req.uri().path(),
    );
    attach_parent(&span, req.headers());
    req.extensions_mut().insert(RequestId(id.clone()));
    let mut resp = next.run(req).instrument(span).await;
    if let Ok(v) = HeaderValue::from_str(&id) {
        resp.headers_mut().insert(REQUEST_ID_HEADER, v);
    }
    resp
}

/// A W3C trace context: the ids of a `traceparent` header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceContext {
    /// 32 lowercase hex digits, not all zero.
    pub trace_id: String,
    /// 16 lowercase hex digits, not all zero.
    pub span_id: String,
    /// The sampled flag.
    pub sampled: bool,
}

fn random_hex(bytes: usize) -> String {
    loop {
        let v: Vec<u8> = (0..bytes).map(|_| rand::random::<u8>()).collect();
        if v.iter().any(|b| *b != 0) {
            return hex::encode(v);
        }
    }
}

impl TraceContext {
    /// A new trace with a random trace id and span id, sampled.
    pub fn new_root() -> Self {
        Self {
            trace_id: random_hex(16),
            span_id: random_hex(8),
            sampled: true,
        }
    }

    /// A child: same trace, new span id.
    pub fn child(&self) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            span_id: random_hex(8),
            sampled: self.sampled,
        }
    }

    /// The `traceparent` header value (version 00).
    pub fn traceparent(&self) -> String {
        format!(
            "00-{}-{}-{}",
            self.trace_id,
            self.span_id,
            if self.sampled { "01" } else { "00" }
        )
    }
}

/// Parses a `traceparent` header value; `None` when it is invalid (version `ff`, upper case hex,
/// all-zero ids, wrong lengths).
pub fn parse_traceparent(tp: &str) -> Option<TraceContext> {
    let parts: Vec<&str> = tp.trim().split('-').collect();
    if parts.len() < 4 || parts[0].len() != 2 || parts[0] == "ff" {
        return None;
    }
    if parts[0] == "00" && parts.len() != 4 {
        return None;
    }
    let lower_hex = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let id_ok = |s: &str, n: usize| s.len() == n && lower_hex(s) && s.bytes().any(|b| b != b'0');
    let (trace, span, flags) = (parts[1], parts[2], parts[3]);
    if !lower_hex(parts[0]) || !id_ok(trace, 32) || !id_ok(span, 16) {
        return None;
    }
    if flags.len() != 2 || !lower_hex(flags) {
        return None;
    }
    let flags = u8::from_str_radix(flags, 16).ok()?;
    Some(TraceContext {
        trace_id: trace.to_string(),
        span_id: span.to_string(),
        sampled: flags & 1 == 1,
    })
}

struct HeaderExtract<'a>(&'a HeaderMap);

impl Extractor for HeaderExtract<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

struct MapInject<'a>(&'a mut HashMap<String, String>);

impl Injector for MapInject<'_> {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key.to_string(), value);
    }
}

/// Makes the trace context of incoming headers (`traceparent`) the parent of `span`; no effect
/// unless OTLP export is on.
pub fn attach_parent(span: &tracing::Span, headers: &HeaderMap) {
    let cx = opentelemetry::global::get_text_map_propagator(|p| p.extract(&HeaderExtract(headers)));
    let _ = span.set_parent(cx);
}

/// The `traceparent` for an outgoing call made inside `span`: the span's own context when OTLP is
/// on, else a child of `incoming` when that parses, else `None`.
pub fn outgoing_traceparent(span: &tracing::Span, incoming: Option<&str>) -> Option<String> {
    let cx = span.context();
    if cx.span().span_context().is_valid() {
        let mut map = HashMap::new();
        opentelemetry::global::get_text_map_propagator(|p| {
            p.inject_context(&cx, &mut MapInject(&mut map))
        });
        return map.remove("traceparent");
    }
    incoming
        .and_then(parse_traceparent)
        .map(|t| t.child().traceparent())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[test]
    fn traceparent_parsing() {
        let tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        let t = parse_traceparent(tp).unwrap();
        assert_eq!(t.trace_id, "0af7651916cd43dd8448eb211c80319c");
        assert!(t.sampled);
        assert_eq!(t.traceparent(), tp);
        for bad in [
            "00-00000000000000000000000000000000-b7ad6b7169203331-01",
            "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01",
            "ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "00-0AF7651916CD43DD8448EB211C80319C-b7ad6b7169203331-01",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01-extra",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-zz",
            "garbage",
        ] {
            assert!(parse_traceparent(bad).is_none(), "{bad}");
        }
        assert!(
            parse_traceparent("01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00-x")
                .is_some_and(|t| !t.sampled),
            "future versions may carry more fields"
        );
        let root = TraceContext::new_root();
        assert_eq!(parse_traceparent(&root.traceparent()), Some(root.clone()));
        let child = root.child();
        assert_eq!(child.trace_id, root.trace_id);
        assert_ne!(child.span_id, root.span_id);
        let out = outgoing_traceparent(&tracing::Span::none(), Some(tp)).unwrap();
        assert!(out.starts_with("00-0af7651916cd43dd8448eb211c80319c-"));
        assert!(outgoing_traceparent(&tracing::Span::none(), None).is_none());
    }

    #[test]
    fn log_formats() {
        assert_eq!("JSON".parse::<LogFormat>(), Ok(LogFormat::Json));
        assert_eq!("text".parse::<LogFormat>(), Ok(LogFormat::Text));
        assert!("xml".parse::<LogFormat>().is_err());
    }

    #[tokio::test]
    async fn request_ids_and_http_metrics() {
        let recorder = prometheus_builder().unwrap().build_recorder();
        let handle = recorder.handle();
        let app: Router = Router::new()
            .route(
                "/items/{id}",
                get(|axum::Extension(id): axum::Extension<RequestId>| async move { id.0 }),
            )
            .layer(axum::middleware::from_fn(http_metrics))
            .layer(axum::middleware::from_fn(request_id))
            .merge(metrics_router(handle.clone()));
        let _guard = metrics::set_default_local_recorder(&recorder);
        let call = |req: Request<Body>| {
            let app = app.clone();
            async move { app.oneshot(req).await.unwrap() }
        };
        let r = call(
            Request::get("/items/1")
                .header(REQUEST_ID_HEADER, "abc-123")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(r.headers()[REQUEST_ID_HEADER], "abc-123");
        let body = r.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"abc-123");
        let r = call(
            Request::get("/items/2")
                .header(REQUEST_ID_HEADER, "bad id\twith spaces")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let id = r.headers()[REQUEST_ID_HEADER].to_str().unwrap().to_string();
        assert!(uuid::Uuid::parse_str(&id).is_ok(), "{id}");
        let r = call(Request::get("/nowhere").body(Body::empty()).unwrap()).await;
        assert_eq!(r.status(), 404);
        let text = handle.render();
        assert!(
            text.contains(
                "http_requests_total{method=\"GET\",route=\"/items/{id}\",status=\"200\"} 2"
            ),
            "{text}"
        );
        assert!(
            text.contains("http_request_duration_seconds_bucket"),
            "{text}"
        );
        let r = call(Request::get("/metrics").body(Body::empty()).unwrap()).await;
        assert_eq!(r.status(), 200);
    }
}
