//! Security headers, the Content-Security-Policy builder, origin checks, and request limits.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::ApiError;

/// A Content-Security-Policy. [`Csp::strict`] allows only same-origin scripts, styles, images,
/// fonts and requests, and forbids framing, plugins and `<base>`.
///
/// ```
/// use franshub_http::Csp;
///
/// let csp = Csp::strict()
///     .allow("connect-src", "https://api.example.com")
///     .unwrap()
///     .with_style_nonce("abc123");
/// let v = csp.build();
/// assert!(v.contains("connect-src 'self' https://api.example.com"));
/// assert!(v.contains("style-src 'self' 'nonce-abc123'"));
/// assert!(!v.contains("unsafe-inline"));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Csp {
    directives: Vec<(String, Vec<String>)>,
}

fn valid_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 512
        && s.chars()
            .all(|c| c.is_ascii_graphic() && c != ';' && c != ',')
}

impl Csp {
    /// The strict default policy.
    pub fn strict() -> Self {
        let d = |name: &str, src: &[&str]| {
            (
                name.to_string(),
                src.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            )
        };
        Self {
            directives: vec![
                d("default-src", &["'none'"]),
                d("script-src", &["'self'"]),
                d("style-src", &["'self'"]),
                d("img-src", &["'self'", "data:"]),
                d("font-src", &["'self'", "data:"]),
                d("connect-src", &["'self'"]),
                d("manifest-src", &["'self'"]),
                d("base-uri", &["'none'"]),
                d("form-action", &["'self'"]),
                d("frame-ancestors", &["'none'"]),
                d("object-src", &["'none'"]),
            ],
        }
    }

    /// Adds a source to a directive (creating the directive). Sources with whitespace, `;`, `,` or
    /// control characters are refused, so configuration values cannot inject directives.
    pub fn allow(mut self, directive: &str, source: &str) -> Result<Self, String> {
        if !valid_token(directive)
            || !directive
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'-')
        {
            return Err(format!("invalid CSP directive `{directive}`"));
        }
        if !valid_token(source) {
            return Err(format!(
                "invalid CSP source `{source}`: no whitespace, `;` or `,`"
            ));
        }
        match self.directives.iter_mut().find(|(n, _)| n == directive) {
            Some((_, list)) => {
                if list.len() == 1 && list[0] == "'none'" {
                    list.clear();
                }
                if !list.iter().any(|s| s == source) {
                    list.push(source.to_string());
                }
            }
            None => self
                .directives
                .push((directive.to_string(), vec![source.to_string()])),
        }
        Ok(self)
    }

    /// The policy with `'nonce-<nonce>'` added to `style-src` (for UI libraries that inject
    /// `<style>` elements).
    pub fn with_style_nonce(&self, nonce: &str) -> Self {
        self.clone()
            .allow("style-src", &format!("'nonce-{nonce}'"))
            .unwrap_or_else(|_| self.clone())
    }

    /// The header value.
    pub fn build(&self) -> String {
        self.directives
            .iter()
            .map(|(n, s)| format!("{n} {}", s.join(" ")))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

impl Default for Csp {
    fn default() -> Self {
        Self::strict()
    }
}

/// Headers [`security_headers`] adds to every response that does not set them itself.
#[derive(Clone, Debug)]
pub struct SecurityHeaders {
    /// `Content-Security-Policy`; `None` leaves it to the handlers.
    pub csp: Option<Csp>,
    /// `Strict-Transport-Security: max-age=<secs>`; set it only when the server is reached over
    /// https.
    pub hsts: Option<Duration>,
}

impl Default for SecurityHeaders {
    /// A strict CSP for API responses (`default-src 'none'; frame-ancestors 'none'`) and no HSTS.
    fn default() -> Self {
        Self {
            csp: Some(Csp {
                directives: vec![
                    ("default-src".into(), vec!["'none'".into()]),
                    ("frame-ancestors".into(), vec!["'none'".into()]),
                ],
            }),
            hsts: None,
        }
    }
}

/// Middleware adding `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
/// `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`, the CSP and HSTS of
/// `cfg`, unless the response already has them.
///
/// ```no_run
/// use std::sync::Arc;
/// use axum::{Router, middleware};
/// use franshub_http::{SecurityHeaders, security_headers};
///
/// let app: Router = Router::new()
///     .layer(middleware::from_fn_with_state(Arc::new(SecurityHeaders::default()), security_headers));
/// ```
pub async fn security_headers(
    State(cfg): State<Arc<SecurityHeaders>>,
    req: Request,
    next: Next,
) -> Response {
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    let mut set = |name: header::HeaderName, value: HeaderValue| {
        if !h.contains_key(&name) {
            h.insert(name, value);
        }
    };
    set(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    set(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    set(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    set(
        header::HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    if let Some(csp) = &cfg.csp
        && let Ok(v) = HeaderValue::from_str(&csp.build())
    {
        set(header::CONTENT_SECURITY_POLICY, v);
    }
    if let Some(max_age) = cfg.hsts
        && let Ok(v) = HeaderValue::from_str(&format!("max-age={}", max_age.as_secs()))
    {
        set(header::STRICT_TRANSPORT_SECURITY, v);
    }
    r
}

/// Whether a request's `Origin` may call the API: no `Origin` header (not a browser
/// cross-origin request), an origin listed in `allowed` (exact match such as
/// `https://ui.example.com`), or the origin of the `Host` the request was sent to.
pub fn origin_allowed(headers: &HeaderMap, allowed: &[String]) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return true;
    };
    let Ok(o) = origin.to_str() else {
        return false;
    };
    if allowed.iter().any(|a| a == o) {
        return true;
    }
    headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| {
            o.strip_prefix("http://")
                .or_else(|| o.strip_prefix("https://"))
                == Some(h)
        })
}

/// A request body limit for extractors such as [`crate::ApiJson`]; bodies over it answer 413 with
/// the uniform error body when read through [`crate::ApiJson`].
pub fn body_limit(bytes: usize) -> DefaultBodyLimit {
    DefaultBodyLimit::max(bytes)
}

/// Middleware answering 503 `timeout` (uniform error body) when the handler takes longer than the
/// duration in its state. Use it for request/response APIs, not for streams.
///
/// ```no_run
/// use std::time::Duration;
/// use axum::{Router, middleware};
/// use franshub_http::request_timeout;
///
/// let app: Router = Router::new()
///     .layer(middleware::from_fn_with_state(Duration::from_secs(30), request_timeout));
/// ```
pub async fn request_timeout(State(limit): State<Duration>, req: Request, next: Next) -> Response {
    match tokio::time::timeout(limit, next.run(req)).await {
        Ok(r) => r,
        Err(_) => {
            metrics::counter!("http_request_timeouts_total").increment(1);
            ApiError::new(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "timeout",
                "the request took too long",
            )
            .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_is_strict_and_refuses_injection() {
        let p = Csp::strict().build();
        assert!(p.starts_with("default-src 'none'; script-src 'self';"));
        assert!(!p.contains("unsafe-inline") && !p.contains("unsafe-eval") && !p.contains('*'));
        assert!(p.contains("frame-ancestors 'none'"));
        assert!(
            Csp::strict()
                .allow("connect-src", "a; script-src *")
                .is_err()
        );
        assert!(Csp::strict().allow("connect-src", "a b").is_err());
        assert!(Csp::strict().allow("Bad", "a").is_err());
        let c = Csp::strict()
            .allow("connect-src", "https://mock.example.com:8443")
            .unwrap()
            .allow("connect-src", "https://mock.example.com:8443")
            .unwrap()
            .allow("default-src", "'self'")
            .unwrap()
            .allow("worker-src", "'self'")
            .unwrap();
        let v = c.build();
        assert!(
            v.contains("connect-src 'self' https://mock.example.com:8443;"),
            "{v}"
        );
        assert!(v.contains("default-src 'self';"), "{v}");
        assert!(v.ends_with("worker-src 'self'"), "{v}");
    }

    #[test]
    fn origins() {
        let mut h = HeaderMap::new();
        assert!(origin_allowed(&h, &[]));
        h.insert(header::HOST, HeaderValue::from_static("ui.example.com"));
        h.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example.com"),
        );
        assert!(!origin_allowed(&h, &[]));
        assert!(origin_allowed(&h, &["https://evil.example.com".into()]));
        h.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://ui.example.com"),
        );
        assert!(origin_allowed(&h, &[]));
        h.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://ui.example.com.evil.example.com"),
        );
        assert!(!origin_allowed(&h, &[]));
    }
}
