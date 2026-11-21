//! The uniform JSON error of every FransHub API: `{"code": "...", "message": "...", "details": ...}`.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The JSON body of an error response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Stable machine-readable code such as `unauthorized` or `not_found`.
    pub code: String,
    /// One sentence for people.
    pub message: String,
    /// Optional structured details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

/// An error response with the uniform JSON body. Boxed, so `Result<T, ApiError>` stays small.
#[derive(Clone, Debug)]
pub struct ApiError(Box<Inner>);

#[derive(Clone, Debug)]
struct Inner {
    status: StatusCode,
    body: ErrorBody,
    headers: Vec<(HeaderName, HeaderValue)>,
}

/// Result type of handlers answering [`ApiError`].
pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    /// An error with a status, code and message.
    pub fn new(status: StatusCode, code: &str, message: impl Into<String>) -> Self {
        Self(Box::new(Inner {
            status,
            body: ErrorBody {
                code: code.to_string(),
                message: message.into(),
                details: None,
            },
            headers: Vec::new(),
        }))
    }

    /// The HTTP status.
    pub fn status(&self) -> StatusCode {
        self.0.status
    }

    /// The JSON body.
    pub fn body(&self) -> &ErrorBody {
        &self.0.body
    }

    /// Adds structured details.
    pub fn with_details(mut self, details: Value) -> Self {
        self.0.body.details = Some(details);
        self
    }

    /// Adds a response header.
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.0.headers.push((name, value));
        self
    }

    /// 400 `bad_request`.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    /// 401 `unauthorized`, the same for every reason (missing, unknown, expired or revoked
    /// credentials), with `WWW-Authenticate: Bearer`.
    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "authentication required",
        )
        .with_header(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))
    }

    /// 403 `forbidden`.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    /// 404 `not_found` for a kind of resource (`token`, `scope`).
    pub fn not_found(what: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("{what} not found"),
        )
    }

    /// 409 `conflict`.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    /// 429 `too_many_requests`.
    pub fn too_many_requests(message: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "too_many_requests", message)
    }

    /// 503 `unavailable`.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable", message)
    }

    /// 500 `internal` with a generic message; the cause belongs in the log, not the response.
    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal error",
        )
    }
}

impl From<anyhow::Error> for ApiError {
    /// Logs the error and answers a generic 500.
    fn from(e: anyhow::Error) -> Self {
        tracing::error!(error = %format!("{e:#}"), "request failed");
        Self::internal()
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}: {}",
            self.0.status.as_u16(),
            self.0.body.code,
            self.0.body.message
        )
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let inner = *self.0;
        let mut r = (inner.status, Json(inner.body)).into_response();
        for (k, v) in inner.headers {
            r.headers_mut().insert(k, v);
        }
        r.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        r
    }
}

/// A JSON request body whose rejections answer with the uniform error shape.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApiJson<T>(pub T);

impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(Self(v)),
            Err(r) => Err(json_rejection(&r)),
        }
    }
}

fn json_rejection(r: &JsonRejection) -> ApiError {
    let status = r.status();
    let code = match status {
        StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "unsupported_media_type",
        _ => "bad_request",
    };
    let message = match r {
        JsonRejection::JsonDataError(e) => format!("invalid JSON body: {}", e.body_text()),
        JsonRejection::JsonSyntaxError(_) => "the body is not valid JSON".to_string(),
        JsonRejection::MissingJsonContentType(_) => {
            "expected Content-Type: application/json".to_string()
        }
        _ if status == StatusCode::PAYLOAD_TOO_LARGE => "the body is too large".to_string(),
        _ => "the body could not be read".to_string(),
    };
    ApiError::new(status, code, message)
}

impl<T: Serialize> IntoResponse for ApiJson<T> {
    fn into_response(self) -> Response {
        Json(self.0).into_response()
    }
}
