//! Redaction of secrets before data is logged, stored or shown: sensitive headers, query
//! parameters, JSON keys (also inside XML, multipart and broken JSON text), and registered literal
//! values wherever they appear. Long text is truncated on a character boundary.
//!
//! ```
//! use franshub_redact::Redactor;
//!
//! let r = Redactor::with_defaults();
//! let h = r.headers([("Authorization", "Bearer abc"), ("Accept", "text/html")]);
//! assert_eq!(h["authorization"], "Bearer ***");
//! assert_eq!(r.query("user=a&password=b"), "user=a&password=***");
//! ```

use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, LazyLock, RwLock};

use aho_corasick::{AhoCorasick, MatchKind};
use regex::Regex;
use serde_json::Value;

/// What a redacted value is replaced with.
pub const MASK: &str = "***";
/// Shortest literal [`Redactor::register_literal`] accepts.
pub const MIN_LITERAL_LEN: usize = 8;
/// Most literals kept; registering more drops the oldest.
pub const MAX_LITERALS: usize = 256;

/// Header names masked by [`Redactor::with_defaults`], besides any name with a token, secret,
/// password, key, signature or credential part.
pub const DEFAULT_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "apikey",
    "api-key",
    "x-auth-token",
    "x-signature",
    "x-hub-signature",
    "x-hub-signature-256",
    "x-amz-security-token",
    "ocp-apim-subscription-key",
];

/// JSON keys, query parameters and form fields masked by [`Redactor::with_defaults`]. Keys compare
/// case-insensitively, ignoring `_` and `-`.
pub const DEFAULT_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "otp",
    "apikey",
    "api_key",
    "authorization",
    "auth",
    "pin",
    "cvv",
    "sig",
    "signature",
    "key",
    "private_key",
    "session",
];

/// Masks secrets in headers, queries and bodies.
pub struct Redactor {
    headers: HashSet<String>,
    keys: HashSet<String>,
    literals: RwLock<Literals>,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.literals.read().map(|l| l.values.len()).unwrap_or(0);
        f.debug_struct("Redactor")
            .field("headers", &self.headers.len())
            .field("keys", &self.keys.len())
            .field("literals", &n)
            .finish()
    }
}

#[derive(Default)]
struct Literals {
    values: Vec<String>,
    matcher: Option<Arc<AhoCorasick>>,
}

fn normalize(k: &str) -> String {
    k.split('[')
        .next()
        .unwrap_or(k)
        .chars()
        .filter(|c| *c != '_' && *c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

impl Redactor {
    /// A redactor for these header names and keys.
    pub fn new(headers: &[impl AsRef<str>], keys: &[impl AsRef<str>]) -> Self {
        Self {
            headers: headers
                .iter()
                .map(|h| h.as_ref().to_ascii_lowercase())
                .collect(),
            keys: keys.iter().map(|k| normalize(k.as_ref())).collect(),
            literals: RwLock::new(Literals::default()),
        }
    }

    /// A redactor for [`DEFAULT_HEADERS`] and [`DEFAULT_KEYS`].
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_HEADERS, DEFAULT_KEYS)
    }

    /// Registers a secret value that is masked wherever it appears verbatim. Values shorter than
    /// [`MIN_LITERAL_LEN`] are refused; beyond [`MAX_LITERALS`] the oldest is dropped.
    pub fn register_literal(&self, value: &str) -> Result<(), String> {
        if value.len() < MIN_LITERAL_LEN {
            return Err(format!(
                "the value is shorter than {MIN_LITERAL_LEN} bytes and cannot be redacted reliably"
            ));
        }
        let Ok(mut l) = self.literals.write() else {
            return Err("the redaction list is unavailable".into());
        };
        if l.values.iter().any(|v| v == value) {
            return Ok(());
        }
        if l.values.len() >= MAX_LITERALS {
            l.values.remove(0);
        }
        l.values.push(value.to_string());
        let built = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&l.values)
            .map_err(|e| format!("building the redaction list failed: {e}"))?;
        l.matcher = Some(Arc::new(built));
        Ok(())
    }

    fn literal_matcher(&self) -> Option<Arc<AhoCorasick>> {
        self.literals.read().ok().and_then(|l| l.matcher.clone())
    }

    /// Masks registered literals in text.
    pub fn scrub<'a>(&self, text: &'a str) -> Cow<'a, str> {
        match self.literal_matcher() {
            Some(m) if m.is_match(text) => {
                let masks = vec![MASK; m.patterns_len()];
                Cow::Owned(m.replace_all(text, &masks))
            }
            _ => Cow::Borrowed(text),
        }
    }

    fn scrub_bytes<'a>(&self, body: &'a [u8]) -> Cow<'a, [u8]> {
        match self.literal_matcher() {
            Some(m) if m.is_match(body) => {
                let masks = vec![MASK.as_bytes(); m.patterns_len()];
                Cow::Owned(m.replace_all_bytes(body, &masks))
            }
            _ => Cow::Borrowed(body),
        }
    }

    /// Whether a header is masked: a configured name, or one with a token, secret, password, key,
    /// signature or credential part.
    pub fn sensitive_header(&self, h: &str) -> bool {
        let h = h.to_ascii_lowercase();
        self.headers.contains(&h)
            || h.split(['-', '_']).any(|t| {
                matches!(
                    t,
                    "sig"
                        | "signature"
                        | "hmac"
                        | "token"
                        | "secret"
                        | "password"
                        | "apikey"
                        | "key"
                        | "credential"
                        | "credentials"
                ) || t.ends_with("signature")
                    || t.ends_with("token")
            })
    }

    /// Whether a JSON key, query parameter or form field is masked.
    pub fn sensitive_key(&self, k: &str) -> bool {
        self.keys.contains(&normalize(k))
    }

    /// Removes sensitive keys from a JSON value; returns whether any was removed.
    pub fn strip_sensitive(&self, v: &mut Value) -> bool {
        match v {
            Value::Object(m) => {
                let before = m.len();
                m.retain(|k, _| !self.sensitive_key(k));
                let mut removed = m.len() != before;
                for x in m.values_mut() {
                    removed |= self.strip_sensitive(x);
                }
                removed
            }
            Value::Array(a) => a
                .iter_mut()
                .fold(false, |acc, x| self.strip_sensitive(x) | acc),
            _ => false,
        }
    }

    /// Headers with lowercase names, sensitive values masked (keeping an auth scheme such as
    /// `Bearer`), literals scrubbed and repeated headers joined with `, `.
    pub fn headers<'a>(
        &self,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> BTreeMap<String, String> {
        let mut out: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in headers {
            let k = k.to_ascii_lowercase();
            let v = if self.sensitive_header(&k) {
                mask_auth(v)
            } else {
                self.scrub(v).into_owned()
            };
            out.entry(k)
                .and_modify(|e| {
                    e.push_str(", ");
                    e.push_str(&v);
                })
                .or_insert(v);
        }
        out
    }

    /// A query string with sensitive parameters masked.
    pub fn query(&self, raw: &str) -> String {
        if raw.is_empty() {
            return String::new();
        }
        let raw = self.scrub(raw);
        raw.split('&')
            .map(|p| match p.split_once('=') {
                Some((k, _)) if self.sensitive_key(&percent_decode(k)) => format!("{k}={MASK}"),
                _ => p.to_string(),
            })
            .collect::<Vec<_>>()
            .join("&")
    }

    /// Masks the values of sensitive keys in a JSON value, at any depth.
    pub fn json(&self, v: &mut Value) {
        match v {
            Value::Object(m) => {
                for (k, x) in m.iter_mut() {
                    if self.sensitive_key(k) {
                        *x = Value::String(MASK.into());
                    } else {
                        self.json(x);
                    }
                }
            }
            Value::Array(a) => a.iter_mut().for_each(|x| self.json(x)),
            _ => {}
        }
    }

    fn composite_secret(&self, v: &Value) -> bool {
        match v {
            Value::Object(m) => m.iter().any(|(k, x)| {
                (self.sensitive_key(k) && (x.is_object() || x.is_array()))
                    || self.composite_secret(x)
            }),
            Value::Array(a) => a.iter().any(|x| self.composite_secret(x)),
            _ => false,
        }
    }

    /// Masks sensitive keys in text that may hold JSON, XML or multipart data, keeping the rest of
    /// the text as it is.
    pub fn mask_text(&self, text: &str) -> String {
        static JSON_KV: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r#""([A-Za-z0-9_.\-]{1,64})"(\s*:\s*)("(?:[^"\\]|\\.)*"?|-?[0-9][0-9.eE+-]*|true|false)"#).expect("static regex")
        });
        static XML_EL: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"<((?:[A-Za-z_][\w.-]*:)?([A-Za-z_][\w.-]*))((?:\s[^<>]*)?)>([^<]*)")
                .expect("static regex")
        });
        static XML_ATTR: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r#"(\s(?:[A-Za-z_][\w.-]*:)?([A-Za-z_][\w.-]*)\s*=\s*)("[^"]*"|'[^']*')"#)
                .expect("static regex")
        });
        static MULTIPART: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r#"(?i)(content-disposition:[^\r\n]*\bname="([^"]{1,128})"[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n)([^\r\n]*)"#).expect("static regex")
        });
        let out = JSON_KV.replace_all(text, |c: &regex::Captures| {
            if self.sensitive_key(&c[1]) {
                format!("\"{}\"{}\"{MASK}\"", &c[1], &c[2])
            } else {
                c[0].to_string()
            }
        });
        let out = MULTIPART.replace_all(&out, |c: &regex::Captures| {
            if self.sensitive_key(&c[2]) {
                format!("{}{MASK}", &c[1])
            } else {
                c[0].to_string()
            }
        });
        if !text.trim_start().starts_with('<') {
            return out.into_owned();
        }
        let out = XML_ATTR.replace_all(&out, |c: &regex::Captures| {
            if self.sensitive_key(&c[2]) {
                format!("{}\"{MASK}\"", &c[1])
            } else {
                c[0].to_string()
            }
        });
        let out = XML_EL.replace_all(&out, |c: &regex::Captures| {
            if self.sensitive_key(&c[2]) && !c[4].trim().is_empty() {
                format!("<{}{}>{MASK}", &c[1], &c[3])
            } else {
                c[0].to_string()
            }
        });
        out.into_owned()
    }

    /// A body as text for logs and storage: literals scrubbed, sensitive keys masked (JSON, forms,
    /// XML, multipart), binary data summarised, and the result cut at `max` bytes.
    pub fn body(&self, body: &[u8], content_type: Option<&str>, max: usize) -> String {
        let body = self.scrub_bytes(body);
        let body: &[u8] = &body;
        let ct = content_type.unwrap_or("").to_ascii_lowercase();
        let trimmed = body.trim_ascii_start();
        if body.iter().take(512).any(|b| *b == 0) && !ct.contains("json") && !ct.contains("text") {
            return format!("[binary {} bytes]", body.len());
        }
        if ct.starts_with("application/x-www-form-urlencoded") {
            let head = &body[..body.len().min(max.saturating_mul(2))];
            return truncate(self.query(&String::from_utf8_lossy(head)), max);
        }
        let looks_json =
            ct.contains("json") || trimmed.first().is_some_and(|b| *b == b'{' || *b == b'[');
        if looks_json
            && body.len() <= max
            && let Ok(mut v) = serde_json::from_slice::<Value>(body)
            && self.composite_secret(&v)
        {
            self.json(&mut v);
            return truncate(v.to_string(), max);
        }
        let head = &body[..body.len().min(max)];
        let text = String::from_utf8_lossy(head);
        let masked = self.mask_text(&text);
        if body.len() > max {
            format!("{masked}…[truncated {} bytes]", body.len() - head.len())
        } else {
            masked
        }
    }
}

fn mask_auth(v: &str) -> String {
    match v.split_once(' ') {
        Some((scheme, _))
            if scheme.len() <= 16 && scheme.chars().all(|c| c.is_ascii_alphabetic()) =>
        {
            format!("{scheme} {MASK}")
        }
        _ => MASK.to_string(),
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                match s
                    .get(i + 1..i + 3)
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Cuts text at `max` bytes on a character boundary and notes how much was cut.
pub fn truncate(mut s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let total = s.len();
    let mut cut = max;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
    s.push_str(&format!("…[truncated {} bytes]", total - cut));
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn r() -> Redactor {
        Redactor::with_defaults()
    }

    #[test]
    fn masks_headers_keeping_scheme() {
        let out = r().headers([
            ("Authorization", "Bearer abc.def"),
            ("X-Callback-Token", "s3cr3t"),
            ("Accept", "a"),
            ("accept", "b"),
        ]);
        assert_eq!(out["authorization"], "Bearer ***");
        assert_eq!(out["x-callback-token"], "***");
        assert_eq!(out["accept"], "a, b");
    }

    #[test]
    fn masks_json_keys_but_not_lookalikes() {
        let body = json!({"password": "p", "nested": [{"Access-Token": "t", "message_token": "keep"}], "otp": 1234}).to_string();
        let out: Value =
            serde_json::from_str(&r().body(body.as_bytes(), Some("application/json"), 10_000))
                .unwrap();
        assert_eq!(
            out,
            json!({"password": "***", "nested": [{"Access-Token": "***", "message_token": "keep"}], "otp": "***"})
        );
        let mut v = json!({"a": {"client_secret": "x", "b": 1}});
        assert!(r().strip_sensitive(&mut v));
        assert_eq!(v, json!({"a": {"b": 1}}));
    }

    #[test]
    fn masks_xml_multipart_broken_json_and_keeps_raw_text() {
        let r = r();
        assert_eq!(
            r.body(
                b"<s:Body><m:password>Hunter2</m:password><user>u</user><x token=\"t1\"/></s:Body>",
                Some("text/xml"),
                10_000
            ),
            "<s:Body><m:password>***</m:password><user>u</user><x token=\"***\"/></s:Body>"
        );
        assert_eq!(
            r.body(br#"{"password":"Hunter2json",}"#, None, 10_000),
            r#"{"password":"***",}"#
        );
        assert_eq!(
            r.body(br#" {"a": 1, "pin": 1234}"#, Some("text/plain"), 10_000),
            r#" {"a": 1, "pin": "***"}"#
        );
        let mp = "--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nHunter2mp\r\n--b\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nu\r\n--b--";
        let out = r.body(
            mp.as_bytes(),
            Some("multipart/form-data; boundary=b"),
            10_000,
        );
        assert!(
            !out.contains("Hunter2mp") && out.contains("\r\nu\r\n"),
            "{out}"
        );
        let cut = r.body(br#"{"password":"Hunter2-very-long-value"}"#, None, 20);
        assert!(!cut.contains("Hunter2"), "{cut}");
        assert_eq!(
            r.body(br#"{"secret": {"a": "b"}}"#, None, 10_000),
            r#"{"secret":"***"}"#
        );
    }

    #[test]
    fn registered_literals_are_masked_everywhere() {
        let r = r();
        assert!(r.register_literal("short").is_err());
        r.register_literal("Bearer s3cr3t-literal").unwrap();
        r.register_literal("s3cr3t-literal").unwrap();
        r.register_literal("s3cr3t-literal").unwrap();
        let h = r.headers([("X-Probe", "got Bearer s3cr3t-literal!"), ("Accept", "a")]);
        assert_eq!(h["x-probe"], "got ***!");
        assert_eq!(r.query("a=s3cr3t-literal&b=1"), "a=***&b=1");
        let body = format!("{}got=s3cr3t-literal", "x".repeat(30));
        let out = r.body(body.as_bytes(), Some("text/plain"), 40);
        assert!(!out.contains("s3cr3t"), "{out}");
        assert_eq!(
            r.body(
                br#"{"echo":"s3cr3t-literal"}"#,
                Some("application/json"),
                1000
            ),
            r#"{"echo":"***"}"#
        );
        assert_eq!(r.scrub("nothing here"), "nothing here");
        assert!(!format!("{r:?}").contains("s3cr3t"));
    }

    #[test]
    fn literals_are_bounded() {
        let r = r();
        for i in 0..(MAX_LITERALS + 5) {
            r.register_literal(&format!("literal-value-{i:04}"))
                .unwrap();
        }
        assert_eq!(r.scrub("literal-value-0000"), "literal-value-0000");
        assert_eq!(
            r.scrub(&format!("literal-value-{:04}", MAX_LITERALS + 4)),
            MASK
        );
    }

    #[test]
    fn masks_forms_queries_and_truncates() {
        assert_eq!(
            r().query("user=a&password=b&pass%77ord=c&pass%zzword=d"),
            "user=a&password=***&pass%77ord=***&pass%zzword=d"
        );
        assert_eq!(
            r().body(
                b"user=a&client_secret=x",
                Some("application/x-www-form-urlencoded"),
                100
            ),
            "user=a&client_secret=***"
        );
        let long = r().body("é".repeat(100).as_bytes(), Some("text/plain"), 11);
        assert!(long.starts_with("ééééé") && long.contains("truncated"));
        assert_eq!(r().body(&[0, 1, 2], None, 100), "[binary 3 bytes]");
        assert_eq!(truncate("abc".into(), 5), "abc");
        assert_eq!(truncate("abcdef".into(), 3), "abc…[truncated 3 bytes]");
    }
}
