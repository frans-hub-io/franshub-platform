//! Static tokens from a file, compared in constant time.

use std::path::Path;

use anyhow::{Context, bail};
use franshub_access::{AccessPolicy, Binding, PrincipalKind, Scopes, Subject};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use franshub_access::Principal;

/// Longest static or managed token value accepted, in bytes.
pub const MAX_TOKEN_BYTES: usize = 512;

struct Entry {
    name: String,
    role: String,
    hash: [u8; 32],
}

/// Static tokens: each has a name and a role granted globally. Only SHA-256 hashes are kept.
///
/// File format, one token per line (`#` starts a comment line):
///
/// ```text
/// ops:admin:sha256:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
/// ci:editor:0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e
/// dashboard:viewer:plain-secret-value-of-at-least-16-bytes
/// ```
///
/// The third field is `sha256:<hex>`, a bare 64-digit lowercase hex SHA-256, or the plain token
/// (hashed when loaded; at least 16 bytes). Prefer hashes: the file then holds no secret.
#[derive(Default)]
pub struct StaticTokens {
    entries: Vec<Entry>,
}

impl std::fmt::Debug for StaticTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(
                self.entries
                    .iter()
                    .map(|e| format!("{}:{}", e.name, e.role)),
            )
            .finish()
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
}

fn parse_hash(raw: &str) -> Option<[u8; 32]> {
    let hex_part = raw.strip_prefix("sha256:").unwrap_or(raw);
    if hex_part.len() != 64
        || !hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    hex::decode(hex_part).ok()?.try_into().ok()
}

impl StaticTokens {
    /// No static tokens.
    pub fn none() -> Self {
        Self::default()
    }

    /// Reads a token file; every role must exist in the policy. Errors name the line, never the
    /// secret.
    pub fn from_file(path: &Path, policy: &AccessPolicy) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the token file {}", path.display()))?;
        Self::parse(&text, policy).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
    }

    /// Parses token lines (see the type documentation).
    pub fn parse(text: &str, policy: &AccessPolicy) -> anyhow::Result<Self> {
        let mut entries: Vec<Entry> = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let at = format!("line {}", i + 1);
            let mut parts = line.splitn(3, ':');
            let (Some(name), Some(role), Some(secret)) = (parts.next(), parts.next(), parts.next())
            else {
                bail!("{at}: expected name:role:secret");
            };
            let (name, role, secret) = (name.trim(), role.trim(), secret.trim());
            if !valid_name(name) {
                bail!("{at}: token names are 1..128 characters of [A-Za-z0-9._@-]");
            }
            if policy.role(role).is_none() {
                bail!("{at} ({name}): unknown role `{role}`");
            }
            if entries.iter().any(|e| e.name == name) {
                bail!("{at} ({name}): token name listed twice");
            }
            let hash = match parse_hash(secret) {
                Some(h) => h,
                None if secret.starts_with("sha256:") => {
                    bail!("{at} ({name}): sha256: must be followed by 64 lowercase hex digits")
                }
                None if secret.len() < 16 || secret.len() > MAX_TOKEN_BYTES => {
                    bail!("{at} ({name}): a plain token must be 16..{MAX_TOKEN_BYTES} bytes")
                }
                None => Sha256::digest(secret.as_bytes()).into(),
            };
            if entries.iter().any(|e| bool::from(e.hash.ct_eq(&hash))) {
                bail!("{at} ({name}): the same token is listed twice");
            }
            entries.push(Entry {
                name: name.to_string(),
                role: role.to_string(),
                hash,
            });
        }
        Ok(Self { entries })
    }

    /// Number of tokens.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// No tokens.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether a static token has this name (managed tokens must not reuse it).
    pub fn has_name(&self, name: &str) -> bool {
        self.entries.iter().any(|e| e.name == name)
    }

    /// `(name, role)` of every token, in file order.
    pub fn roles(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|e| (e.name.as_str(), e.role.as_str()))
    }

    /// The principal of a presented value, comparing against every entry in constant time.
    pub fn authenticate(&self, value: &str, policy: &AccessPolicy) -> Option<Principal> {
        if value.is_empty() || value.len() > MAX_TOKEN_BYTES {
            return None;
        }
        let presented: [u8; 32] = Sha256::digest(value.as_bytes()).into();
        let mut found: Option<&Entry> = None;
        for e in &self.entries {
            if bool::from(e.hash.ct_eq(&presented)) {
                found = Some(e);
            }
        }
        let e = found?;
        let binding = Binding {
            subject: Subject::User(e.name.clone()),
            role: e.role.clone(),
            scopes: Scopes::Global,
        };
        Some(policy.principal(PrincipalKind::Token, &e.name, &[binding]))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use franshub_access::Catalog;

    use super::*;
    use crate::tokens::hash_token;

    fn policy() -> AccessPolicy {
        AccessPolicy::new(Arc::new(
            Catalog::builder()
                .permission("launches:read", "r")
                .role("viewer", &["launches:read"])
                .role("admin", &["*"])
                .build()
                .unwrap(),
        ))
    }

    #[test]
    fn hashed_and_plain_entries() {
        let p = policy();
        let text = format!(
            "# comment\nops:admin:sha256:{}\n\nci:viewer:{}\ndash:viewer:plain-secret-value-0001\n",
            hash_token("admin-token-value"),
            hash_token("viewer-token-value")
        );
        let t = StaticTokens::parse(&text, &p).unwrap();
        assert_eq!(t.len(), 3);
        let ops = t.authenticate("admin-token-value", &p).unwrap();
        assert_eq!(ops.name, "ops");
        assert_eq!(ops.kind, PrincipalKind::Token);
        assert!(ops.allowed(&p.catalog().require("tokens:write"), None));
        let ci = t.authenticate("viewer-token-value", &p).unwrap();
        assert!(!ci.allowed(&p.catalog().require("tokens:write"), None));
        assert!(t.authenticate("plain-secret-value-0001", &p).is_some());
        assert!(t.authenticate("wrong", &p).is_none());
        assert!(t.authenticate("", &p).is_none());
        assert!(t.authenticate(&"x".repeat(600), &p).is_none());
        assert!(t.has_name("ci") && !t.has_name("nobody"));
        let dbg = format!("{t:?}");
        assert!(
            dbg.contains("ops:admin") && !dbg.contains("plain-secret"),
            "{dbg}"
        );
    }

    #[test]
    fn errors_name_the_line_but_never_the_secret() {
        let p = policy();
        let cases = [
            ("a:admin", "line 1: expected name:role:secret"),
            (
                "bad name:admin:plain-secret-value-0001",
                "line 1: token names",
            ),
            (
                "a:root:plain-secret-value-0001",
                "line 1 (a): unknown role `root`",
            ),
            ("a:admin:sha256:zz", "sha256: must be followed"),
            ("a:admin:short", "a plain token must be"),
            (
                "a:admin:plain-secret-value-0001\na:viewer:plain-secret-value-0002",
                "line 2 (a): token name listed twice",
            ),
            (
                "a:admin:plain-secret-value-0001\nb:viewer:plain-secret-value-0001",
                "line 2 (b): the same token is listed twice",
            ),
        ];
        for (text, want) in cases {
            let e = format!("{:#}", StaticTokens::parse(text, &p).unwrap_err());
            assert!(e.contains(want), "{text}: {e}");
            assert!(!e.contains("plain-secret"), "{e}");
        }
    }
}
