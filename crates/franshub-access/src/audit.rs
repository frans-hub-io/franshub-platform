//! Audit records of changes and sign-ins, and the store they go to.

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::grants::Principal;

/// Largest page an [`AuditStore`] returns.
pub const MAX_PAGE: u32 = 1000;
/// Page size when the filter sets none.
pub const DEFAULT_PAGE: u32 = 100;

/// One audit record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    /// Assigned by the store; 0 before [`AuditStore::append`].
    #[serde(default)]
    pub id: i64,
    /// When it happened.
    pub at: DateTime<Utc>,
    /// Name of the principal.
    pub principal: String,
    /// `user`, `token` or `apiToken`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_kind: Option<String>,
    /// Role names of the principal's bindings, comma-separated.
    pub roles: String,
    /// The scope the change applied to; `None` for global changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Dotted action name such as `token.create`.
    pub action: String,
    /// Action details; never secrets.
    pub detail: Value,
}

impl AuditEvent {
    /// An event by a principal, timestamped now.
    pub fn new(principal: &Principal, action: &str, scope: Option<&str>, detail: Value) -> Self {
        Self {
            id: 0,
            at: Utc::now(),
            principal: principal.name.clone(),
            principal_kind: Some(principal.kind.as_str().to_string()),
            roles: principal.role_label(),
            scope: scope.map(String::from),
            action: action.to_string(),
            detail,
        }
    }

    /// An event by someone who is not (yet) a principal, such as a failed sign-in.
    pub fn anonymous(name: &str, kind: Option<&str>, action: &str, detail: Value) -> Self {
        Self {
            id: 0,
            at: Utc::now(),
            principal: name.to_string(),
            principal_kind: kind.map(String::from),
            roles: String::new(),
            scope: None,
            action: action.to_string(),
            detail,
        }
    }
}

/// Which records to return, newest first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditFilter {
    /// Exact action, or a prefix ending in `*` (`token.*`).
    pub action: Option<String>,
    /// Exact principal name.
    pub principal: Option<String>,
    /// Exact scope.
    pub scope: Option<String>,
    /// At or after.
    pub since: Option<DateTime<Utc>>,
    /// Before.
    pub until: Option<DateTime<Utc>>,
    /// Records with a smaller id only: the `nextBefore` of the previous page.
    pub before: Option<i64>,
    /// Page size, 1..=1000 (default 100).
    pub limit: Option<u32>,
}

impl AuditFilter {
    /// The action prefix of `token.*`.
    pub fn action_prefix(&self) -> Option<&str> {
        self.action.as_deref().and_then(|a| a.strip_suffix('*'))
    }

    /// The page size, clamped.
    pub fn page_size(&self) -> u32 {
        self.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE)
    }

    /// Whether a record matches (the paging cursor included).
    pub fn accepts(&self, e: &AuditEvent) -> bool {
        let action_ok = match (self.action_prefix(), &self.action) {
            (Some(p), _) => e.action.starts_with(p),
            (None, Some(a)) => e.action == *a,
            (None, None) => true,
        };
        action_ok
            && self.principal.as_ref().is_none_or(|p| *p == e.principal)
            && self
                .scope
                .as_ref()
                .is_none_or(|s| e.scope.as_ref() == Some(s))
            && self.since.is_none_or(|s| e.at >= s)
            && self.until.is_none_or(|u| e.at < u)
            && self.before.is_none_or(|b| e.id < b)
    }
}

/// One page of records, newest first.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditPage {
    /// The records.
    pub events: Vec<AuditEvent>,
    /// Pass as `before` to read the next page; `None` on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_before: Option<i64>,
}

impl AuditPage {
    /// A page from up to `size + 1` matching records, newest first.
    pub fn from_rows(mut rows: Vec<AuditEvent>, size: u32) -> Self {
        let more = rows.len() > size as usize;
        rows.truncate(size as usize);
        let next_before = if more {
            rows.last().map(|e| e.id)
        } else {
            None
        };
        Self {
            events: rows,
            next_before,
        }
    }
}

/// Where audit records go.
#[async_trait]
pub trait AuditStore: Send + Sync {
    /// Stores a record and returns its id.
    async fn append(&self, event: &AuditEvent) -> anyhow::Result<i64>;
    /// Records matching the filter, newest first, one page at a time.
    async fn query(&self, filter: &AuditFilter) -> anyhow::Result<AuditPage>;
    /// Deletes records older than `at`; returns how many.
    async fn purge_older_than(&self, at: DateTime<Utc>) -> anyhow::Result<u64>;
}

/// An in-process audit store keeping the newest records (bounded); for tests and development.
pub struct MemoryAuditStore {
    max: usize,
    inner: Mutex<(i64, VecDeque<AuditEvent>)>,
}

impl MemoryAuditStore {
    /// Keeps at most `max` records, dropping the oldest.
    pub fn new(max: usize) -> Self {
        Self {
            max: max.max(1),
            inner: Mutex::new((0, VecDeque::new())),
        }
    }
}

impl Default for MemoryAuditStore {
    fn default() -> Self {
        Self::new(10_000)
    }
}

#[async_trait]
impl AuditStore for MemoryAuditStore {
    async fn append(&self, event: &AuditEvent) -> anyhow::Result<i64> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.0 += 1;
        let mut e = event.clone();
        e.id = g.0;
        if g.1.len() >= self.max {
            g.1.pop_front();
        }
        g.1.push_back(e);
        Ok(g.0)
    }

    async fn query(&self, f: &AuditFilter) -> anyhow::Result<AuditPage> {
        let size = f.page_size();
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let rows: Vec<AuditEvent> =
            g.1.iter()
                .rev()
                .filter(|e| f.accepts(e))
                .take(size as usize + 1)
                .cloned()
                .collect();
        Ok(AuditPage::from_rows(rows, size))
    }

    async fn purge_older_than(&self, at: DateTime<Utc>) -> anyhow::Result<u64> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let before = g.1.len();
        g.1.retain(|e| e.at >= at);
        Ok((before - g.1.len()) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(action: &str, principal: &str, scope: Option<&str>) -> AuditEvent {
        let mut e = AuditEvent::anonymous(principal, Some("user"), action, json!({}));
        e.scope = scope.map(String::from);
        e
    }

    #[tokio::test]
    async fn memory_store_filters_pages_and_bounds() {
        let s = MemoryAuditStore::new(50);
        for i in 0..60 {
            let action = if i % 2 == 0 {
                "token.create"
            } else {
                "auth.login"
            };
            let scope = (i % 3 == 0).then_some("a");
            s.append(&ev(action, &format!("p{}", i % 4), scope))
                .await
                .unwrap();
        }
        let all = s
            .query(&AuditFilter {
                limit: Some(1000),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(all.events.len(), 50, "bounded");
        assert!(all.next_before.is_none());
        assert_eq!(all.events[0].id, 60);
        let tokens = s
            .query(&AuditFilter {
                action: Some("token.*".into()),
                limit: Some(10),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(tokens.events.len(), 10);
        assert!(tokens.events.iter().all(|e| e.action == "token.create"));
        let next = s
            .query(&AuditFilter {
                action: Some("token.*".into()),
                limit: Some(10),
                before: tokens.next_before,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(next.events[0].id < tokens.events[9].id);
        let scoped = s
            .query(&AuditFilter {
                scope: Some("a".into()),
                principal: Some("p0".into()),
                limit: Some(1000),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            scoped
                .events
                .iter()
                .all(|e| e.scope.as_deref() == Some("a") && e.principal == "p0")
        );
        assert_eq!(
            s.purge_older_than(Utc::now() + chrono::Duration::seconds(1))
                .await
                .unwrap(),
            50
        );
    }
}
