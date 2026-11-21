//! `GET /api/v1/me` and the managed tokens API under `/api/v1/tokens`.

use std::collections::BTreeSet;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use chrono::{DateTime, Utc};
use franshub_access::{
    ALL_SCOPES, AuditEvent, GrantsView, PermSet, Permission, Principal, PrincipalKind, Scopes,
    TOKENS_READ, TOKENS_WRITE,
};
use franshub_http::{ApiError, ApiJson, ApiResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::platform::{
    Auth, AuthMethod, DEFAULT_TOKEN_DAYS, Platform, PlatformState, deny, require,
};
use crate::tokens::{ApiToken, TokenService, TokenStatus, hash_token, stored_precision};

const MAX_NAME: usize = 128;
const MAX_DESCRIPTION: usize = 1024;

/// The answer of `GET /api/v1/me`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeView {
    /// User or token name.
    pub name: String,
    /// `user`, `token` or `apiToken`.
    pub kind: PrincipalKind,
    /// `session`, `bearer`, `staticToken` or `managedToken`.
    pub auth_method: AuthMethod,
    /// Role names of the bindings that apply.
    pub roles: Vec<String>,
    /// OIDC users: their groups.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// Managed tokens: the token id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<Uuid>,
    /// Effective permissions: in scope S they are `global ∪ allScopes ∪ scopes[S]`.
    pub permissions: GrantsView,
}

async fn me(auth: Auth) -> ApiJson<MeView> {
    let p = auth.principal;
    ApiJson(MeView {
        name: p.name,
        kind: p.kind,
        auth_method: auth.method,
        roles: p.roles,
        groups: p.groups,
        token_id: p.token_id,
        permissions: p.perms.view(),
    })
}

/// Body of `POST /api/v1/tokens`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateToken {
    /// `[A-Za-z0-9._@-]`, at most 128 characters; unique among active tokens and distinct from
    /// static token names.
    pub name: String,
    /// A built-in or custom role.
    pub role: String,
    /// Scope keys, or `["*"]` for every scope including later ones. Set this or `global: true`.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Grant the role everywhere.
    #[serde(default)]
    pub global: Option<bool>,
    /// Lifetime in days, 1..=max (default 90, or the max when lower).
    #[serde(default)]
    pub expires_in_days: Option<u32>,
    /// Free text, at most 1024 bytes.
    #[serde(default)]
    pub description: Option<String>,
}

/// Metadata of a managed token; the value is never shown after creation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenInfo {
    /// Id.
    pub id: Uuid,
    /// Name.
    pub name: String,
    /// Role.
    pub role: String,
    /// Scope keys; `["*"]` for every scope; empty for a global token.
    pub scopes: Vec<String>,
    /// Granted globally.
    pub global: bool,
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Who created it.
    pub created_by: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Expiry.
    pub expires_at: DateTime<Utc>,
    /// Last use (recorded at most once a minute).
    pub last_used_at: Option<DateTime<Utc>>,
    /// Revocation time.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Status now.
    pub status: TokenStatus,
    /// The managed token that created it; it expires no later than that one and is revoked with it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<Uuid>,
}

impl TokenInfo {
    /// The view of a stored token.
    pub fn of(t: &ApiToken) -> Self {
        let now = Utc::now();
        TokenInfo {
            id: t.id,
            name: t.name.clone(),
            role: t.role.clone(),
            scopes: t.scopes.clone(),
            global: t.global,
            description: t.description.clone(),
            created_by: t.created_by.clone(),
            created_at: stored_precision(t.created_at),
            expires_at: stored_precision(t.expires_at),
            last_used_at: t.last_used_at.map(stored_precision),
            revoked_at: t
                .revoked_at
                .filter(|_| t.status(now) == TokenStatus::Revoked)
                .map(stored_precision),
            status: t.status(now),
            parent_id: t.parent_id,
        }
    }
}

/// Answer of `POST /api/v1/tokens`: the value, shown only here, and the metadata.
#[derive(Debug, Serialize)]
pub struct CreatedToken {
    /// The token value: store it now.
    pub token: String,
    /// Metadata.
    #[serde(flatten)]
    pub info: TokenInfo,
}

/// Answer of `GET /api/v1/tokens`.
#[derive(Debug, Serialize)]
pub struct TokenList {
    /// Newest first.
    pub tokens: Vec<TokenInfo>,
}

#[derive(Deserialize)]
struct TokensQuery {
    scope: Option<String>,
    status: Option<String>,
}

/// A role and where the caller may grant it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantableRole {
    /// Role name.
    pub name: String,
    /// Defined by the product rather than the access file.
    pub builtin: bool,
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Permissions of the role.
    pub permissions: Vec<String>,
    /// The caller may create global tokens with this role.
    pub global: bool,
    /// Scopes where the caller may create tokens with this role.
    pub scopes: Vec<String>,
    /// The caller may create `["*"]` tokens with this role.
    pub all_scopes: bool,
}

/// Answer of `GET /api/v1/tokens/options`: computed by the server from the escalation rule.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenOptions {
    /// Longest lifetime in days.
    pub max_days: u32,
    /// Lifetime used when `expiresInDays` is omitted.
    pub default_days: u32,
    /// Scopes the caller can see.
    pub scopes: Vec<String>,
    /// Roles with the scopes where the caller may grant them (roles it cannot grant anywhere
    /// included, with empty choices).
    pub roles: Vec<GrantableRole>,
}

fn svc(p: &Platform) -> ApiResult<&TokenService> {
    p.tokens()
        .map(|t| t.as_ref())
        .ok_or_else(|| ApiError::not_found("managed tokens"))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
}

fn is_all_scopes(t: &ApiToken) -> bool {
    matches!(t.binding_scopes(), Scopes::All)
}

fn scopes_of(t: &ApiToken) -> Vec<Option<&str>> {
    if t.global {
        vec![None]
    } else {
        t.scopes.iter().map(|s| Some(s.as_str())).collect()
    }
}

/// The caller holds `perm` in every scope of the token; for a `*` token, globally or through its
/// own `*` grant.
fn holds_everywhere(p: &Principal, perm: &Permission, t: &ApiToken) -> bool {
    if is_all_scopes(t) {
        return p.perms.allowed_in_all_scopes(perm);
    }
    let scopes = scopes_of(t);
    !scopes.is_empty() && scopes.into_iter().all(|s| p.allowed(perm, s))
}

fn place(scope: Option<&str>) -> String {
    match scope {
        Some(s) => format!(" in scope {s}"),
        None => " globally".into(),
    }
}

fn scoped_part(platform: &Platform, perms: &PermSet) -> PermSet {
    perms
        .iter()
        .filter(|p| !platform.policy().catalog().is_global_only(p))
        .cloned()
        .collect()
}

/// The first permission of a role that the caller does not hold in `scope` (globally for `None`).
fn missing_for_role(
    platform: &Platform,
    p: &Principal,
    perms: &PermSet,
    scope: Option<&str>,
) -> Option<Permission> {
    match scope {
        None => perms.iter().find(|x| !p.perms.allowed_globally(x)).cloned(),
        Some(s) => {
            let held = p.perms.in_scope(s);
            scoped_part(platform, perms)
                .into_iter()
                .find(|x| !held.contains(x))
        }
    }
}

/// What a `*` token needs: `tokens:write` and every scoped permission of the role, each held
/// globally or through the caller's own `*` grant.
fn missing_in_all_scopes(
    platform: &Platform,
    p: &Principal,
    perms: &PermSet,
) -> Option<Permission> {
    let write = platform.permission(TOKENS_WRITE);
    std::iter::once(write)
        .chain(scoped_part(platform, perms))
        .find(|x| !p.perms.allowed_in_all_scopes(x))
}

fn require_all_scopes(p: &Principal, perm: &Permission) -> ApiResult<()> {
    if p.perms.allowed_in_all_scopes(perm) {
        return Ok(());
    }
    Err(deny(
        p,
        &format!("requires permission {perm} in all scopes (globally or through scopes: [\"*\"])"),
        perm,
        None,
    ))
}

async fn visible_scope(platform: &Platform, p: &Principal, key: &str) -> ApiResult<()> {
    let exists = platform.scopes().exists(key).await?;
    if !exists || !p.perms.sees_scope(key) {
        return Err(ApiError::not_found("scope"));
    }
    Ok(())
}

fn token_detail(t: &ApiToken) -> serde_json::Value {
    json!({
        "id": t.id,
        "name": t.name,
        "kind": PrincipalKind::ApiToken.as_str(),
        "role": t.role,
        "global": t.global,
        "scopes": t.scopes,
        "expiresAt": stored_precision(t.expires_at),
    })
}

fn audit_scope(t: &ApiToken) -> Option<&str> {
    match t.scopes.as_slice() {
        [one] if !t.global && one != ALL_SCOPES => Some(one.as_str()),
        _ => None,
    }
}

async fn create_token<S: PlatformState>(
    State(state): State<S>,
    auth: Auth,
    ApiJson(body): ApiJson<CreateToken>,
) -> ApiResult<(StatusCode, ApiJson<CreatedToken>)> {
    let platform = state.platform();
    let svc = svc(platform)?;
    let p = &auth.principal;
    let name = body.name.trim().to_string();
    if !valid_name(&name) {
        return Err(ApiError::bad_request(format!(
            "name must be 1..{MAX_NAME} characters of [A-Za-z0-9._@-]"
        )));
    }
    let perms = platform
        .policy()
        .role(&body.role)
        .map(|r| r.permissions.clone())
        .ok_or_else(|| ApiError::bad_request(format!("unknown role `{}`", body.role)))?;
    let scopes = Scopes::from_parts(body.scopes, body.global.unwrap_or(false))
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    match &scopes {
        Scopes::All => match missing_in_all_scopes(platform, p, &perms) {
            None => {}
            Some(m) if m.as_str() == TOKENS_WRITE => require_all_scopes(p, &m)?,
            Some(m) => {
                return Err(deny(
                    p,
                    &format!(
                        "requires permission {m} in all scopes (globally or through scopes: [\"*\"]) to grant role {} there",
                        body.role
                    ),
                    &m,
                    None,
                ));
            }
        },
        Scopes::Global | Scopes::List(_) => {
            let list: Vec<Option<&str>> = match &scopes {
                Scopes::List(l) => l.iter().map(|s| Some(s.as_str())).collect(),
                _ => vec![None],
            };
            for key in list.iter().flatten() {
                visible_scope(platform, p, key).await?;
            }
            let write = platform.permission(TOKENS_WRITE);
            for s in list {
                require(p, &write, s)?;
                if let Some(m) = missing_for_role(platform, p, &perms, s) {
                    return Err(deny(
                        p,
                        &format!(
                            "requires permission {m}{} to grant role {} there",
                            place(s),
                            body.role
                        ),
                        &m,
                        s,
                    ));
                }
            }
        }
    }
    let max = platform.settings().token_max_days;
    let days = body.expires_in_days.unwrap_or(DEFAULT_TOKEN_DAYS.min(max));
    if days == 0 || days > max {
        return Err(ApiError::bad_request(format!(
            "expiresInDays must be between 1 and {max}"
        )));
    }
    let description = body
        .description
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty());
    if description
        .as_ref()
        .is_some_and(|d| d.len() > MAX_DESCRIPTION || d.chars().any(char::is_control))
    {
        return Err(ApiError::bad_request(format!(
            "description is limited to {MAX_DESCRIPTION} bytes without control characters"
        )));
    }
    if platform.static_tokens().has_name(&name) {
        return Err(ApiError::conflict(format!(
            "name {name} belongs to a static token"
        )));
    }
    let now = stored_precision(Utc::now());
    let mut expires_at = now + chrono::Duration::days(i64::from(days));
    if let Some(parent) = p.token_id {
        let pt = svc
            .store()
            .get(parent)
            .await?
            .filter(|t| t.status(now) == TokenStatus::Active)
            .ok_or_else(ApiError::unauthorized)?;
        expires_at = expires_at.min(pt.expires_at);
    }
    let value = svc.format().generate();
    let (global, keys) = match &scopes {
        Scopes::Global => (true, vec![]),
        other => (false, other.keys()),
    };
    let t = ApiToken {
        id: Uuid::now_v7(),
        name,
        sha256: hash_token(value.expose()),
        role: body.role,
        scopes: keys,
        global,
        description,
        created_by: p.name.clone(),
        created_at: now,
        expires_at,
        last_used_at: None,
        revoked_at: None,
        revoked: false,
        parent_id: p.token_id,
    };
    if !svc.store().create(&t, now).await? {
        return Err(ApiError::conflict(format!(
            "an active token named {} exists",
            t.name
        )));
    }
    svc.forget(&t.sha256);
    svc.note_created();
    platform
        .audit(AuditEvent::new(
            p,
            "token.create",
            audit_scope(&t),
            token_detail(&t),
        ))
        .await;
    platform.refresh_gauge().await;
    Ok((
        StatusCode::CREATED,
        ApiJson(CreatedToken {
            token: value.expose().to_string(),
            info: TokenInfo::of(&t),
        }),
    ))
}

async fn list_tokens<S: PlatformState>(
    State(state): State<S>,
    auth: Auth,
    Query(q): Query<TokensQuery>,
) -> ApiResult<ApiJson<TokenList>> {
    let platform = state.platform();
    let svc = svc(platform)?;
    let p = &auth.principal;
    let read = platform.permission(TOKENS_READ);
    let status = match q.status.as_deref() {
        None => None,
        Some("active") => Some(TokenStatus::Active),
        Some("expired") => Some(TokenStatus::Expired),
        Some("revoked") => Some(TokenStatus::Revoked),
        Some(_) => {
            return Err(ApiError::bad_request(
                "status must be active, expired or revoked",
            ));
        }
    };
    match &q.scope {
        Some(s) => {
            visible_scope(platform, p, s).await?;
            require(p, &read, Some(s))?;
        }
        None if !p.perms.anywhere(&read) => require(p, &read, None)?,
        None => {}
    }
    let now = Utc::now();
    let tokens = svc
        .store()
        .list()
        .await?
        .iter()
        .filter(|t| holds_everywhere(p, &read, t))
        .filter(|t| status.is_none_or(|s| t.status(now) == s))
        .filter(|t| {
            q.scope
                .as_ref()
                .is_none_or(|s| !t.global && (is_all_scopes(t) || t.scopes.contains(s)))
        })
        .map(TokenInfo::of)
        .collect();
    Ok(ApiJson(TokenList { tokens }))
}

async fn own_token<S: PlatformState>(
    State(state): State<S>,
    auth: Auth,
) -> ApiResult<ApiJson<TokenInfo>> {
    let svc = svc(state.platform())?;
    let id = auth
        .principal
        .token_id
        .ok_or_else(|| ApiError::not_found("token"))?;
    let t = svc
        .store()
        .get(id)
        .await?
        .ok_or_else(|| ApiError::not_found("token"))?;
    Ok(ApiJson(TokenInfo::of(&t)))
}

async fn get_token<S: PlatformState>(
    State(state): State<S>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<ApiJson<TokenInfo>> {
    let platform = state.platform();
    let svc = svc(platform)?;
    let p = &auth.principal;
    let read = platform.permission(TOKENS_READ);
    let t = svc
        .store()
        .get(id)
        .await?
        .filter(|t| p.token_id == Some(t.id) || holds_everywhere(p, &read, t))
        .ok_or_else(|| ApiError::not_found("token"))?;
    Ok(ApiJson(TokenInfo::of(&t)))
}

async fn revoke_descendants(
    svc: &TokenService,
    root: Uuid,
    at: DateTime<Utc>,
) -> ApiResult<Vec<Uuid>> {
    let all = svc.store().list().await?;
    let mut frontier = vec![root];
    let mut seen: BTreeSet<Uuid> = BTreeSet::from([root]);
    let mut revoked = Vec::new();
    while let Some(parent) = frontier.pop() {
        for t in all.iter().filter(|t| t.parent_id == Some(parent)) {
            if !seen.insert(t.id) {
                continue;
            }
            if svc.store().revoke(t.id, at).await? {
                svc.forget(&t.sha256);
                revoked.push(t.id);
            }
            frontier.push(t.id);
        }
    }
    Ok(revoked)
}

async fn revoke_token<S: PlatformState>(
    State(state): State<S>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<ApiJson<TokenInfo>> {
    let platform = state.platform();
    let svc = svc(platform)?;
    let p = &auth.principal;
    let read = platform.permission(TOKENS_READ);
    let write = platform.permission(TOKENS_WRITE);
    let own = p.token_id == Some(id);
    if !own && !p.perms.anywhere(&write) {
        require(p, &write, None)?;
    }
    let t = svc
        .store()
        .get(id)
        .await?
        .ok_or_else(|| ApiError::not_found("token"))?;
    if !own {
        if !holds_everywhere(p, &read, &t) && !holds_everywhere(p, &write, &t) {
            return Err(ApiError::not_found("token"));
        }
        if is_all_scopes(&t) {
            require_all_scopes(p, &write)?;
        } else {
            for s in scopes_of(&t) {
                require(p, &write, s)?;
            }
        }
    }
    let now = stored_precision(Utc::now());
    let revoked = svc.store().revoke(id, now).await?;
    svc.forget(&t.sha256);
    let t = svc
        .store()
        .get(id)
        .await?
        .ok_or_else(|| ApiError::not_found("token"))?;
    if revoked {
        let children = revoke_descendants(svc, id, now).await?;
        let mut detail = token_detail(&t);
        detail["self"] = json!(own);
        if !children.is_empty() {
            detail["revokedChildren"] = json!(children);
        }
        platform
            .audit(AuditEvent::new(p, "token.revoke", audit_scope(&t), detail))
            .await;
        platform.refresh_gauge().await;
    }
    Ok(ApiJson(TokenInfo::of(&t)))
}

async fn token_options<S: PlatformState>(
    State(state): State<S>,
    auth: Auth,
) -> ApiResult<ApiJson<TokenOptions>> {
    let platform = state.platform();
    svc(platform)?;
    let p = &auth.principal;
    let write = platform.permission(TOKENS_WRITE);
    if !p.perms.anywhere(&write) {
        require(p, &write, None)?;
    }
    let scopes: Vec<String> = platform
        .scopes()
        .list()
        .await?
        .into_iter()
        .filter(|s| p.perms.sees_scope(s))
        .collect();
    let roles = platform
        .policy()
        .roles()
        .map(|r| {
            let grantable = |s: Option<&str>| {
                p.allowed(&write, s) && missing_for_role(platform, p, &r.permissions, s).is_none()
            };
            GrantableRole {
                name: r.name.clone(),
                builtin: r.builtin,
                description: r.description.clone(),
                permissions: r
                    .permissions
                    .iter()
                    .map(|x| x.as_str().to_string())
                    .collect(),
                global: grantable(None),
                scopes: scopes
                    .iter()
                    .filter(|s| grantable(Some(s)))
                    .cloned()
                    .collect(),
                all_scopes: missing_in_all_scopes(platform, p, &r.permissions).is_none(),
            }
        })
        .collect();
    let max_days = platform.settings().token_max_days;
    Ok(ApiJson(TokenOptions {
        max_days,
        default_days: DEFAULT_TOKEN_DAYS.min(max_days),
        scopes,
        roles,
    }))
}

/// The platform routes: `GET /api/v1/me`, and the managed tokens API: `GET|POST /api/v1/tokens`,
/// `GET /api/v1/tokens/options`, `GET /api/v1/tokens/self`, `GET|DELETE /api/v1/tokens/{id}`.
/// The tokens API answers 404 when managed tokens are not configured.
pub fn routes<S: PlatformState>() -> Router<S> {
    Router::new()
        .route("/api/v1/me", get(me))
        .route(
            "/api/v1/tokens",
            get(list_tokens::<S>).post(create_token::<S>),
        )
        .route("/api/v1/tokens/options", get(token_options::<S>))
        .route("/api/v1/tokens/self", get(own_token::<S>))
        .route(
            "/api/v1/tokens/{id}",
            get(get_token::<S>).delete(revoke_token::<S>),
        )
}
