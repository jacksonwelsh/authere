//! SCIM `/Users` handlers — list, get, create, replace, patch, delete.
//!
//! All write paths audit via the acting SCIM token (`ScimAuth.token`) so mutations are
//! attributable per-IdP. Deactivation (`active: true → false`) additionally calls
//! `revoke_all_user_tokens` so existing JWT sessions terminate immediately.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::Deserialize;
use uuid::Uuid;

use crate::AppState;
use crate::audit::{
    log_scim_user_created, log_scim_user_deactivated, log_scim_user_deleted,
    log_scim_user_reactivated, log_scim_user_updated,
};
use crate::db::DbEntity;
use crate::errors::AppError;
use crate::scim::auth::ScimAuth;
use crate::scim::error::ScimError;
use crate::scim::filter;
use crate::scim::patch::{self, PatchOp};
use crate::scim::schema::{ListResponse, ScimJson, ScimUser, weak_etag};
use crate::user::{CreateUserInput, User};
use crate::user::auth::token::revoke_all_user_tokens;

const TAG: &str = "scim";

/// Upper bound on `count`. Above this we either cap (SCIM §3.4.2) or return `tooMany`. We
/// cap — clients that actually want everything can page.
const MAX_PAGE_SIZE: usize = 200;
const DEFAULT_PAGE_SIZE: usize = 100;

#[derive(Debug, Deserialize, Default)]
pub struct ListUsersQuery {
    /// SCIM filter expression. Parsed by `scim::filter`. Absent → no filter.
    #[serde(default)]
    pub filter: Option<String>,
    /// 1-based. SCIM clients expect 1-based indexing; 0 or missing → 1.
    #[serde(rename = "startIndex", default)]
    pub start_index: Option<usize>,
    /// Page size. Absent → [`DEFAULT_PAGE_SIZE`]. Above [`MAX_PAGE_SIZE`] clamps to max.
    #[serde(default)]
    pub count: Option<usize>,
}

#[utoipa::path(
    get,
    path = "/scim/v2/Users",
    params(
        ("filter" = Option<String>, Query, description = "SCIM filter expression, e.g. userName eq \"alice\""),
        ("startIndex" = Option<usize>, Query, description = "1-based page offset (default 1)"),
        ("count" = Option<usize>, Query, description = "Page size (default 100, max 200)"),
    ),
    responses(
        (status = 200, description = "SCIM ListResponse of matching users"),
        (status = 400, description = "Invalid filter"),
        (status = 401, description = "Authentication required"),
    ),
    tag = TAG,
)]
pub async fn list_users(
    State(state): State<AppState>,
    _auth: ScimAuth,
    Query(q): Query<ListUsersQuery>,
) -> Result<ScimJson<ListResponse<ScimUser>>, ScimError> {
    let start_index = q.start_index.unwrap_or(1).max(1);
    let count = q.count.unwrap_or(DEFAULT_PAGE_SIZE).min(MAX_PAGE_SIZE);
    let offset = start_index - 1;

    let mut total_qb: sqlx::QueryBuilder<sqlx::Sqlite> =
        sqlx::QueryBuilder::new("SELECT COUNT(*) FROM users");
    let mut data_qb: sqlx::QueryBuilder<sqlx::Sqlite> = sqlx::QueryBuilder::new(
        "SELECT id, username, name, email, active, external_id, created_at, updated_at FROM users",
    );

    if let Some(ref raw) = q.filter {
        let expr = filter::parse(raw)?;
        total_qb.push(" WHERE ");
        filter::compile(&expr, &mut total_qb)?;
        data_qb.push(" WHERE ");
        filter::compile(&expr, &mut data_qb)?;
    }

    // Stable pagination: order by created_at then id so duplicates at the same epoch don't
    // flap across pages.
    data_qb.push(" ORDER BY created_at ASC, id ASC LIMIT ");
    data_qb.push_bind(count as i64);
    data_qb.push(" OFFSET ");
    data_qb.push_bind(offset as i64);

    let mut conn = state.db_pool.acquire().await.map_err(ScimError::from_sqlx)?;

    let total: i64 = total_qb
        .build_query_scalar()
        .fetch_one(&mut *conn)
        .await
        .map_err(ScimError::from_sqlx)?;

    let rows: Vec<UserRow> = data_qb
        .build_query_as::<UserRow>()
        .fetch_all(&mut *conn)
        .await
        .map_err(ScimError::from_sqlx)?;

    let resources: Vec<ScimUser> = rows
        .into_iter()
        .map(|r| ScimUser::from_user(&r.into(), &state.origin))
        .collect();

    Ok(ScimJson::new(ListResponse::new(
        resources,
        total.max(0) as usize,
        start_index,
    )))
}

#[utoipa::path(
    get,
    path = "/scim/v2/Users/{id}",
    params(("id" = Uuid, Path, description = "User id")),
    responses(
        (status = 200, description = "SCIM User resource"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "User not found"),
    ),
    tag = TAG,
)]
pub async fn get_user(
    State(state): State<AppState>,
    _auth: ScimAuth,
    Path(id): Path<Uuid>,
) -> Result<ScimJson<ScimUser>, ScimError> {
    let mut conn = state.db_pool.acquire().await.map_err(ScimError::from_sqlx)?;
    let user = User::get(id, &mut conn).await?.ok_or_else(ScimError::not_found)?;
    let etag = HeaderValue::from_str(&weak_etag(user.updated_at))
        .map_err(|e| ScimError::internal(format!("bad etag: {e}")))?;
    let body = ScimUser::from_user(&user, &state.origin);
    Ok(ScimJson::new(body).header(header::ETAG, etag))
}

// Row struct for the dynamic list query. We hand-roll rather than `query_as!` so we can use
// QueryBuilder (filter composition requires dynamic SQL).
#[derive(sqlx::FromRow)]
struct UserRow {
    id: Uuid,
    username: String,
    name: String,
    email: Option<String>,
    active: bool,
    external_id: Option<String>,
    created_at: i64,
    updated_at: i64,
}

impl From<UserRow> for User {
    fn from(r: UserRow) -> Self {
        User {
            id: r.id,
            username: r.username,
            name: r.name,
            email: r.email,
            active: r.active,
            external_id: r.external_id,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

impl ScimError {
    /// Bridge sqlx errors without losing context. `AppError`'s generic conversion is fine but
    /// we lose the sqlx detail in tracing; this keeps the warning local to this module.
    fn from_sqlx(e: sqlx::Error) -> Self {
        tracing::error!(error = %e, "scim users sqlx error");
        Self::internal("database error")
    }
}

// ============================================================================
// Write handlers: create, replace, patch, delete
// ============================================================================

/// Validate the SCIM user payload and project it onto Authere's `User` validators. We reuse
/// the existing validators (userName, name length, email format) so SCIM and internal APIs
/// stay consistent on what counts as a valid identity.
fn validate_scim_user_fields(
    user_name: &str,
    display_name: &str,
    email: &Option<String>,
) -> Result<(), ScimError> {
    let mut errs = Vec::new();
    if let Err(e) = User::validate_username(user_name) {
        errs.push(e);
    }
    if let Err(e) = User::validate_name(display_name) {
        errs.push(e);
    }
    if let Err(e) = User::validate_email(email) {
        errs.push(e);
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(ScimError::invalid_value(errs.join("; ")))
    }
}

/// Case-insensitive pre-INSERT dup check. SCIM §4.1.1 mandates case-insensitive userName
/// uniqueness; Authere's schema enforces case-sensitive uniqueness, so we add this check
/// in-transaction to avoid surfacing "Alice" + "alice" as distinct accounts.
async fn ensure_username_unique(
    username: &str,
    exclude_id: Option<Uuid>,
    conn: &mut sqlx::SqliteConnection,
) -> Result<(), ScimError> {
    let existing = User::get_by_username_ci(username, conn).await?;
    if let Some(existing_user) = existing {
        if Some(existing_user.id) != exclude_id {
            return Err(ScimError::unique(format!(
                "a user with userName '{username}' already exists"
            )));
        }
    }
    Ok(())
}

/// Compare `If-Match` header (if present) against the current weak ETag for the user. 412
/// on mismatch. Absent header → OK (not all clients send it).
fn check_if_match(headers: &HeaderMap, current_version: &str) -> Result<(), ScimError> {
    let Some(h) = headers.get(header::IF_MATCH) else {
        return Ok(());
    };
    let expected = h
        .to_str()
        .map_err(|_| ScimError::invalid_syntax("If-Match header is not UTF-8"))?
        .trim();
    if expected == "*" {
        return Ok(());
    }
    if expected != current_version {
        return Err(ScimError::precondition_failed());
    }
    Ok(())
}

fn parse_if_match(headers: &HeaderMap) -> Result<Option<String>, ScimError> {
    headers
        .get(header::IF_MATCH)
        .map(|h| {
            h.to_str()
                .map(|s| s.trim().to_string())
                .map_err(|_| ScimError::invalid_syntax("If-Match header is not UTF-8"))
        })
        .transpose()
}

fn location_header(state: &AppState, id: Uuid) -> Result<HeaderValue, ScimError> {
    HeaderValue::from_str(&format!(
        "{}/scim/v2/Users/{}",
        state.origin.trim_end_matches('/'),
        id
    ))
    .map_err(|e| ScimError::internal(format!("bad location: {e}")))
}

#[utoipa::path(
    post,
    path = "/scim/v2/Users",
    request_body = serde_json::Value,
    responses(
        (status = 201, description = "Created"),
        (status = 400, description = "Invalid body"),
        (status = 401, description = "Authentication required"),
        (status = 409, description = "userName or externalId already taken"),
    ),
    tag = TAG,
)]
pub async fn create_user(
    State(state): State<AppState>,
    auth: ScimAuth,
    Json(body): Json<ScimUser>,
) -> Result<ScimJson<ScimUser>, ScimError> {
    let display = body
        .resolve_display_name()
        .ok_or_else(|| ScimError::invalid_value("name.formatted, displayName, or name.givenName/familyName is required"))?;
    let email = body.resolve_email();
    validate_scim_user_fields(&body.user_name, &display, &email)?;

    let mut tx = state.db_pool.begin().await.map_err(AppError::from)?;

    ensure_username_unique(&body.user_name, None, &mut tx).await?;

    let mut user = User::new(body.user_name.clone(), display, email);
    user.active = body.active;
    user.external_id = body.external_id.clone();
    user.save(&mut tx).await?;

    tx.commit().await.map_err(AppError::from)?;

    let mut conn = state.db_pool.acquire().await.map_err(AppError::from)?;
    let _ = log_scim_user_created(
        user.id,
        auth.token.id,
        &auth.token.name,
        &auth.audit,
        &mut conn,
    )
    .await;

    let loc = location_header(&state, user.id)?;
    let etag = HeaderValue::from_str(&weak_etag(user.updated_at))
        .map_err(|e| ScimError::internal(format!("bad etag: {e}")))?;
    let resource = ScimUser::from_user(&user, &state.origin);

    Ok(ScimJson::new(resource)
        .status(StatusCode::CREATED)
        .header(header::LOCATION, loc)
        .header(header::ETAG, etag))
}

/// Apply a fresh ScimUser image onto the stored `User`, persisting each change and handling
/// active transitions (revoke tokens on deactivation). Returns whether the active flag changed
/// and, if so, which direction — so the caller can pick the right audit event.
async fn persist_scim_changes(
    user: &mut User,
    new_username: String,
    new_display: String,
    new_email: Option<String>,
    new_active: bool,
    new_external_id: Option<String>,
    conn: &mut sqlx::SqliteConnection,
) -> Result<ActiveTransition, ScimError> {
    validate_scim_user_fields(&new_username, &new_display, &new_email)?;

    let username_changed = new_username != user.username;
    let need_profile_update =
        username_changed || new_display != user.name || new_email != user.email;

    if username_changed {
        ensure_username_unique(&new_username, Some(user.id), conn).await?;
    }

    if need_profile_update {
        user.update(
            Some(new_display),
            Some(new_email),
            Some(new_username),
            conn,
        )
        .await?;
    }

    if user.external_id != new_external_id {
        user.set_external_id(new_external_id, conn).await?;
    }

    let transition = if new_active == user.active {
        ActiveTransition::Unchanged
    } else if new_active {
        ActiveTransition::Reactivated
    } else {
        ActiveTransition::Deactivated
    };

    if matches!(
        transition,
        ActiveTransition::Deactivated | ActiveTransition::Reactivated
    ) {
        user.set_active(new_active, conn).await?;
    }

    if matches!(transition, ActiveTransition::Deactivated) {
        revoke_all_user_tokens(user.id, conn).await?;
    }

    Ok(transition)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTransition {
    Unchanged,
    Deactivated,
    Reactivated,
}

async fn audit_transition(
    user_id: Uuid,
    auth: &ScimAuth,
    transition: ActiveTransition,
    conn: &mut sqlx::SqliteConnection,
) {
    match transition {
        ActiveTransition::Unchanged => {
            let _ = log_scim_user_updated(
                user_id,
                auth.token.id,
                &auth.token.name,
                None,
                &auth.audit,
                conn,
            )
            .await;
        }
        ActiveTransition::Deactivated => {
            let _ = log_scim_user_deactivated(
                user_id,
                auth.token.id,
                &auth.token.name,
                &auth.audit,
                conn,
            )
            .await;
        }
        ActiveTransition::Reactivated => {
            let _ = log_scim_user_reactivated(
                user_id,
                auth.token.id,
                &auth.token.name,
                &auth.audit,
                conn,
            )
            .await;
        }
    }
}

#[utoipa::path(
    put,
    path = "/scim/v2/Users/{id}",
    params(("id" = Uuid, Path, description = "User id")),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Replaced"),
        (status = 400, description = "Invalid body"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "User not found"),
        (status = 409, description = "userName or externalId already taken"),
        (status = 412, description = "If-Match version mismatch"),
    ),
    tag = TAG,
)]
pub async fn replace_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: ScimAuth,
    headers: HeaderMap,
    Json(body): Json<ScimUser>,
) -> Result<ScimJson<ScimUser>, ScimError> {
    let mut conn = state.db_pool.acquire().await.map_err(AppError::from)?;
    let mut user = User::get(id, &mut conn).await?.ok_or_else(ScimError::not_found)?;

    check_if_match(&headers, &weak_etag(user.updated_at))?;

    let new_display = body
        .resolve_display_name()
        .ok_or_else(|| ScimError::invalid_value("a resolvable name is required"))?;
    let new_email = body.resolve_email();

    let transition = persist_scim_changes(
        &mut user,
        body.user_name.clone(),
        new_display,
        new_email,
        body.active,
        body.external_id.clone(),
        &mut conn,
    )
    .await?;

    audit_transition(user.id, &auth, transition, &mut conn).await;

    let etag = HeaderValue::from_str(&weak_etag(user.updated_at))
        .map_err(|e| ScimError::internal(format!("bad etag: {e}")))?;
    Ok(ScimJson::new(ScimUser::from_user(&user, &state.origin)).header(header::ETAG, etag))
}

#[utoipa::path(
    patch,
    path = "/scim/v2/Users/{id}",
    params(("id" = Uuid, Path, description = "User id")),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Patched"),
        (status = 400, description = "Invalid PATCH operation"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "User not found"),
        (status = 412, description = "If-Match version mismatch"),
    ),
    tag = TAG,
)]
pub async fn patch_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: ScimAuth,
    headers: HeaderMap,
    Json(body): Json<PatchOp>,
) -> Result<ScimJson<ScimUser>, ScimError> {
    body.validate_schema()?;

    let _if_match = parse_if_match(&headers)?;

    let mut conn = state.db_pool.acquire().await.map_err(AppError::from)?;
    let mut user = User::get(id, &mut conn).await?.ok_or_else(ScimError::not_found)?;
    check_if_match(&headers, &weak_etag(user.updated_at))?;

    // Apply ops against an in-memory SCIM view of the user. If any op fails, we abort
    // without touching the DB.
    let mut working = ScimUser::from_user(&user, &state.origin);
    patch::apply_all(&mut working, &body.operations)?;

    let new_display = working
        .resolve_display_name()
        .ok_or_else(|| ScimError::invalid_value("a resolvable name is required"))?;
    let new_email = working.resolve_email();

    let transition = persist_scim_changes(
        &mut user,
        working.user_name.clone(),
        new_display,
        new_email,
        working.active,
        working.external_id.clone(),
        &mut conn,
    )
    .await?;

    audit_transition(user.id, &auth, transition, &mut conn).await;

    let etag = HeaderValue::from_str(&weak_etag(user.updated_at))
        .map_err(|e| ScimError::internal(format!("bad etag: {e}")))?;
    Ok(ScimJson::new(ScimUser::from_user(&user, &state.origin)).header(header::ETAG, etag))
}

#[utoipa::path(
    delete,
    path = "/scim/v2/Users/{id}",
    params(("id" = Uuid, Path, description = "User id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "User not found"),
    ),
    tag = TAG,
)]
pub async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: ScimAuth,
) -> Result<StatusCode, ScimError> {
    let mut conn = state.db_pool.acquire().await.map_err(AppError::from)?;
    let deleted = User::delete(id, &mut conn).await?;
    if !deleted {
        return Err(ScimError::not_found());
    }
    let _ = log_scim_user_deleted(
        id,
        auth.token.id,
        &auth.token.name,
        &auth.audit,
        &mut conn,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// Silence an unused-import warning on CreateUserInput — it's part of the public surface but
// not directly used in this module. (The input type is the JSON body which we parse via
// ScimUser directly.)
#[allow(dead_code)]
fn _uses_create_user_input(_: CreateUserInput) {}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("../migrations").run(&pool).await.unwrap();
        pool
    }

    async fn insert_user(pool: &SqlitePool, u: &User) {
        let mut conn = pool.acquire().await.unwrap();
        u.save(&mut conn).await.unwrap();
    }

    #[tokio::test]
    async fn filter_compile_runs_against_real_db() {
        // Direct DB exercise: ensure the filter parser's output actually executes on SQLite
        // (no dialect mismatches) end-to-end. We don't need the full handler machinery for this.
        let pool = pool().await;
        let mut u1 = User::new("alice".into(), "Alice".into(), Some("alice@example.com".into()));
        u1.external_id = Some("okta-1".into());
        insert_user(&pool, &u1).await;

        let mut u2 = User::new("bob".into(), "Bob".into(), Some("bob@example.com".into()));
        u2.external_id = Some("okta-2".into());
        insert_user(&pool, &u2).await;

        let cases = [
            (r#"userName eq "alice""#, 1usize),
            (r#"userName eq "ALICE""#, 1), // case-insensitive
            (r#"userName eq "alice" or userName eq "bob""#, 2),
            (r#"externalId eq "okta-1""#, 1),
            (r#"externalId pr"#, 2),
            (r#"active eq true"#, 2),
            (r#"active eq false"#, 0),
            (r#"userName sw "a""#, 1),
            (r#"userName co "li""#, 1),
            (r#"not (userName eq "alice")"#, 1),
        ];

        for (filter_str, expected) in cases {
            let expr = filter::parse(filter_str).unwrap();
            let mut qb: sqlx::QueryBuilder<sqlx::Sqlite> =
                sqlx::QueryBuilder::new("SELECT COUNT(*) FROM users WHERE ");
            filter::compile(&expr, &mut qb).unwrap();
            let count: i64 = qb
                .build_query_scalar()
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("query failed for filter {filter_str}: {e}"));
            assert_eq!(
                count as usize, expected,
                "filter {filter_str} returned {count}, expected {expected}"
            );
        }
    }

    #[tokio::test]
    async fn get_user_returns_none_for_missing() {
        let pool = pool().await;
        let mut conn = pool.acquire().await.unwrap();
        assert!(User::get(Uuid::now_v7(), &mut conn).await.unwrap().is_none());
    }

    #[test]
    fn default_page_size_sensible() {
        assert!(DEFAULT_PAGE_SIZE <= MAX_PAGE_SIZE);
        assert!(DEFAULT_PAGE_SIZE > 0);
    }

    #[test]
    fn list_query_defaults_are_sensible() {
        let q: ListUsersQuery = ListUsersQuery::default();
        assert!(q.filter.is_none());
        assert!(q.start_index.is_none());
        assert!(q.count.is_none());
    }
}
