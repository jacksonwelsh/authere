//! SCIM `/Users` handlers — list + get only at this stage. POST/PUT/PATCH/DELETE land in the
//! follow-up change together with the PATCH operation applicator.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, header};
use serde::Deserialize;
use uuid::Uuid;

use crate::AppState;
use crate::db::DbEntity;
use crate::scim::auth::ScimAuth;
use crate::scim::error::ScimError;
use crate::scim::filter;
use crate::scim::schema::{ListResponse, ScimJson, ScimUser, weak_etag};
use crate::user::User;

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
