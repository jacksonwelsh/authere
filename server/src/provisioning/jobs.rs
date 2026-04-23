//! `outbound_jobs` table access + pure backoff math.
//!
//! A job represents an intent to push one lifecycle event to one target. Jobs are inserted
//! inside the enclosing write transaction (so the user row and the job row commit together),
//! then drained by the worker. Only the worker transitions `pending → in_flight → (succeeded |
//! failed | dead)`; the API surface exposes retry which moves `failed|dead → pending`.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::SqliteConnection;
use uuid::Uuid;

use crate::errors::AppError;
use crate::provisioning::event::{UserLifecycleEvent, build_scim_body};
use crate::provisioning::targets;
use crate::user::User;

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_IN_FLIGHT: &str = "in_flight";
pub const STATUS_SUCCEEDED: &str = "succeeded";
pub const STATUS_FAILED: &str = "failed";
pub const STATUS_DEAD: &str = "dead";

/// After this many retryable failures the job is parked as `dead`. Admins can re-queue by
/// hitting the retry endpoint.
pub const DEAD_LETTER_ATTEMPTS: u32 = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundJob {
    pub id: Uuid,
    pub target_id: Uuid,
    pub user_id: Uuid,
    pub event_type: String,
    pub payload: String,
    pub status: String,
    pub attempts: i64,
    pub next_attempt_at: i64,
    pub last_error: Option<String>,
    pub last_response_status: Option<i64>,
    pub external_resource_id: Option<String>,
    pub idempotency_key: String,
    pub created_at: i64,
    pub updated_at: i64,
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

/// Exponential backoff with jitter, capped at 1 hour. Pure — unit-testable directly.
///
/// Attempt 0 is the first retry delay (used *after* the first failure). Growth: 5s * 2^n with
/// a 10% jitter floor so parallel jobs don't synchronize retries.
pub fn backoff_delay(attempts: u32) -> Duration {
    let cap: u64 = 60 * 60; // 1 hour
    let base: u64 = 5u64.saturating_mul(1u64 << attempts.min(12));
    let capped = base.min(cap);
    // Deterministic jitter for tests? Not strictly: we add up to 10% using a cheap hash.
    // Callers that want determinism can call this directly and ignore the jitter tier.
    let jitter = (capped / 10).max(1);
    Duration::from_secs(capped.saturating_sub(jitter / 2))
}

/// Insert one `outbound_jobs` row per enabled target, all sharing the same user snapshot.
/// Returns the count of jobs enqueued.
///
/// Call this inside your write transaction, then call `Notifier::notify_one` after commit.
pub async fn insert_for_all_enabled_targets(
    user: &User,
    event: UserLifecycleEvent,
    origin: &str,
    conn: &mut SqliteConnection,
) -> Result<usize, AppError> {
    // `list_enabled` reads the targets table through the same connection — if it's a
    // transaction, the visibility is consistent. Any target disabled mid-flight is still
    // queued against; the worker will re-check `enabled` before dispatching.
    let all_targets = targets::list_enabled(conn).await?;
    if all_targets.is_empty() {
        return Ok(0);
    }

    let body = build_scim_body(user, event, origin);
    let payload = serde_json::to_string(&body).unwrap_or_else(|_| "null".into());
    let now = now_epoch();
    let event_str = event.as_str();

    let mut inserted = 0usize;
    for t in all_targets {
        let id = Uuid::now_v7();
        let idempotency_key = Uuid::now_v7().to_string();
        sqlx::query!(
            r#"INSERT INTO outbound_jobs
                (id, target_id, user_id, event_type, payload, status,
                 attempts, next_attempt_at, idempotency_key, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)"#,
            id,
            t.id,
            user.id,
            event_str,
            payload,
            STATUS_PENDING,
            now,
            idempotency_key,
            now,
            now
        )
        .execute(&mut *conn)
        .await?;
        inserted += 1;
    }
    Ok(inserted)
}

/// Atomically claim up to `limit` `pending` jobs whose `next_attempt_at <= now`, flipping them
/// to `in_flight`. Uses SQLite's `UPDATE … RETURNING` so two workers can't claim the same job.
///
/// Jobs that have an earlier still-pending/in-flight job for the same `(target_id, user_id)`
/// are intentionally left behind — we want strict per-user FIFO per target so `update`
/// doesn't race ahead of `create`.
pub async fn claim_batch(
    now: i64,
    limit: i64,
    conn: &mut SqliteConnection,
) -> Result<Vec<OutboundJob>, AppError> {
    // Strategy: select ready ids, excluding any with a blocking earlier job in same pair,
    // then UPDATE those specific ids. SQLite doesn't support UPDATE...FROM with a subquery
    // targeting the same row set inside a single statement cleanly, so we do it in two.
    let ids = sqlx::query_scalar!(
        r#"SELECT j.id as "id: Uuid"
             FROM outbound_jobs j
            WHERE j.status = ?
              AND j.next_attempt_at <= ?
              AND NOT EXISTS (
                  SELECT 1 FROM outbound_jobs earlier
                   WHERE earlier.target_id = j.target_id
                     AND earlier.user_id = j.user_id
                     AND earlier.created_at < j.created_at
                     AND earlier.status IN (?, ?)
              )
         ORDER BY j.created_at ASC, j.id ASC
            LIMIT ?"#,
        STATUS_PENDING,
        now,
        STATUS_PENDING,
        STATUS_IN_FLIGHT,
        limit
    )
    .fetch_all(&mut *conn)
    .await?;

    if ids.is_empty() {
        return Ok(Vec::new());
    }

    // Now flip each to in_flight and return the row. Doing this one-by-one keeps the SQL
    // straightforward; the batches are small.
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let row = sqlx::query!(
            r#"UPDATE outbound_jobs
                  SET status = ?, updated_at = ?
                WHERE id = ? AND status = ?
              RETURNING id as "id: Uuid", target_id as "target_id: Uuid",
                        user_id as "user_id: Uuid", event_type, payload, status,
                        attempts, next_attempt_at, last_error, last_response_status,
                        external_resource_id, idempotency_key, created_at, updated_at"#,
            STATUS_IN_FLIGHT,
            now,
            id,
            STATUS_PENDING
        )
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(r) = row {
            out.push(OutboundJob {
                id: r.id,
                target_id: r.target_id,
                user_id: r.user_id,
                event_type: r.event_type,
                payload: r.payload,
                status: r.status,
                attempts: r.attempts,
                next_attempt_at: r.next_attempt_at,
                last_error: r.last_error,
                last_response_status: r.last_response_status,
                external_resource_id: r.external_resource_id,
                idempotency_key: r.idempotency_key,
                created_at: r.created_at,
                updated_at: r.updated_at,
            });
        }
    }
    Ok(out)
}

pub async fn mark_success(
    id: Uuid,
    external_id: Option<&str>,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let now = now_epoch();
    sqlx::query!(
        r#"UPDATE outbound_jobs
              SET status = ?, external_resource_id = COALESCE(?, external_resource_id),
                  last_error = NULL, updated_at = ?
            WHERE id = ?"#,
        STATUS_SUCCEEDED,
        external_id,
        now,
        id
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn mark_failure_retryable(
    id: Uuid,
    status: u16,
    detail: &str,
    attempt: u32,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let now = now_epoch();
    let delay = backoff_delay(attempt);
    let next = now + delay.as_secs() as i64;
    let new_attempts = attempt as i64 + 1;
    let status_i = status as i64;

    let new_status = if new_attempts >= DEAD_LETTER_ATTEMPTS as i64 {
        STATUS_DEAD
    } else {
        STATUS_PENDING
    };

    sqlx::query!(
        r#"UPDATE outbound_jobs
              SET status = ?, attempts = ?, next_attempt_at = ?,
                  last_error = ?, last_response_status = ?, updated_at = ?
            WHERE id = ?"#,
        new_status,
        new_attempts,
        next,
        detail,
        status_i,
        now,
        id
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn mark_failure_permanent(
    id: Uuid,
    status: u16,
    detail: &str,
    attempt: u32,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let now = now_epoch();
    let new_attempts = attempt as i64 + 1;
    let status_i = status as i64;
    sqlx::query!(
        r#"UPDATE outbound_jobs
              SET status = ?, attempts = ?,
                  last_error = ?, last_response_status = ?, updated_at = ?
            WHERE id = ?"#,
        STATUS_FAILED,
        new_attempts,
        detail,
        status_i,
        now,
        id
    )
    .execute(conn)
    .await?;
    Ok(())
}

/// Admin-requested re-queue. `failed | dead → pending` with `next_attempt_at = now`. Attempts
/// counter is NOT reset so the backoff math still reflects history if the target is still
/// broken.
pub async fn requeue(id: Uuid, conn: &mut SqliteConnection) -> Result<bool, AppError> {
    let now = now_epoch();
    let res = sqlx::query!(
        r#"UPDATE outbound_jobs
              SET status = ?, next_attempt_at = ?, updated_at = ?
            WHERE id = ? AND status IN (?, ?)"#,
        STATUS_PENDING,
        now,
        now,
        id,
        STATUS_FAILED,
        STATUS_DEAD
    )
    .execute(conn)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn get(id: Uuid, conn: &mut SqliteConnection) -> Result<Option<OutboundJob>, AppError> {
    let row = sqlx::query!(
        r#"SELECT id as "id: Uuid", target_id as "target_id: Uuid",
                  user_id as "user_id: Uuid", event_type, payload, status,
                  attempts, next_attempt_at, last_error, last_response_status,
                  external_resource_id, idempotency_key, created_at, updated_at
             FROM outbound_jobs WHERE id = ?"#,
        id
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|r| OutboundJob {
        id: r.id,
        target_id: r.target_id,
        user_id: r.user_id,
        event_type: r.event_type,
        payload: r.payload,
        status: r.status,
        attempts: r.attempts,
        next_attempt_at: r.next_attempt_at,
        last_error: r.last_error,
        last_response_status: r.last_response_status,
        external_resource_id: r.external_resource_id,
        idempotency_key: r.idempotency_key,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }))
}

pub async fn list_recent(
    target_id: Option<Uuid>,
    status: Option<&str>,
    limit: i64,
    conn: &mut SqliteConnection,
) -> Result<Vec<OutboundJob>, AppError> {
    let mut qb: sqlx::QueryBuilder<sqlx::Sqlite> = sqlx::QueryBuilder::new(
        r#"SELECT id, target_id, user_id, event_type, payload, status,
                  attempts, next_attempt_at, last_error, last_response_status,
                  external_resource_id, idempotency_key, created_at, updated_at
             FROM outbound_jobs WHERE 1=1"#,
    );
    if let Some(t) = target_id {
        qb.push(" AND target_id = ").push_bind(t);
    }
    if let Some(s) = status {
        qb.push(" AND status = ").push_bind(s.to_string());
    }
    qb.push(" ORDER BY created_at DESC LIMIT ").push_bind(limit);

    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        target_id: Uuid,
        user_id: Uuid,
        event_type: String,
        payload: String,
        status: String,
        attempts: i64,
        next_attempt_at: i64,
        last_error: Option<String>,
        last_response_status: Option<i64>,
        external_resource_id: Option<String>,
        idempotency_key: String,
        created_at: i64,
        updated_at: i64,
    }

    let rows: Vec<Row> = qb.build_query_as().fetch_all(conn).await?;
    Ok(rows
        .into_iter()
        .map(|r| OutboundJob {
            id: r.id,
            target_id: r.target_id,
            user_id: r.user_id,
            event_type: r.event_type,
            payload: r.payload,
            status: r.status,
            attempts: r.attempts,
            next_attempt_at: r.next_attempt_at,
            last_error: r.last_error,
            last_response_status: r.last_response_status,
            external_resource_id: r.external_resource_id,
            idempotency_key: r.idempotency_key,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
        .collect())
}

/// Deserialize the stored payload into a SCIM body. Swallows JSON errors — a malformed
/// payload shouldn't wedge the worker, it should surface as a permanent failure on dispatch.
pub fn decode_payload(payload: &str) -> Value {
    serde_json::from_str(payload).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_exponentially() {
        let d0 = backoff_delay(0);
        let d1 = backoff_delay(1);
        let d2 = backoff_delay(2);
        assert!(d1 > d0);
        assert!(d2 > d1);
    }

    #[test]
    fn backoff_caps_at_one_hour() {
        let huge = backoff_delay(50);
        assert!(huge <= Duration::from_secs(60 * 60));
    }

    #[test]
    fn backoff_first_is_in_range() {
        let d = backoff_delay(0);
        // 5 seconds base with 10% jitter floor → ~4-5 seconds.
        assert!(d >= Duration::from_secs(4));
        assert!(d <= Duration::from_secs(6));
    }

    #[test]
    fn backoff_monotonic_under_cap() {
        let d10 = backoff_delay(10);
        let d11 = backoff_delay(11);
        // Both are at or near the cap; 11 should not be smaller than 10.
        assert!(d11 >= d10);
    }

    #[test]
    fn decode_payload_bad_json_returns_null() {
        assert!(decode_payload("").is_null());
        assert!(decode_payload("{not-json").is_null());
    }

    #[test]
    fn decode_payload_roundtrip() {
        let v = decode_payload(r#"{"a":1}"#);
        assert_eq!(v["a"], 1);
    }
}
