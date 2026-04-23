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
/// Coalesced away by an equivalent or superseding later job. Terminal, non-retryable.
pub const STATUS_SUPERSEDED: &str = "superseded";

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

/// Exponential backoff base delay, capped at 1 hour. Pure — unit-testable directly.
///
/// Attempt 0 is the first retry delay (used *after* the first failure). Growth: 5s * 2^n.
/// This is the *un-jittered* base; [`backoff_delay`] wraps this with a random jitter to
/// de-synchronize parallel jobs.
pub fn backoff_base(attempts: u32) -> Duration {
    let cap: u64 = 60 * 60; // 1 hour
    let base: u64 = 5u64.saturating_mul(1u64 << attempts.min(12));
    Duration::from_secs(base.min(cap))
}

/// Apply `[-fraction .. +fraction]` jitter to a base delay, where `fraction` is a ratio in
/// `[0.0, 1.0]`. Pure — the caller supplies the random `roll` in `[0.0, 1.0]` so tests can
/// feed edge values directly.
pub fn apply_jitter(base: Duration, fraction: f64, roll: f64) -> Duration {
    let frac = fraction.clamp(0.0, 1.0);
    let roll = roll.clamp(0.0, 1.0);
    let secs = base.as_secs_f64();
    // Map roll in [0, 1] onto [-frac, +frac] and scale.
    let adj = secs * frac * (roll * 2.0 - 1.0);
    let jittered = (secs + adj).max(0.0);
    Duration::from_secs_f64(jittered)
}

/// Convenience wrapper: exponential backoff base + ±10% random jitter via `thread_rng`.
/// Not pure — for pure flows use [`backoff_base`] + [`apply_jitter`] directly.
pub fn backoff_delay(attempts: u32) -> Duration {
    use rand::Rng;
    let roll: f64 = rand::thread_rng().gen_range(0.0..1.0);
    apply_jitter(backoff_base(attempts), 0.10, roll)
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

/// Per-target derived health for the admin dashboard. Snapshots the latest success, the
/// latest failure (`failed` or `dead`), and how many job attempts have failed in a row since
/// the last success — so admins see "this target has been broken for the last 12 jobs"
/// at a glance.
#[derive(Debug, Clone)]
pub struct TargetHealth {
    pub target_id: Uuid,
    pub last_success_at: Option<i64>,
    pub last_failure_at: Option<i64>,
    pub consecutive_failures: i64,
}

/// Compute health rows for every target. Done as three small aggregate queries and merged
/// in-memory — cheaper than hand-rolling a single mega-query and keeps the intent obvious.
pub async fn compute_health(
    conn: &mut SqliteConnection,
) -> Result<Vec<TargetHealth>, AppError> {
    let last_success = sqlx::query!(
        r#"SELECT target_id as "target_id: Uuid", MAX(updated_at) as "ts: i64"
             FROM outbound_jobs WHERE status = ? GROUP BY target_id"#,
        STATUS_SUCCEEDED
    )
    .fetch_all(&mut *conn)
    .await?;

    let last_failure = sqlx::query!(
        r#"SELECT target_id as "target_id: Uuid", MAX(updated_at) as "ts: i64"
             FROM outbound_jobs
            WHERE status IN (?, ?)
         GROUP BY target_id"#,
        STATUS_FAILED,
        STATUS_DEAD
    )
    .fetch_all(&mut *conn)
    .await?;

    // Consecutive failures since the last success per target. We compare by job id rather
    // than updated_at because `updated_at` is second-granularity (UUIDv7 ids are strictly
    // monotonic, including within a single second). "Consecutive" here means: failed/dead
    // jobs whose id sorts after the most recent `succeeded` job's id for the same target —
    // i.e. the jobs the admin would see as "since the last good one."
    let conseq = sqlx::query!(
        r#"SELECT j.target_id as "target_id: Uuid", COUNT(*) as "n: i64"
             FROM outbound_jobs j
             LEFT JOIN (
                 SELECT target_id, MAX(id) as last_id
                   FROM outbound_jobs WHERE status = ?
                   GROUP BY target_id
             ) s ON s.target_id = j.target_id
            WHERE j.status IN (?, ?)
              AND (s.last_id IS NULL OR j.id > s.last_id)
         GROUP BY j.target_id"#,
        STATUS_SUCCEEDED,
        STATUS_FAILED,
        STATUS_DEAD
    )
    .fetch_all(&mut *conn)
    .await?;

    use std::collections::BTreeMap;
    let mut out: BTreeMap<Uuid, TargetHealth> = BTreeMap::new();
    for r in last_success {
        out.entry(r.target_id).or_insert(TargetHealth {
            target_id: r.target_id,
            last_success_at: None,
            last_failure_at: None,
            consecutive_failures: 0,
        })
        .last_success_at = r.ts;
    }
    for r in last_failure {
        out.entry(r.target_id).or_insert(TargetHealth {
            target_id: r.target_id,
            last_success_at: None,
            last_failure_at: None,
            consecutive_failures: 0,
        })
        .last_failure_at = r.ts;
    }
    for r in conseq {
        out.entry(r.target_id).or_insert(TargetHealth {
            target_id: r.target_id,
            last_success_at: None,
            last_failure_at: None,
            consecutive_failures: 0,
        })
        .consecutive_failures = r.n.unwrap_or(0);
    }
    Ok(out.into_values().collect())
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

/// Minimal view of a pending job used by the coalescer. Defined separately from
/// [`OutboundJob`] so [`plan_coalesce`] can be exercised without constructing full rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoalesceCandidate {
    pub id: Uuid,
    pub event_type: String,
    pub created_at: i64,
}

impl From<&OutboundJob> for CoalesceCandidate {
    fn from(j: &OutboundJob) -> Self {
        CoalesceCandidate {
            id: j.id,
            event_type: j.event_type.clone(),
            created_at: j.created_at,
        }
    }
}

/// Plan which pending jobs in a single `(target, user)` pair should be marked
/// [`STATUS_SUPERSEDED`]. Pure — the caller hands in the pair's pending jobs in
/// `created_at` order, and receives the ids to park.
///
/// Rules:
///   1. If a `delete` exists, every earlier pending job is redundant (the target will drop
///      the user anyway). Everything before the *last* delete is superseded; only the final
///      `delete` survives.
///   2. For runs of consecutive collapsible events (`update`, `deactivate`, `reactivate`),
///      only the last one in the run is kept — earlier ones in the run carry stale payloads.
///      Runs do *not* cross event-type boundaries: `update, deactivate, update` keeps all
///      three because each carries a semantically distinct side-effect.
///   3. `create` is never superseded automatically: downstream update/delete flows may rely
///      on capturing the target-assigned id from the create response.
pub fn plan_coalesce(jobs: &[CoalesceCandidate]) -> Vec<Uuid> {
    let mut supersede: Vec<Uuid> = Vec::new();
    if jobs.is_empty() {
        return supersede;
    }

    // Pass 1: collapse everything earlier than the last `delete`, if any.
    let mut tail_start = 0usize;
    if let Some(last_delete) = jobs.iter().rposition(|j| j.event_type == "delete") {
        for j in &jobs[..last_delete] {
            supersede.push(j.id);
        }
        tail_start = last_delete;
    }

    // Pass 2: collapse consecutive same-type runs for the collapsible events.
    let collapsible = |s: &str| matches!(s, "update" | "deactivate" | "reactivate");
    let tail = &jobs[tail_start..];
    for i in 0..tail.len().saturating_sub(1) {
        if supersede.contains(&tail[i].id) {
            continue;
        }
        if collapsible(&tail[i].event_type) && tail[i].event_type == tail[i + 1].event_type {
            supersede.push(tail[i].id);
        }
    }

    supersede
}

/// Walk all `(target, user)` pairs with at least two pending jobs and apply [`plan_coalesce`]
/// against each. Returns the count of jobs flipped to [`STATUS_SUPERSEDED`].
///
/// Cheap to run before every claim tick: the aggregation filters out pairs with a single
/// pending row (no work to do), and the candidate rows are small.
pub async fn run_coalesce_pass(conn: &mut SqliteConnection) -> Result<usize, AppError> {
    // Pairs with more than one pending job — these are the only ones eligible for collapse.
    let pairs = sqlx::query!(
        r#"SELECT target_id as "target_id: Uuid", user_id as "user_id: Uuid"
             FROM outbound_jobs
            WHERE status = ?
         GROUP BY target_id, user_id
           HAVING COUNT(*) > 1"#,
        STATUS_PENDING
    )
    .fetch_all(&mut *conn)
    .await?;

    if pairs.is_empty() {
        return Ok(0);
    }

    let now = now_epoch();
    let mut flipped = 0usize;
    for pair in pairs {
        let rows = sqlx::query!(
            r#"SELECT id as "id: Uuid", event_type, created_at
                 FROM outbound_jobs
                WHERE target_id = ? AND user_id = ? AND status = ?
             ORDER BY created_at ASC, id ASC"#,
            pair.target_id,
            pair.user_id,
            STATUS_PENDING
        )
        .fetch_all(&mut *conn)
        .await?;

        let candidates: Vec<CoalesceCandidate> = rows
            .into_iter()
            .map(|r| CoalesceCandidate {
                id: r.id,
                event_type: r.event_type,
                created_at: r.created_at,
            })
            .collect();

        for id in plan_coalesce(&candidates) {
            let res = sqlx::query!(
                r#"UPDATE outbound_jobs
                      SET status = ?, updated_at = ?
                    WHERE id = ? AND status = ?"#,
                STATUS_SUPERSEDED,
                now,
                id,
                STATUS_PENDING
            )
            .execute(&mut *conn)
            .await?;
            flipped += res.rows_affected() as usize;
        }
    }
    Ok(flipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_base_grows_exponentially() {
        let d0 = backoff_base(0);
        let d1 = backoff_base(1);
        let d2 = backoff_base(2);
        assert!(d1 > d0);
        assert!(d2 > d1);
    }

    #[test]
    fn backoff_base_caps_at_one_hour() {
        assert!(backoff_base(50) <= Duration::from_secs(60 * 60));
    }

    #[test]
    fn backoff_base_first_is_five_seconds() {
        assert_eq!(backoff_base(0), Duration::from_secs(5));
    }

    #[test]
    fn backoff_base_monotonic_under_cap() {
        assert!(backoff_base(11) >= backoff_base(10));
    }

    #[test]
    fn apply_jitter_roll_zero_is_minimum() {
        // roll=0 maps to -fraction → minimum of the jittered range.
        let out = apply_jitter(Duration::from_secs(100), 0.10, 0.0);
        assert_eq!(out, Duration::from_secs_f64(90.0));
    }

    #[test]
    fn apply_jitter_roll_one_is_maximum() {
        let out = apply_jitter(Duration::from_secs(100), 0.10, 1.0);
        assert_eq!(out, Duration::from_secs_f64(110.0));
    }

    #[test]
    fn apply_jitter_mid_roll_is_base() {
        let out = apply_jitter(Duration::from_secs(100), 0.10, 0.5);
        assert_eq!(out, Duration::from_secs(100));
    }

    #[test]
    fn apply_jitter_clamps_negative_to_zero() {
        // Pathologically large fraction shouldn't produce negative delays.
        let out = apply_jitter(Duration::from_secs(10), 5.0, 0.0);
        assert_eq!(out, Duration::ZERO);
    }

    #[test]
    fn apply_jitter_zero_fraction_is_passthrough() {
        let out = apply_jitter(Duration::from_secs(42), 0.0, 0.9);
        assert_eq!(out, Duration::from_secs(42));
    }

    #[test]
    fn backoff_delay_wrapper_stays_in_envelope() {
        // With 10% jitter, the wrapper must always be within ±10% of the base.
        for attempts in [0u32, 1, 3, 5, 10] {
            let base = backoff_base(attempts).as_secs_f64();
            for _ in 0..32 {
                let got = backoff_delay(attempts).as_secs_f64();
                assert!(
                    got >= base * 0.9 - 1e-6 && got <= base * 1.1 + 1e-6,
                    "got {got} outside [{}, {}] for attempts {attempts}",
                    base * 0.9,
                    base * 1.1
                );
            }
        }
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

    // -----------------------------------------------------------------
    // plan_coalesce: all the interesting shapes.
    // -----------------------------------------------------------------

    fn candidate(ev: &str, t: i64) -> CoalesceCandidate {
        CoalesceCandidate {
            id: Uuid::now_v7(),
            event_type: ev.to_string(),
            created_at: t,
        }
    }

    #[test]
    fn coalesce_empty_is_noop() {
        assert!(plan_coalesce(&[]).is_empty());
    }

    #[test]
    fn coalesce_single_job_kept() {
        let c = vec![candidate("create", 1)];
        assert!(plan_coalesce(&c).is_empty());
    }

    #[test]
    fn coalesce_consecutive_updates_keeps_latest() {
        let c = vec![
            candidate("update", 1),
            candidate("update", 2),
            candidate("update", 3),
        ];
        let super_ = plan_coalesce(&c);
        assert_eq!(super_, vec![c[0].id, c[1].id]);
    }

    #[test]
    fn coalesce_consecutive_deactivates_keeps_latest() {
        let c = vec![candidate("deactivate", 1), candidate("deactivate", 2)];
        let super_ = plan_coalesce(&c);
        assert_eq!(super_, vec![c[0].id]);
    }

    #[test]
    fn coalesce_does_not_cross_type_boundaries() {
        // update, deactivate, update — each flips different state, keep all three.
        let c = vec![
            candidate("update", 1),
            candidate("deactivate", 2),
            candidate("update", 3),
        ];
        assert!(plan_coalesce(&c).is_empty());
    }

    #[test]
    fn coalesce_delete_supersedes_everything_earlier() {
        let c = vec![
            candidate("create", 1),
            candidate("update", 2),
            candidate("deactivate", 3),
            candidate("delete", 4),
        ];
        let super_ = plan_coalesce(&c);
        assert_eq!(super_.len(), 3);
        assert_eq!(super_, vec![c[0].id, c[1].id, c[2].id]);
    }

    #[test]
    fn coalesce_keeps_create_before_updates() {
        // create, update, update → keep [create, update₂]
        let c = vec![
            candidate("create", 1),
            candidate("update", 2),
            candidate("update", 3),
        ];
        let super_ = plan_coalesce(&c);
        // Only update₁ is in a run with update₂.
        assert_eq!(super_, vec![c[1].id]);
    }

    #[test]
    fn coalesce_run_then_different_type_doesnt_take_later() {
        // update, update, deactivate — keep [update₂, deactivate]
        let c = vec![
            candidate("update", 1),
            candidate("update", 2),
            candidate("deactivate", 3),
        ];
        let super_ = plan_coalesce(&c);
        assert_eq!(super_, vec![c[0].id]);
    }

    #[test]
    fn coalesce_two_deletes_keeps_only_the_last() {
        let c = vec![candidate("delete", 1), candidate("delete", 2)];
        let super_ = plan_coalesce(&c);
        assert_eq!(super_, vec![c[0].id]);
    }

    #[test]
    fn coalesce_create_is_never_collapsed() {
        // Two creates would be weird, but if it happens, neither should be superseded
        // through the run-collapse pass (create is not in the collapsible set).
        let c = vec![candidate("create", 1), candidate("create", 2)];
        assert!(plan_coalesce(&c).is_empty());
    }
}
