//! Initial-sync backfill for a freshly-enabled target. Enumerates every active user in the
//! DB and enqueues a `create` job for the given target. Safe to re-run: the 409-on-create
//! idempotency in the generic adapter means re-enqueued creates land as success with the
//! existing id.
//!
//! This is a one-shot per target (tracked by `provisioning_targets.backfill_done_at`).
//! Toggling the target off/on afterwards does not re-backfill; admins who want a full
//! resync can reissue retries or delete+recreate the target.

use serde_json::to_string;
use sqlx::SqliteConnection;
use uuid::Uuid;

use crate::errors::AppError;
use crate::provisioning::event::{UserLifecycleEvent, build_scim_body};
use crate::provisioning::jobs::STATUS_PENDING;
use crate::provisioning::targets;
use crate::user::User;

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

/// Run the initial backfill for a single target. Skips users who already have any outbound
/// job recorded against this target (pending or historical) so a retry-after-crash doesn't
/// double-enqueue. Returns the number of jobs enqueued.
///
/// Callers should run this in a transaction if they want atomicity with the target's state
/// flip; [`run_if_needed`] below does that wrapping.
pub async fn run(
    target_id: Uuid,
    origin: &str,
    conn: &mut SqliteConnection,
) -> Result<usize, AppError> {
    let active_users = sqlx::query_as!(
        User,
        r#"SELECT id as "id: uuid::Uuid", name, username, email,
                  active as "active!: bool", external_id, created_at, updated_at
             FROM users
            WHERE active = 1
              AND id NOT IN (
                  SELECT user_id FROM outbound_jobs WHERE target_id = ?
              )"#,
        target_id
    )
    .fetch_all(&mut *conn)
    .await?;

    if active_users.is_empty() {
        return Ok(0);
    }

    let now = now_epoch();
    let event = UserLifecycleEvent::Created;
    let event_str = event.as_str();

    let mut inserted = 0usize;
    for user in active_users {
        let body = build_scim_body(&user, event, origin);
        let payload = to_string(&body).unwrap_or_else(|_| "null".into());
        let id = Uuid::now_v7();
        let idempotency_key = Uuid::now_v7().to_string();
        sqlx::query!(
            r#"INSERT INTO outbound_jobs
                (id, target_id, user_id, event_type, payload, status,
                 attempts, next_attempt_at, idempotency_key, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)"#,
            id,
            target_id,
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

/// If the target is enabled and has not yet been backfilled, run the backfill and mark
/// `backfill_done_at`. Returns the count of jobs enqueued (0 if already done / disabled /
/// missing). Idempotent.
pub async fn run_if_needed(
    target_id: Uuid,
    origin: &str,
    conn: &mut SqliteConnection,
) -> Result<usize, AppError> {
    let Some(target) = targets::get(target_id, conn).await? else {
        return Ok(0);
    };
    if !target.enabled || target.backfill_done_at.is_some() {
        return Ok(0);
    }
    let n = run(target_id, origin, conn).await?;
    targets::mark_backfill_done(target_id, conn).await?;
    Ok(n)
}
