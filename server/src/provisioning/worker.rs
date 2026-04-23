//! Background worker that drains `outbound_jobs` and dispatches through target adapters.
//!
//! One instance per process. Wakes on either a 30s tick or a [`Notifier`] poke from the
//! write path. On each tick it claims a batch of ready jobs, dispatches them in parallel,
//! and records the outcomes. Lost notifications are absorbed by the tick.

use std::sync::Arc;
use std::time::Duration;

use sqlx::SqlitePool;
use tracing::{debug, error, warn};

use crate::provisioning::Notifier;
use crate::provisioning::adapter::{AdapterOutcome, ProvisioningAdapter};
use crate::provisioning::adapters::generic_scim::GenericScimAdapter;
use crate::provisioning::jobs::{self, OutboundJob};
use crate::provisioning::targets::{self, KIND_GENERIC_SCIM, KEY_LEN, ProvisioningTarget};

const TICK: Duration = Duration::from_secs(30);
const BATCH_SIZE: i64 = 16;

/// Entry point: loops forever (until the process exits) dispatching jobs. Expected to be
/// spawned once from `main.rs`.
///
/// `master_key` is the AES-GCM key for decrypting target auth tokens.
pub async fn run(
    pool: SqlitePool,
    notifier: Notifier,
    master_key: [u8; KEY_LEN],
    http_client: reqwest::Client,
) {
    let generic = Arc::new(GenericScimAdapter::new(http_client));
    loop {
        tokio::select! {
            _ = tokio::time::sleep(TICK) => {}
            _ = notifier.notified() => {}
        }

        match tick(&pool, &master_key, generic.as_ref()).await {
            Ok(n) if n > 0 => debug!(dispatched = n, "provisioning worker tick"),
            Ok(_) => {}
            Err(e) => error!(error = ?e, "provisioning worker tick failed"),
        }
    }
}

async fn tick(
    pool: &SqlitePool,
    master_key: &[u8; KEY_LEN],
    generic: &GenericScimAdapter,
) -> Result<usize, crate::errors::AppError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64;

    let mut conn = pool.acquire().await?;
    let claimed = jobs::claim_batch(now, BATCH_SIZE, &mut conn).await?;
    drop(conn);

    let count = claimed.len();
    for job in claimed {
        if let Err(e) = dispatch_one(pool, master_key, generic, job).await {
            error!(error = ?e, "dispatch_one failed");
        }
    }
    Ok(count)
}

async fn dispatch_one(
    pool: &SqlitePool,
    master_key: &[u8; KEY_LEN],
    generic: &GenericScimAdapter,
    job: OutboundJob,
) -> Result<(), crate::errors::AppError> {
    let mut conn = pool.acquire().await?;
    let Some(target) = targets::get(job.target_id, &mut conn).await? else {
        // Target was deleted between enqueue and dispatch — terminal.
        warn!(job_id = %job.id, target_id = %job.target_id, "target gone; marking job failed");
        jobs::mark_failure_permanent(job.id, 0, "target deleted", job.attempts as u32, &mut conn)
            .await?;
        return Ok(());
    };

    if !target.enabled {
        // Admin disabled the target after enqueue. Don't send, but don't dead-letter either;
        // treat as a permanent failure with a clear reason.
        jobs::mark_failure_permanent(job.id, 0, "target disabled", job.attempts as u32, &mut conn)
            .await?;
        return Ok(());
    }

    let token = match targets::decrypt_token(
        &target.auth_token_ciphertext,
        &target.auth_token_nonce,
        master_key,
    ) {
        Ok(t) => t,
        Err(e) => {
            // Can't talk to the target without the token. Retryable so admins can rotate the
            // master key and recover, but if it keeps failing the dead-letter attempts cap
            // will still eventually park the job.
            jobs::mark_failure_retryable(
                job.id,
                0,
                &format!("token decrypt failed: {e:?}"),
                job.attempts as u32,
                &mut conn,
            )
            .await?;
            return Ok(());
        }
    };

    let body = jobs::decode_payload(&job.payload);
    let outcome = dispatch_via_adapter(&target, &token, &job, body, generic).await;

    match outcome {
        AdapterOutcome::Success { external_id } => {
            jobs::mark_success(job.id, external_id.as_deref(), &mut conn).await?;
        }
        AdapterOutcome::RetryableFailure { status, detail } => {
            warn!(
                job_id = %job.id,
                target_id = %target.id,
                attempts = job.attempts,
                status,
                "retryable dispatch failure"
            );
            jobs::mark_failure_retryable(
                job.id,
                status,
                &detail,
                job.attempts as u32,
                &mut conn,
            )
            .await?;
        }
        AdapterOutcome::PermanentFailure { status, detail } => {
            warn!(
                job_id = %job.id,
                target_id = %target.id,
                status,
                "permanent dispatch failure"
            );
            jobs::mark_failure_permanent(
                job.id,
                status,
                &detail,
                job.attempts as u32,
                &mut conn,
            )
            .await?;
        }
    }
    Ok(())
}

/// Pick an adapter based on `target.kind`. Only one adapter shipped today; this is the
/// extension point for Slack/Okta/etc.
async fn dispatch_via_adapter(
    target: &ProvisioningTarget,
    token: &str,
    job: &OutboundJob,
    body: serde_json::Value,
    generic: &GenericScimAdapter,
) -> AdapterOutcome {
    match target.kind.as_str() {
        KIND_GENERIC_SCIM => generic.dispatch(target, token, job, body).await,
        other => AdapterOutcome::PermanentFailure {
            status: 0,
            detail: format!("unknown target kind {other}"),
        },
    }
}
