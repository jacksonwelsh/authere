//! Dead-letter webhook fan-out. When a job transitions to `dead` (retry budget exhausted),
//! the worker fires one best-effort POST to the target's `dead_letter_webhook_url` so
//! admins can wire PagerDuty / Slack / internal alerting.
//!
//! Intentionally small: no retries of the webhook itself, no queuing, no templating. The
//! primary provisioning path has already given up — the webhook is supplementary and must
//! not reopen the job.

use serde_json::{Value, json};

use crate::provisioning::jobs::OutboundJob;
use crate::provisioning::targets::ProvisioningTarget;

/// Build the JSON envelope POSTed to a dead-letter webhook. Pure — the shape stays tight
/// and carries no PII beyond ids that a downstream alert routing tool can correlate back
/// to Authere.
pub fn build_envelope(target: &ProvisioningTarget, job: &OutboundJob) -> Value {
    json!({
        "type": "authere.provisioning.dead_letter",
        "target": {
            "id": target.id,
            "name": target.name,
            "kind": target.kind,
        },
        "job": {
            "id": job.id,
            "user_id": job.user_id,
            "event_type": job.event_type,
            "attempts": job.attempts,
            "last_response_status": job.last_response_status,
            // `last_error` is already truncated to ≤512 chars by the adapter classifier.
            "last_error": job.last_error,
            "external_resource_id": job.external_resource_id,
        },
    })
}

/// Fire the webhook. Always returns `Ok(())`; webhook delivery errors are logged but never
/// surface — a broken alert endpoint must not keep the worker from advancing.
pub async fn fire(
    client: &reqwest::Client,
    target: &ProvisioningTarget,
    job: &OutboundJob,
) {
    let Some(url) = target.dead_letter_webhook_url.as_deref() else {
        return;
    };
    if url.trim().is_empty() {
        return;
    }
    let body = build_envelope(target, job);
    let req = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .timeout(std::time::Duration::from_secs(10))
        .json(&body);
    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            tracing::info!(
                target_id = %target.id,
                job_id = %job.id,
                "provisioning.dead_letter.webhook.sent"
            );
        }
        Ok(resp) => {
            tracing::warn!(
                target_id = %target.id,
                job_id = %job.id,
                status = resp.status().as_u16(),
                "provisioning.dead_letter.webhook.non_2xx"
            );
        }
        Err(e) => {
            tracing::warn!(
                target_id = %target.id,
                job_id = %job.id,
                error = %e,
                "provisioning.dead_letter.webhook.failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn sample_target() -> ProvisioningTarget {
        ProvisioningTarget {
            id: Uuid::nil(),
            name: "Alerts".into(),
            kind: "generic_scim".into(),
            base_url: "http://x".into(),
            auth_token_ciphertext: vec![],
            auth_token_nonce: vec![],
            enabled: true,
            created_at: 0,
            created_by: None,
            updated_at: 0,
            backfill_done_at: None,
            attribute_map: None,
            dead_letter_webhook_url: Some("http://alert".into()),
        }
    }

    fn sample_job() -> OutboundJob {
        OutboundJob {
            id: Uuid::nil(),
            target_id: Uuid::nil(),
            user_id: Uuid::nil(),
            event_type: "create".into(),
            payload: "{}".into(),
            status: "dead".into(),
            attempts: 8,
            next_attempt_at: 0,
            last_error: Some("ECONNREFUSED".into()),
            last_response_status: Some(0),
            external_resource_id: Some("ext-1".into()),
            idempotency_key: "ik".into(),
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn envelope_carries_core_fields() {
        let env = build_envelope(&sample_target(), &sample_job());
        assert_eq!(env["type"], "authere.provisioning.dead_letter");
        assert_eq!(env["target"]["name"], "Alerts");
        assert_eq!(env["target"]["kind"], "generic_scim");
        assert_eq!(env["job"]["event_type"], "create");
        assert_eq!(env["job"]["attempts"], 8);
        assert_eq!(env["job"]["last_error"], "ECONNREFUSED");
        assert_eq!(env["job"]["external_resource_id"], "ext-1");
    }

    #[test]
    fn envelope_omits_payload_and_credentials() {
        let env = build_envelope(&sample_target(), &sample_job());
        // Payload is deliberately excluded — it may contain user PII. Credentials likewise.
        assert!(env["job"].get("payload").is_none());
        assert!(env.get("auth_token").is_none());
        assert!(env["target"].get("auth_token_ciphertext").is_none());
    }
}
