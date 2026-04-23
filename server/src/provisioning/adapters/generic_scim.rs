//! Generic SCIM 2.0 adapter. Issues POST/PUT/PATCH/DELETE against `<base_url>/Users[/<id>]`
//! with a bearer token. Maps HTTP status classes to retry/permanent outcomes per the RFC:
//! 5xx/408/429 retry, other 4xx are permanent, 2xx succeed, 409 on create is treated as
//! idempotent success (target already has the user — record the id and move on).

use std::time::Duration;

use serde_json::Value;

use crate::provisioning::adapter::{AdapterOutcome, ProvisioningAdapter};
use crate::provisioning::event::UserLifecycleEvent;
use crate::provisioning::jobs::OutboundJob;
use crate::provisioning::targets::ProvisioningTarget;
use crate::scim::SCIM_CONTENT_TYPE;

/// Per-request timeout. Downstream SCIM servers should answer faster than this.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub struct GenericScimAdapter {
    client: reqwest::Client,
}

impl GenericScimAdapter {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

/// Classify an HTTP response into an AdapterOutcome. Pure — isolated so it can be unit tested
/// without standing up an HTTP server.
pub fn classify_response(
    event: UserLifecycleEvent,
    status: u16,
    body_text: &str,
) -> AdapterOutcome {
    // 2xx: success. Try to pluck out an id for create flows.
    if (200..300).contains(&status) {
        let id = extract_id_from_body(body_text);
        return AdapterOutcome::Success { external_id: id };
    }

    // 409 on create: the target already has this user. Treat as success for idempotency.
    // The body sometimes carries the existing resource's id; if so, capture it.
    if status == 409 && matches!(event, UserLifecycleEvent::Created) {
        let id = extract_id_from_body(body_text);
        return AdapterOutcome::Success { external_id: id };
    }

    // Delete on a resource the target already forgot about is success (idempotent).
    if status == 404 && matches!(event, UserLifecycleEvent::Deleted) {
        return AdapterOutcome::Success { external_id: None };
    }

    // Retryable transients.
    if status == 408 || status == 429 || (500..600).contains(&status) {
        return AdapterOutcome::RetryableFailure {
            status,
            detail: trim_detail(body_text),
        };
    }

    // Everything else is permanent — 400/401/403/422 etc. Won't resolve on retry.
    AdapterOutcome::PermanentFailure {
        status,
        detail: trim_detail(body_text),
    }
}

/// Pluck `id` out of a SCIM response body. Returns `None` on non-JSON or missing field.
fn extract_id_from_body(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    v.get("id").and_then(|x| x.as_str()).map(String::from)
}

fn trim_detail(body: &str) -> String {
    const MAX: usize = 512;
    if body.len() <= MAX {
        body.to_string()
    } else {
        let mut s = body[..MAX].to_string();
        s.push_str("…");
        s
    }
}

fn build_url(base_url: &str, event: UserLifecycleEvent, external_id: Option<&str>) -> String {
    let base = base_url.trim_end_matches('/');
    match event {
        UserLifecycleEvent::Created => format!("{base}/Users"),
        UserLifecycleEvent::Updated
        | UserLifecycleEvent::Deactivated
        | UserLifecycleEvent::Reactivated
        | UserLifecycleEvent::Deleted => {
            // For updates/deletes we need the target-assigned id if we have one (filled in by
            // the create response), otherwise fall back to Authere's UUID in the path — some
            // targets key off externalId and accept either.
            let id = external_id.unwrap_or("");
            format!("{base}/Users/{id}")
        }
    }
}

impl ProvisioningAdapter for GenericScimAdapter {
    async fn dispatch(
        &self,
        target: &ProvisioningTarget,
        target_auth_token: &str,
        job: &OutboundJob,
        body: Value,
    ) -> AdapterOutcome {
        let Some(event) = UserLifecycleEvent::from_str(&job.event_type) else {
            return AdapterOutcome::PermanentFailure {
                status: 0,
                detail: format!("unknown event_type {}", job.event_type),
            };
        };

        // For updates/deletes without a captured external id, fall back to our internal UUID.
        let fallback_id = job.user_id.to_string();
        let url_id = job.external_resource_id.as_deref().or(Some(&fallback_id));
        let url = build_url(&target.base_url, event, url_id);

        let rb = match event {
            UserLifecycleEvent::Created => self.client.post(&url).json(&body),
            UserLifecycleEvent::Updated => self.client.put(&url).json(&body),
            UserLifecycleEvent::Deactivated | UserLifecycleEvent::Reactivated => {
                self.client.patch(&url).json(&body)
            }
            UserLifecycleEvent::Deleted => self.client.delete(&url),
        };

        let rb = rb
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {target_auth_token}"))
            .header(reqwest::header::ACCEPT, SCIM_CONTENT_TYPE)
            .header(reqwest::header::CONTENT_TYPE, SCIM_CONTENT_TYPE)
            .timeout(REQUEST_TIMEOUT);

        let res = match rb.send().await {
            Ok(r) => r,
            Err(e) => {
                let is_timeout = e.is_timeout() || e.is_connect();
                let status = 0u16;
                let detail = format!("transport error: {e}");
                return if is_timeout {
                    AdapterOutcome::RetryableFailure { status, detail }
                } else {
                    // Other transport errors (DNS failure, TLS) — retry; the admin may fix
                    // the URL or network mid-flight.
                    AdapterOutcome::RetryableFailure { status, detail }
                };
            }
        };

        let status = res.status().as_u16();
        let text = res.text().await.unwrap_or_default();
        classify_response(event, status, &text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_2xx_success_with_id() {
        let out = classify_response(UserLifecycleEvent::Created, 201, r#"{"id":"abc-123"}"#);
        assert_eq!(
            out,
            AdapterOutcome::Success {
                external_id: Some("abc-123".into())
            }
        );
    }

    #[test]
    fn classify_2xx_success_without_id() {
        let out = classify_response(UserLifecycleEvent::Updated, 200, r#"{"meta":{}}"#);
        assert_eq!(out, AdapterOutcome::Success { external_id: None });
    }

    #[test]
    fn classify_204_on_delete_is_success() {
        let out = classify_response(UserLifecycleEvent::Deleted, 204, "");
        assert_eq!(out, AdapterOutcome::Success { external_id: None });
    }

    #[test]
    fn classify_409_on_create_is_idempotent_success() {
        let out = classify_response(
            UserLifecycleEvent::Created,
            409,
            r#"{"id":"existing-xyz","detail":"conflict"}"#,
        );
        assert_eq!(
            out,
            AdapterOutcome::Success {
                external_id: Some("existing-xyz".into())
            }
        );
    }

    #[test]
    fn classify_409_on_update_is_permanent_failure() {
        let out = classify_response(UserLifecycleEvent::Updated, 409, "{}");
        assert!(matches!(out, AdapterOutcome::PermanentFailure { .. }));
    }

    #[test]
    fn classify_404_on_delete_is_idempotent_success() {
        let out = classify_response(UserLifecycleEvent::Deleted, 404, "");
        assert_eq!(out, AdapterOutcome::Success { external_id: None });
    }

    #[test]
    fn classify_404_on_update_is_permanent_failure() {
        let out = classify_response(UserLifecycleEvent::Updated, 404, "");
        assert!(matches!(out, AdapterOutcome::PermanentFailure { .. }));
    }

    #[test]
    fn classify_5xx_is_retryable() {
        for status in [500, 502, 503, 504] {
            let out = classify_response(UserLifecycleEvent::Created, status, "{}");
            assert!(matches!(out, AdapterOutcome::RetryableFailure { .. }), "status {status}");
        }
    }

    #[test]
    fn classify_429_is_retryable() {
        let out = classify_response(UserLifecycleEvent::Created, 429, "{}");
        assert!(matches!(out, AdapterOutcome::RetryableFailure { .. }));
    }

    #[test]
    fn classify_408_is_retryable() {
        let out = classify_response(UserLifecycleEvent::Created, 408, "{}");
        assert!(matches!(out, AdapterOutcome::RetryableFailure { .. }));
    }

    #[test]
    fn classify_400_is_permanent() {
        let out = classify_response(UserLifecycleEvent::Created, 400, "{}");
        assert!(matches!(out, AdapterOutcome::PermanentFailure { .. }));
    }

    #[test]
    fn classify_401_is_permanent() {
        let out = classify_response(UserLifecycleEvent::Created, 401, "{}");
        assert!(matches!(out, AdapterOutcome::PermanentFailure { .. }));
    }

    #[test]
    fn classify_body_is_truncated() {
        let big = "x".repeat(1000);
        let out = classify_response(UserLifecycleEvent::Created, 500, &big);
        let AdapterOutcome::RetryableFailure { detail, .. } = out else {
            panic!("wrong variant");
        };
        assert!(detail.len() < 600);
    }

    #[test]
    fn extract_id_from_non_json_returns_none() {
        assert_eq!(extract_id_from_body("not json"), None);
    }

    #[test]
    fn extract_id_from_missing_field_returns_none() {
        assert_eq!(extract_id_from_body(r#"{"other":"value"}"#), None);
    }

    #[test]
    fn build_url_create_appends_users() {
        let u = build_url("https://api.x.co/scim/v2", UserLifecycleEvent::Created, None);
        assert_eq!(u, "https://api.x.co/scim/v2/Users");
    }

    #[test]
    fn build_url_create_strips_trailing_slash() {
        let u = build_url("https://api.x.co/scim/v2/", UserLifecycleEvent::Created, None);
        assert_eq!(u, "https://api.x.co/scim/v2/Users");
    }

    #[test]
    fn build_url_update_uses_external_id() {
        let u = build_url(
            "https://api.x.co/scim/v2",
            UserLifecycleEvent::Updated,
            Some("ext-42"),
        );
        assert_eq!(u, "https://api.x.co/scim/v2/Users/ext-42");
    }

    #[test]
    fn build_url_deactivate_patches_by_id() {
        let u = build_url(
            "https://api.x.co/scim/v2",
            UserLifecycleEvent::Deactivated,
            Some("ext-42"),
        );
        assert_eq!(u, "https://api.x.co/scim/v2/Users/ext-42");
    }

    #[test]
    fn build_url_delete_uses_id() {
        let u = build_url(
            "https://api.x.co/scim/v2",
            UserLifecycleEvent::Deleted,
            Some("ext-42"),
        );
        assert_eq!(u, "https://api.x.co/scim/v2/Users/ext-42");
    }
}
