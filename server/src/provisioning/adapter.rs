//! The adapter seam. Each target kind (generic SCIM, Slack, Okta, …) implements
//! [`ProvisioningAdapter`]. The worker is adapter-agnostic and only talks through this trait.

use serde_json::Value;

use crate::provisioning::jobs::OutboundJob;
use crate::provisioning::targets::ProvisioningTarget;

/// Outcome of dispatching a single job through an adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterOutcome {
    /// The downstream target accepted the request. If the adapter received a SCIM id (create
    /// flows, or 409-as-idempotent-success), it's returned here to be persisted on the job row
    /// for subsequent update/delete flows.
    Success { external_id: Option<String> },
    /// Transient failure — the worker reschedules with backoff. `status` is the HTTP status
    /// (or 0 for network/timeout errors), `detail` is a short human-readable message that
    /// becomes `outbound_jobs.last_error`.
    RetryableFailure { status: u16, detail: String },
    /// Permanent failure — the job moves to `failed` and stops retrying. Used for 4xx that
    /// won't resolve on retry (malformed body, auth rejected, etc).
    PermanentFailure { status: u16, detail: String },
}

/// Anything that can push one job to one target. Implementations should be cheap to construct;
/// the worker may hold one instance per target kind and reuse it across many jobs.
///
/// The adapter receives the target *plus* the body already materialized from the job payload,
/// so it doesn't need to know about the event types. For `DELETE` flows the adapter sees a
/// `null` body and is expected to honor the target's idiom (e.g. literal DELETE on generic,
/// PATCH active=false on Slack).
pub trait ProvisioningAdapter: Send + Sync {
    async fn dispatch(
        &self,
        target: &ProvisioningTarget,
        target_auth_token: &str,
        job: &OutboundJob,
        body: Value,
    ) -> AdapterOutcome;
}
