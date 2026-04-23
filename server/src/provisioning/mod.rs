//! Outbound SCIM 2.0 provisioning. When users change in Authere, the worker in this module
//! pushes matching User resources to configured downstream targets (Slack, generic SCIM, …).
//!
//! The shape is:
//!
//! 1. Every user-mutating write path calls [`enqueue`] *inside its existing transaction*. This
//!    is load-bearing: atomicity between the user write and the durable job row is the
//!    at-least-once guarantee.
//! 2. [`Notifier`] (wrapped `tokio::sync::Notify`) is a wakeup signal for the worker — not a
//!    queue. Correctness lives in the `outbound_jobs` table; the notifier only reduces latency.
//! 3. [`worker::run`] drains ready jobs, dispatches through [`adapter::ProvisioningAdapter`],
//!    records the outcome, and schedules retries with exponential backoff.
//!
//! The adapter trait is deliberately tiny. The only shipped adapter is
//! [`adapters::generic_scim`], but the seam is there so Slack/Okta quirks can land without
//! touching the core.

use std::sync::Arc;

use tokio::sync::Notify;

pub mod adapter;
pub mod adapters;
pub mod admin;
pub mod backfill;
pub mod dead_letter;
pub mod event;
pub mod jobs;
pub mod mapping;
pub mod targets;
pub mod worker;

/// Wakeup signal handed to write paths so they can poke the worker after committing a job.
/// Cloning is cheap — it's an `Arc<Notify>` internally.
#[derive(Clone, Default)]
pub struct Notifier(Arc<Notify>);

impl Notifier {
    pub fn new() -> Self {
        Self(Arc::new(Notify::new()))
    }

    /// Wake one worker waiter. Safe to call from anywhere; lost notifications are absorbed by
    /// the worker's periodic poll tick.
    pub fn notify_one(&self) {
        self.0.notify_one();
    }

    /// Wait until notified. Used internally by the worker.
    pub async fn notified(&self) {
        self.0.notified().await;
    }
}

/// Enqueue jobs for all enabled targets. Called from user-write sites inside their existing
/// transaction. If no targets are enabled this is a cheap no-op (a single COUNT).
///
/// The caller is responsible for:
///   - passing a `User` snapshot reflecting the post-write state (after `save`, after `update`)
///   - calling [`Notifier::notify_one`] after the enclosing transaction commits
pub async fn enqueue(
    user: &crate::user::User,
    event: event::UserLifecycleEvent,
    origin: &str,
    conn: &mut sqlx::SqliteConnection,
) -> Result<usize, crate::errors::AppError> {
    jobs::insert_for_all_enabled_targets(user, event, origin, conn).await
}
