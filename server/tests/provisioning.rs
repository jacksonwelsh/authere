//! Integration tests for outbound provisioning.
//!
//! Covers the three things unit tests can't: (1) the enqueue-in-transaction invariant, (2)
//! `claim_batch` exactly-once under repeated claims, and (3) a full end-to-end push from a
//! user creation through the worker to a downstream SCIM mock receiver.

use std::time::Duration;

use authere_server::db::DbEntity;
use authere_server::provisioning::adapter::{AdapterOutcome, ProvisioningAdapter};
use authere_server::provisioning::adapters::generic_scim::GenericScimAdapter;
use authere_server::provisioning::event::UserLifecycleEvent;
use authere_server::provisioning::jobs::{self, STATUS_PENDING, STATUS_SUCCEEDED};
use authere_server::provisioning::targets::{self, KEY_LEN, KIND_GENERIC_SCIM};
use authere_server::user::User;
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .expect("connect in-memory sqlite");
    sqlx::migrate!("../migrations").run(&pool).await.unwrap();
    pool
}

fn fixed_key() -> [u8; KEY_LEN] {
    let mut k = [0u8; KEY_LEN];
    for (i, b) in k.iter_mut().enumerate() {
        *b = i as u8;
    }
    k
}

async fn seed_target(pool: &SqlitePool, base_url: &str) -> Uuid {
    let mut conn = pool.acquire().await.unwrap();
    let t = targets::create(
        "Test Target",
        KIND_GENERIC_SCIM,
        base_url,
        "downstream-secret",
        true,
        None,
        None,
        &fixed_key(),
        &mut conn,
    )
    .await
    .unwrap();
    t.id
}

// ---------------------------------------------------------------------------
// Atomicity: a rolled-back enclosing transaction must not leave a job behind.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn enqueue_rolls_back_with_enclosing_transaction() {
    let pool = pool().await;
    seed_target(&pool, "http://unused").await;

    let mut tx = pool.begin().await.unwrap();
    let user = User::new("alice".into(), "Alice".into(), None);
    user.save(&mut tx).await.unwrap();
    authere_server::provisioning::enqueue(
        &user,
        UserLifecycleEvent::Created,
        "http://origin",
        &mut tx,
    )
    .await
    .unwrap();
    // No commit — let `tx` drop, which rolls back.
    drop(tx);

    let mut conn = pool.acquire().await.unwrap();
    let rows = jobs::list_recent(None, None, 100, &mut conn).await.unwrap();
    assert!(
        rows.is_empty(),
        "rolled-back tx must not leave a job behind"
    );
    assert!(User::get(user.id, &mut conn).await.unwrap().is_none());
}

#[tokio::test]
async fn enqueue_commits_with_enclosing_transaction() {
    let pool = pool().await;
    seed_target(&pool, "http://unused").await;

    let mut tx = pool.begin().await.unwrap();
    let user = User::new("alice".into(), "Alice".into(), None);
    user.save(&mut tx).await.unwrap();
    authere_server::provisioning::enqueue(
        &user,
        UserLifecycleEvent::Created,
        "http://origin",
        &mut tx,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let rows = jobs::list_recent(None, None, 100, &mut conn).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, "create");
    assert_eq!(rows[0].status, STATUS_PENDING);
    assert_eq!(rows[0].user_id, user.id);
}

#[tokio::test]
async fn enqueue_fans_out_to_all_enabled_targets_only() {
    let pool = pool().await;
    let mut conn = pool.acquire().await.unwrap();
    let enabled = targets::create(
        "enabled",
        KIND_GENERIC_SCIM,
        "http://a",
        "t",
        true,
        None,
        None,
        &fixed_key(),
        &mut conn,
    )
    .await
    .unwrap();
    let _disabled = targets::create(
        "disabled",
        KIND_GENERIC_SCIM,
        "http://b",
        "t",
        false,
        None,
        None,
        &fixed_key(),
        &mut conn,
    )
    .await
    .unwrap();
    drop(conn);

    let mut tx = pool.begin().await.unwrap();
    let user = User::new("alice".into(), "Alice".into(), None);
    user.save(&mut tx).await.unwrap();
    let n = authere_server::provisioning::enqueue(
        &user,
        UserLifecycleEvent::Created,
        "http://origin",
        &mut tx,
    )
    .await
    .unwrap();
    assert_eq!(n, 1, "disabled targets must be skipped");
    tx.commit().await.unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let rows = jobs::list_recent(None, None, 100, &mut conn).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].target_id, enabled.id);
}

#[tokio::test]
async fn enqueue_is_noop_when_no_targets() {
    let pool = pool().await;
    // Note: no targets seeded.
    let mut tx = pool.begin().await.unwrap();
    let user = User::new("alice".into(), "Alice".into(), None);
    user.save(&mut tx).await.unwrap();
    let n = authere_server::provisioning::enqueue(
        &user,
        UserLifecycleEvent::Created,
        "http://origin",
        &mut tx,
    )
    .await
    .unwrap();
    assert_eq!(n, 0);
    tx.commit().await.unwrap();
}

// ---------------------------------------------------------------------------
// claim_batch: exactly-once semantics + per-pair FIFO.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn claim_batch_flips_pending_to_in_flight_exactly_once() {
    let pool = pool().await;
    let target_id = seed_target(&pool, "http://unused").await;

    // Insert three pending jobs manually so we control the state.
    let mut tx = pool.begin().await.unwrap();
    for _ in 0..3 {
        let user = User::new(
            format!("u{}", Uuid::now_v7()),
            "U".into(),
            None,
        );
        user.save(&mut tx).await.unwrap();
        authere_server::provisioning::enqueue(
            &user,
            UserLifecycleEvent::Created,
            "http://origin",
            &mut tx,
        )
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let now = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64)
        + 1000; // well past next_attempt_at

    let first = jobs::claim_batch(now, 10, &mut conn).await.unwrap();
    assert_eq!(first.len(), 3, "first claim sees all three");
    // Second claim must see nothing — all have been flipped to in_flight.
    let second = jobs::claim_batch(now, 10, &mut conn).await.unwrap();
    assert!(second.is_empty(), "second claim is empty");
    let _ = target_id;
}

#[tokio::test]
async fn claim_batch_blocks_later_event_on_same_user_target() {
    let pool = pool().await;
    let _target_id = seed_target(&pool, "http://unused").await;

    let mut tx = pool.begin().await.unwrap();
    let user = User::new("alice".into(), "Alice".into(), None);
    user.save(&mut tx).await.unwrap();
    authere_server::provisioning::enqueue(
        &user,
        UserLifecycleEvent::Created,
        "http://origin",
        &mut tx,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Immediately queue an update for the same user.
    std::thread::sleep(std::time::Duration::from_secs(1));
    let mut tx = pool.begin().await.unwrap();
    let user2 = User::get(user.id, &mut tx).await.unwrap().unwrap();
    authere_server::provisioning::enqueue(
        &user2,
        UserLifecycleEvent::Updated,
        "http://origin",
        &mut tx,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 1000;

    let claimed = jobs::claim_batch(now, 10, &mut conn).await.unwrap();
    assert_eq!(
        claimed.len(),
        1,
        "second event must wait until the first resolves"
    );
    assert_eq!(claimed[0].event_type, "create");

    // Mark the first succeeded. Now the update should be claimable.
    jobs::mark_success(claimed[0].id, Some("ext-42"), &mut conn)
        .await
        .unwrap();
    let next = jobs::claim_batch(now, 10, &mut conn).await.unwrap();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].event_type, "update");
}

// ---------------------------------------------------------------------------
// End-to-end: adapter dispatches through a wiremock server.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adapter_posts_scim_user_on_created_event() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/Users"))
        .and(header("authorization", "Bearer downstream-secret"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "downstream-42",
            "userName": "alice"
        })))
        .mount(&server)
        .await;

    let pool = pool().await;
    let mut conn = pool.acquire().await.unwrap();

    let target = targets::create(
        "wiremock",
        KIND_GENERIC_SCIM,
        &server.uri(),
        "downstream-secret",
        true,
        None,
        None,
        &fixed_key(),
        &mut conn,
    )
    .await
    .unwrap();

    let user = User::new("alice".into(), "Alice Example".into(), Some("a@x.co".into()));
    user.save(&mut conn).await.unwrap();
    authere_server::provisioning::enqueue(
        &user,
        UserLifecycleEvent::Created,
        "http://origin",
        &mut conn,
    )
    .await
    .unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 1000;
    let claimed = jobs::claim_batch(now, 10, &mut conn).await.unwrap();
    assert_eq!(claimed.len(), 1);
    let job = claimed.into_iter().next().unwrap();

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let adapter = GenericScimAdapter::new(http);
    let body = jobs::decode_payload(&job.payload);
    let outcome = adapter
        .dispatch(&target, "downstream-secret", &job, body)
        .await;

    match outcome {
        AdapterOutcome::Success { external_id } => {
            assert_eq!(external_id.as_deref(), Some("downstream-42"));
        }
        other => panic!("expected success, got {other:?}"),
    }

    jobs::mark_success(job.id, Some("downstream-42"), &mut conn)
        .await
        .unwrap();
    let stored = jobs::get(job.id, &mut conn).await.unwrap().unwrap();
    assert_eq!(stored.status, STATUS_SUCCEEDED);
    assert_eq!(stored.external_resource_id.as_deref(), Some("downstream-42"));
}

#[tokio::test]
async fn adapter_retries_on_5xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/Users"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
        .mount(&server)
        .await;

    let pool = pool().await;
    let mut conn = pool.acquire().await.unwrap();
    let target = targets::create(
        "wiremock",
        KIND_GENERIC_SCIM,
        &server.uri(),
        "tok",
        true,
        None,
        None,
        &fixed_key(),
        &mut conn,
    )
    .await
    .unwrap();

    let user = User::new("bob".into(), "Bob".into(), None);
    user.save(&mut conn).await.unwrap();
    authere_server::provisioning::enqueue(
        &user,
        UserLifecycleEvent::Created,
        "http://origin",
        &mut conn,
    )
    .await
    .unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 1000;
    let claimed = jobs::claim_batch(now, 10, &mut conn).await.unwrap();
    let job = claimed.into_iter().next().unwrap();

    let http = reqwest::Client::builder().build().unwrap();
    let adapter = GenericScimAdapter::new(http);
    let body = jobs::decode_payload(&job.payload);
    let outcome = adapter.dispatch(&target, "tok", &job, body).await;
    assert!(matches!(outcome, AdapterOutcome::RetryableFailure { status: 503, .. }));
}

#[tokio::test]
async fn adapter_permanent_failure_on_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/Users"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let pool = pool().await;
    let mut conn = pool.acquire().await.unwrap();
    let target = targets::create(
        "wiremock",
        KIND_GENERIC_SCIM,
        &server.uri(),
        "wrong-token",
        true,
        None,
        None,
        &fixed_key(),
        &mut conn,
    )
    .await
    .unwrap();

    let user = User::new("carol".into(), "Carol".into(), None);
    user.save(&mut conn).await.unwrap();
    authere_server::provisioning::enqueue(
        &user,
        UserLifecycleEvent::Created,
        "http://origin",
        &mut conn,
    )
    .await
    .unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 1000;
    let job = jobs::claim_batch(now, 10, &mut conn)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let http = reqwest::Client::builder().build().unwrap();
    let adapter = GenericScimAdapter::new(http);
    let body = jobs::decode_payload(&job.payload);
    let outcome = adapter.dispatch(&target, "wrong-token", &job, body).await;
    assert!(matches!(outcome, AdapterOutcome::PermanentFailure { status: 401, .. }));
}

// ---------------------------------------------------------------------------
// M2: coalescing, backfill, target health.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn coalesce_pass_collapses_consecutive_updates() {
    let pool = pool().await;
    seed_target(&pool, "http://unused").await;

    let mut conn = pool.acquire().await.unwrap();
    let user = User::new("alice".into(), "Alice".into(), None);
    user.save(&mut conn).await.unwrap();
    drop(conn);

    // Queue create then three updates.
    {
        let mut tx = pool.begin().await.unwrap();
        authere_server::provisioning::enqueue(
            &user,
            UserLifecycleEvent::Created,
            "http://origin",
            &mut tx,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    for _ in 0..3 {
        std::thread::sleep(std::time::Duration::from_millis(10));
        let mut tx = pool.begin().await.unwrap();
        authere_server::provisioning::enqueue(
            &user,
            UserLifecycleEvent::Updated,
            "http://origin",
            &mut tx,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    let mut conn = pool.acquire().await.unwrap();
    let before: Vec<_> = jobs::list_recent(None, Some(STATUS_PENDING), 100, &mut conn)
        .await
        .unwrap();
    assert_eq!(before.len(), 4);

    let flipped = jobs::run_coalesce_pass(&mut conn).await.unwrap();
    // 2 of the 3 updates should be superseded; create + latest update remain pending.
    assert_eq!(flipped, 2);

    let pending: Vec<_> = jobs::list_recent(None, Some(STATUS_PENDING), 100, &mut conn)
        .await
        .unwrap();
    assert_eq!(pending.len(), 2);
    let superseded: Vec<_> =
        jobs::list_recent(None, Some(jobs::STATUS_SUPERSEDED), 100, &mut conn)
            .await
            .unwrap();
    assert_eq!(superseded.len(), 2);
}

#[tokio::test]
async fn coalesce_pass_is_noop_with_single_job() {
    let pool = pool().await;
    seed_target(&pool, "http://unused").await;

    let mut conn = pool.acquire().await.unwrap();
    let user = User::new("alice".into(), "Alice".into(), None);
    user.save(&mut conn).await.unwrap();
    authere_server::provisioning::enqueue(
        &user,
        UserLifecycleEvent::Created,
        "http://origin",
        &mut conn,
    )
    .await
    .unwrap();
    let flipped = jobs::run_coalesce_pass(&mut conn).await.unwrap();
    assert_eq!(flipped, 0);
}

#[tokio::test]
async fn coalesce_pass_delete_supersedes_everything() {
    let pool = pool().await;
    seed_target(&pool, "http://unused").await;

    let mut conn = pool.acquire().await.unwrap();
    let user = User::new("alice".into(), "Alice".into(), None);
    user.save(&mut conn).await.unwrap();
    authere_server::provisioning::enqueue(
        &user,
        UserLifecycleEvent::Created,
        "http://origin",
        &mut conn,
    )
    .await
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    authere_server::provisioning::enqueue(
        &user,
        UserLifecycleEvent::Updated,
        "http://origin",
        &mut conn,
    )
    .await
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    authere_server::provisioning::enqueue(
        &user,
        UserLifecycleEvent::Deleted,
        "http://origin",
        &mut conn,
    )
    .await
    .unwrap();

    let flipped = jobs::run_coalesce_pass(&mut conn).await.unwrap();
    assert_eq!(flipped, 2);

    let pending = jobs::list_recent(None, Some(STATUS_PENDING), 100, &mut conn)
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].event_type, "delete");
}

#[tokio::test]
async fn backfill_creates_one_job_per_active_user() {
    let pool = pool().await;
    let mut conn = pool.acquire().await.unwrap();
    let alice = User::new("alice".into(), "Alice".into(), None);
    alice.save(&mut conn).await.unwrap();
    let bob = User::new("bob".into(), "Bob".into(), None);
    bob.save(&mut conn).await.unwrap();
    // Inactive user should be skipped.
    let mut carol = User::new("carol".into(), "Carol".into(), None);
    carol.save(&mut conn).await.unwrap();
    carol.set_active(false, &mut conn).await.unwrap();

    let target = authere_server::provisioning::targets::create(
        "bf-target",
        authere_server::provisioning::targets::KIND_GENERIC_SCIM,
        "http://unused",
        "tok",
        true,
        None,
        None,
        &fixed_key(),
        &mut conn,
    )
    .await
    .unwrap();

    let n = authere_server::provisioning::backfill::run_if_needed(
        target.id,
        "http://origin",
        &mut conn,
    )
    .await
    .unwrap();
    assert_eq!(n, 2, "backfill must enqueue one job per active user");

    // Running again is a no-op (backfill_done_at is now set).
    let n2 = authere_server::provisioning::backfill::run_if_needed(
        target.id,
        "http://origin",
        &mut conn,
    )
    .await
    .unwrap();
    assert_eq!(n2, 0);

    // The done-at mark persists.
    let refreshed =
        authere_server::provisioning::targets::get(target.id, &mut conn)
            .await
            .unwrap()
            .unwrap();
    assert!(refreshed.backfill_done_at.is_some());
}

#[tokio::test]
async fn backfill_skips_disabled_target() {
    let pool = pool().await;
    let mut conn = pool.acquire().await.unwrap();
    let alice = User::new("alice".into(), "Alice".into(), None);
    alice.save(&mut conn).await.unwrap();

    let target = authere_server::provisioning::targets::create(
        "disabled",
        authere_server::provisioning::targets::KIND_GENERIC_SCIM,
        "http://unused",
        "tok",
        false,
        None,
        None,
        &fixed_key(),
        &mut conn,
    )
    .await
    .unwrap();

    let n = authere_server::provisioning::backfill::run_if_needed(
        target.id,
        "http://origin",
        &mut conn,
    )
    .await
    .unwrap();
    assert_eq!(n, 0);

    let refreshed =
        authere_server::provisioning::targets::get(target.id, &mut conn)
            .await
            .unwrap()
            .unwrap();
    assert!(refreshed.backfill_done_at.is_none());
}

#[tokio::test]
async fn target_health_reports_last_success_and_consecutive_failures() {
    let pool = pool().await;
    let target_id = seed_target(&pool, "http://unused").await;

    let mut conn = pool.acquire().await.unwrap();
    let user = User::new("alice".into(), "Alice".into(), None);
    user.save(&mut conn).await.unwrap();

    // Enqueue three jobs; mark the first success, the next two permanent failures.
    for _ in 0..3 {
        authere_server::provisioning::enqueue(
            &user,
            UserLifecycleEvent::Updated,
            "http://origin",
            &mut conn,
        )
        .await
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 1000;
    let first = jobs::claim_batch(now, 10, &mut conn).await.unwrap();
    assert_eq!(first.len(), 1, "per-pair FIFO blocks the rest");
    jobs::mark_success(first[0].id, Some("ok"), &mut conn)
        .await
        .unwrap();
    // Now the next can be claimed.
    let second = jobs::claim_batch(now, 10, &mut conn).await.unwrap();
    assert_eq!(second.len(), 1);
    jobs::mark_failure_permanent(second[0].id, 400, "bad", 0, &mut conn)
        .await
        .unwrap();
    let third = jobs::claim_batch(now, 10, &mut conn).await.unwrap();
    assert_eq!(third.len(), 1);
    jobs::mark_failure_permanent(third[0].id, 400, "bad again", 0, &mut conn)
        .await
        .unwrap();

    let health = jobs::compute_health(&mut conn).await.unwrap();
    assert_eq!(health.len(), 1);
    let h = &health[0];
    assert_eq!(h.target_id, target_id);
    assert!(h.last_success_at.is_some());
    assert!(h.last_failure_at.is_some());
    assert_eq!(h.consecutive_failures, 2);
}

#[tokio::test]
async fn target_health_absent_when_no_jobs() {
    let pool = pool().await;
    seed_target(&pool, "http://unused").await;
    let mut conn = pool.acquire().await.unwrap();
    let health = jobs::compute_health(&mut conn).await.unwrap();
    assert!(
        health.is_empty(),
        "no jobs → no health rows (absent means healthy)"
    );
}

#[tokio::test]
async fn attribute_map_renames_top_level_fields_on_wire() {
    use wiremock::matchers::body_partial_json;

    let server = MockServer::start().await;
    // The mock asserts the downstream receives `username` (snake-ish) rather than Authere's
    // `userName`. If the rename didn't apply, wiremock would not match and the request
    // would fall through to a 404 default.
    Mock::given(method("POST"))
        .and(path("/Users"))
        .and(body_partial_json(serde_json::json!({ "username": "alice" })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "mapped-1"
        })))
        .mount(&server)
        .await;

    let pool = pool().await;
    let mut conn = pool.acquire().await.unwrap();
    let target = authere_server::provisioning::targets::create(
        "mapped",
        KIND_GENERIC_SCIM,
        &server.uri(),
        "tok",
        true,
        None,
        Some(r#"{"userName":"username"}"#),
        &fixed_key(),
        &mut conn,
    )
    .await
    .unwrap();

    let user = User::new("alice".into(), "Alice".into(), None);
    user.save(&mut conn).await.unwrap();
    authere_server::provisioning::enqueue(
        &user,
        UserLifecycleEvent::Created,
        "http://origin",
        &mut conn,
    )
    .await
    .unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 1000;
    let job = jobs::claim_batch(now, 10, &mut conn)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    // Simulate what the worker does: apply mapping before handing to the adapter.
    let raw_body = jobs::decode_payload(&job.payload);
    let mapped =
        authere_server::provisioning::mapping::apply_map(target.attribute_map.as_deref(), raw_body);
    assert_eq!(mapped["username"], "alice");
    assert!(mapped.get("userName").is_none());

    let http = reqwest::Client::builder().build().unwrap();
    let adapter = GenericScimAdapter::new(http);
    let outcome = adapter.dispatch(&target, "tok", &job, mapped).await;
    assert!(
        matches!(
            outcome,
            AdapterOutcome::Success {
                external_id: Some(ref id)
            } if id == "mapped-1"
        ),
        "wiremock body matcher required the rename to have applied: {outcome:?}"
    );
}

#[tokio::test]
async fn attribute_map_absent_leaves_body_unchanged() {
    use wiremock::matchers::body_partial_json;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/Users"))
        .and(body_partial_json(serde_json::json!({ "userName": "bob" })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "bob-1"
        })))
        .mount(&server)
        .await;

    let pool = pool().await;
    let mut conn = pool.acquire().await.unwrap();
    let target = authere_server::provisioning::targets::create(
        "no-map",
        KIND_GENERIC_SCIM,
        &server.uri(),
        "tok",
        true,
        None,
        None,
        &fixed_key(),
        &mut conn,
    )
    .await
    .unwrap();

    let user = User::new("bob".into(), "Bob".into(), None);
    user.save(&mut conn).await.unwrap();
    authere_server::provisioning::enqueue(
        &user,
        UserLifecycleEvent::Created,
        "http://origin",
        &mut conn,
    )
    .await
    .unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 1000;
    let job = jobs::claim_batch(now, 10, &mut conn)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let raw_body = jobs::decode_payload(&job.payload);
    let mapped =
        authere_server::provisioning::mapping::apply_map(target.attribute_map.as_deref(), raw_body);
    assert_eq!(mapped["userName"], "bob");

    let http = reqwest::Client::builder().build().unwrap();
    let adapter = GenericScimAdapter::new(http);
    let outcome = adapter.dispatch(&target, "tok", &job, mapped).await;
    assert!(matches!(outcome, AdapterOutcome::Success { .. }));
}

#[tokio::test]
async fn requeue_moves_failed_job_back_to_pending() {
    let pool = pool().await;
    seed_target(&pool, "http://unused").await;

    let mut conn = pool.acquire().await.unwrap();
    let user = User::new("alice".into(), "Alice".into(), None);
    user.save(&mut conn).await.unwrap();
    authere_server::provisioning::enqueue(
        &user,
        UserLifecycleEvent::Created,
        "http://origin",
        &mut conn,
    )
    .await
    .unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 1000;
    let job = jobs::claim_batch(now, 10, &mut conn)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    jobs::mark_failure_permanent(job.id, 400, "nope", 0, &mut conn)
        .await
        .unwrap();

    let stored = jobs::get(job.id, &mut conn).await.unwrap().unwrap();
    assert_eq!(stored.status, "failed");

    assert!(jobs::requeue(job.id, &mut conn).await.unwrap());
    let reset = jobs::get(job.id, &mut conn).await.unwrap().unwrap();
    assert_eq!(reset.status, STATUS_PENDING);
}
