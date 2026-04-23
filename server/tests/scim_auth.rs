//! SCIM bearer-token enforcement. Based on the auth category of the scim2-tester catalog.

mod scim_common;

use axum::http::StatusCode;

use authere_server::scim;

use scim_common::*;

#[tokio::test]
async fn unauthenticated_request_is_401() {
    let fx = setup().await;
    let resp = get_no_auth(&fx, "/scim/v2/Users").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let v = body_json(resp).await;
    assert_eq!(v["status"], "401");
}

#[tokio::test]
async fn basic_auth_is_rejected() {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;
    let fx = setup().await;
    let req = Request::builder()
        .uri("/scim/v2/Users")
        .header("authorization", "Basic YWRtaW46c2VjcmV0")
        .body(Body::empty())
        .unwrap();
    let resp = fx.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_prefix_is_rejected_without_db_lookup() {
    let fx = setup().await;
    let resp = get_with_token(&fx, "/scim/v2/Users", "jwt.eyJhbGc").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn fake_prefix_token_is_rejected() {
    let fx = setup().await;
    let resp = get_with_token(
        &fx,
        "/scim/v2/Users",
        "authere_scim_not_a_real_token_0000000000",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn valid_token_grants_access() {
    let fx = setup().await;
    let resp = get_with_token(&fx, "/scim/v2/Users", &fx.scim_token).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn revoked_token_is_rejected() {
    let fx = setup().await;
    // Find the token id by hash, then revoke.
    let mut conn = fx.pool.acquire().await.unwrap();
    let list = scim::token::list(&mut conn).await.unwrap();
    assert_eq!(list.len(), 1);
    scim::token::revoke(list[0].id, &mut conn).await.unwrap();
    drop(conn);

    let resp = get_with_token(&fx, "/scim/v2/Users", &fx.scim_token).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn last_used_at_is_recorded_after_request() {
    let fx = setup().await;
    let resp = get_with_token(&fx, "/scim/v2/ServiceProviderConfig", &fx.scim_token).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let mut conn = fx.pool.acquire().await.unwrap();
    let list = scim::token::list(&mut conn).await.unwrap();
    assert!(
        list[0].last_used_at.is_some(),
        "last_used_at should have been populated on first use"
    );
}
