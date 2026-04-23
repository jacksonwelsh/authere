//! SCIM error response shape. Based on the errors category of the scim2-tester catalog —
//! status is a string, schemas includes the Error URN, scimType is present for 4xx
//! vocabulary errors.

mod scim_common;

use axum::http::{StatusCode, header};

use scim_common::*;

#[tokio::test]
async fn error_body_has_string_status_and_error_schema() {
    let fx = setup().await;
    // Wrong token → 401.
    let resp = get_with_token(&fx, "/scim/v2/Users", "authere_scim_bogus_00000000000000000000000000000000").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
    assert_eq!(ct.to_str().unwrap(), SCIM_CONTENT_TYPE);

    let v = body_json(resp).await;
    // Status must be a string, not a number (quirk from early SCIM drafts)
    assert!(v["status"].is_string(), "status must serialize as string");
    assert_eq!(v["status"], "401");
    assert_eq!(
        v["schemas"],
        serde_json::json!(["urn:ietf:params:scim:api:messages:2.0:Error"])
    );
}

#[tokio::test]
async fn get_unknown_user_returns_404_without_scim_type() {
    let fx = setup().await;
    let resp = get_with_token(
        &fx,
        "/scim/v2/Users/00000000-0000-0000-0000-000000000000",
        &fx.scim_token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let v = body_json(resp).await;
    assert_eq!(v["status"], "404");
    // 404 has no scimType vocabulary tag.
    assert!(v.get("scimType").is_none());
}

#[tokio::test]
async fn get_user_returns_etag_on_200() {
    let fx = setup().await;
    let resp = get_with_token(
        &fx,
        &format!("/scim/v2/Users/{}", fx.alice_id),
        &fx.scim_token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let etag = resp.headers().get(header::ETAG).expect("etag header");
    let s = etag.to_str().unwrap();
    assert!(s.starts_with("W/\""), "expected weak etag, got {s:?}");
}

#[tokio::test]
async fn get_user_roundtrips_name_and_emails() {
    let fx = setup().await;
    let resp = get_with_token(
        &fx,
        &format!("/scim/v2/Users/{}", fx.alice_id),
        &fx.scim_token,
    )
    .await;
    let v = body_json(resp).await;
    assert_eq!(v["userName"], "alice");
    assert_eq!(v["name"]["formatted"], "Alice Example");
    assert_eq!(v["emails"][0]["value"], "alice@example.com");
    assert_eq!(v["emails"][0]["primary"], true);
    assert_eq!(v["externalId"], "okta-alice");
    assert_eq!(v["meta"]["resourceType"], "User");
    assert!(v["meta"]["location"].as_str().unwrap().ends_with(&fx.alice_id.to_string()));
}

#[tokio::test]
async fn malformed_uuid_returns_400_not_500() {
    let fx = setup().await;
    let resp = get_with_token(&fx, "/scim/v2/Users/not-a-uuid", &fx.scim_token).await;
    // axum's Path rejection on uuid parse produces a 400. We don't wrap that through our
    // ScimError, but we want to confirm at minimum it's a 4xx and not an internal error.
    assert!(resp.status().is_client_error(), "got {:?}", resp.status());
}
