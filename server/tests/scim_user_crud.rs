//! SCIM `/Users` CRUD: POST, PUT, DELETE. PATCH lives in its own file.

mod scim_common;

use axum::http::{StatusCode, header};
use serde_json::json;

use scim_common::*;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

fn minimal_user_body(user_name: &str) -> serde_json::Value {
    json!({
        "schemas": [USER_SCHEMA],
        "userName": user_name,
        "name": { "formatted": "Test User" },
        "emails": [{ "value": format!("{user_name}@test.co"), "primary": true }],
        "active": true
    })
}

#[tokio::test]
async fn create_returns_201_with_location_and_etag() {
    let fx = setup().await;
    let resp = post_json(&fx, "/scim/v2/Users", &fx.scim_token, minimal_user_body("newuser")).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let loc = resp.headers().get(header::LOCATION).expect("Location");
    let loc_str = loc.to_str().unwrap().to_string();
    assert!(loc_str.contains("/scim/v2/Users/"), "location: {loc_str}");

    let etag = resp.headers().get(header::ETAG).expect("ETag");
    assert!(etag.to_str().unwrap().starts_with("W/\""));

    let v = body_json(resp).await;
    assert_eq!(v["userName"], "newuser");
    assert_eq!(v["emails"][0]["value"], "newuser@test.co");
    assert!(v["id"].is_string());
    assert!(v["meta"]["location"].as_str().unwrap().ends_with(v["id"].as_str().unwrap()));
}

#[tokio::test]
async fn create_rejects_duplicate_username_case_insensitive() {
    let fx = setup().await;
    // alice already exists in the fixture.
    let resp = post_json(&fx, "/scim/v2/Users", &fx.scim_token, minimal_user_body("ALICE")).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let v = body_json(resp).await;
    assert_eq!(v["scimType"], "uniqueness");
}

#[tokio::test]
async fn create_rejects_duplicate_external_id() {
    let fx = setup().await;
    let mut body = minimal_user_body("someone_new");
    body["externalId"] = json!("okta-alice"); // alice already has this externalId
    let resp = post_json(&fx, "/scim/v2/Users", &fx.scim_token, body).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let v = body_json(resp).await;
    assert_eq!(v["scimType"], "uniqueness");
}

#[tokio::test]
async fn create_constructs_display_name_from_given_and_family() {
    let fx = setup().await;
    let body = json!({
        "schemas": [USER_SCHEMA],
        "userName": "carol",
        "name": { "givenName": "Carol", "familyName": "Smith" },
        "active": true
    });
    let resp = post_json(&fx, "/scim/v2/Users", &fx.scim_token, body).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = body_json(resp).await;
    assert_eq!(v["name"]["formatted"], "Carol Smith");
}

#[tokio::test]
async fn create_without_any_name_is_400() {
    let fx = setup().await;
    let body = json!({
        "schemas": [USER_SCHEMA],
        "userName": "nameless",
        "active": true
    });
    let resp = post_json(&fx, "/scim/v2/Users", &fx.scim_token, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_replaces_full_resource() {
    let fx = setup().await;
    let uri = format!("/scim/v2/Users/{}", fx.alice_id);
    let body = json!({
        "schemas": [USER_SCHEMA],
        "userName": "alice_renamed",
        "name": { "formatted": "Alice Renamed" },
        "emails": [{ "value": "alice.new@example.com", "primary": true }],
        "active": true,
        "externalId": "okta-alice-v2"
    });
    let resp = put_json(&fx, &uri, &fx.scim_token, body).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["userName"], "alice_renamed");
    assert_eq!(v["emails"][0]["value"], "alice.new@example.com");
    assert_eq!(v["externalId"], "okta-alice-v2");
}

#[tokio::test]
async fn put_missing_user_returns_404() {
    let fx = setup().await;
    let body = minimal_user_body("ghost");
    let resp = put_json(&fx, "/scim/v2/Users/00000000-0000-0000-0000-000000000000", &fx.scim_token, body).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn if_match_with_wrong_version_returns_412() {
    let fx = setup().await;
    let uri = format!("/scim/v2/Users/{}", fx.alice_id);
    let resp = request(
        &fx,
        "PUT",
        &uri,
        Some(&fx.scim_token),
        Some(minimal_user_body("alice2")),
        &[("if-match", "W/\"999999\"")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn if_match_star_always_matches() {
    let fx = setup().await;
    let uri = format!("/scim/v2/Users/{}", fx.alice_id);
    let resp = request(
        &fx,
        "PUT",
        &uri,
        Some(&fx.scim_token),
        Some(minimal_user_body("alice_star")),
        &[("if-match", "*")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn delete_removes_user_then_get_is_404() {
    let fx = setup().await;
    let uri = format!("/scim/v2/Users/{}", fx.alice_id);
    let resp = delete(&fx, &uri, &fx.scim_token).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = get_with_token(&fx, &uri, &fx.scim_token).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_already_gone_returns_404() {
    let fx = setup().await;
    let uri = "/scim/v2/Users/00000000-0000-0000-0000-000000000000";
    let resp = delete(&fx, uri, &fx.scim_token).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_then_get_by_id_roundtrips() {
    let fx = setup().await;
    let resp = post_json(&fx, "/scim/v2/Users", &fx.scim_token, minimal_user_body("diana")).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    let id = created["id"].as_str().unwrap();

    let resp = get_with_token(&fx, &format!("/scim/v2/Users/{id}"), &fx.scim_token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let got = body_json(resp).await;
    assert_eq!(got["userName"], "diana");
}
