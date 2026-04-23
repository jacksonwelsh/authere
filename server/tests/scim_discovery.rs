//! SCIM discovery endpoint tests. Based on the discovery category of the scim2-tester catalog:
//! ServiceProviderConfig shape, ResourceTypes lists User, Schemas contains core:User.

mod scim_common;

use axum::http::{StatusCode, header};

use scim_common::*;

#[tokio::test]
async fn service_provider_config_requires_auth() {
    let fx = setup().await;
    let resp = get_no_auth(&fx, "/scim/v2/ServiceProviderConfig").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn service_provider_config_returns_scim_content_type() {
    let fx = setup().await;
    let resp = get_with_token(&fx, "/scim/v2/ServiceProviderConfig", &fx.scim_token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
    assert_eq!(ct.to_str().unwrap(), SCIM_CONTENT_TYPE);
}

#[tokio::test]
async fn service_provider_config_shape() {
    let fx = setup().await;
    let resp = get_with_token(&fx, "/scim/v2/ServiceProviderConfig", &fx.scim_token).await;
    let v = body_json(resp).await;
    assert_eq!(v["patch"]["supported"], true);
    assert_eq!(v["bulk"]["supported"], false);
    assert_eq!(v["filter"]["supported"], true);
    assert_eq!(v["sort"]["supported"], false);
    assert_eq!(v["etag"]["supported"], true);
    let schemes = v["authenticationSchemes"].as_array().unwrap();
    assert!(!schemes.is_empty());
    assert_eq!(schemes[0]["type"], "oauthbearertoken");
}

#[tokio::test]
async fn resource_types_lists_user_only() {
    let fx = setup().await;
    let resp = get_with_token(&fx, "/scim/v2/ResourceTypes", &fx.scim_token).await;
    let v = body_json(resp).await;
    assert_eq!(v["totalResults"], 1);
    let resources = v["Resources"].as_array().unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["id"], "User");
}

#[tokio::test]
async fn resource_type_user_reachable_individually() {
    let fx = setup().await;
    let resp = get_with_token(&fx, "/scim/v2/ResourceTypes/User", &fx.scim_token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["id"], "User");
}

#[tokio::test]
async fn resource_type_unknown_returns_404() {
    let fx = setup().await;
    let resp = get_with_token(&fx, "/scim/v2/ResourceTypes/Group", &fx.scim_token).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let v = body_json(resp).await;
    assert_eq!(v["status"], "404");
    assert_eq!(v["schemas"], serde_json::json!(["urn:ietf:params:scim:api:messages:2.0:Error"]));
}

#[tokio::test]
async fn schemas_lists_user_schema() {
    let fx = setup().await;
    let resp = get_with_token(&fx, "/scim/v2/Schemas", &fx.scim_token).await;
    let v = body_json(resp).await;
    assert_eq!(v["totalResults"], 1);
    let resources = v["Resources"].as_array().unwrap();
    assert_eq!(resources[0]["id"], "urn:ietf:params:scim:schemas:core:2.0:User");
}

#[tokio::test]
async fn user_schema_reachable_by_urn() {
    let fx = setup().await;
    let resp = get_with_token(
        &fx,
        "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User",
        &fx.scim_token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["id"], "urn:ietf:params:scim:schemas:core:2.0:User");
    let attrs = v["attributes"].as_array().unwrap();
    // Every attribute in our payload must include `name` and `mutability` — scim2-tester
    // checks for this.
    for a in attrs {
        assert!(a["name"].is_string(), "attribute missing name: {a}");
        assert!(a["mutability"].is_string(), "attribute missing mutability: {a}");
    }
}

#[tokio::test]
async fn unknown_schema_returns_404() {
    let fx = setup().await;
    let resp = get_with_token(&fx, "/scim/v2/Schemas/urn:example:bogus", &fx.scim_token).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
