//! SCIM `/Users?filter=…` end-to-end. Based on the filters category of the scim2-tester
//! catalog: equality by userName, externalId, `pr`, `sw`, `co`, boolean `active`, composite
//! `and/or/not`, and timestamp `meta.lastModified gt`.

mod scim_common;

use axum::http::StatusCode;

use scim_common::*;

async fn list(fx: &Fixture, query: &str) -> serde_json::Value {
    let uri = if query.is_empty() {
        "/scim/v2/Users".to_string()
    } else {
        format!("/scim/v2/Users?{query}")
    };
    let resp = get_with_token(fx, &uri, &fx.scim_token).await;
    assert_eq!(resp.status(), StatusCode::OK, "list failed for {uri}");
    body_json(resp).await
}

fn names(v: &serde_json::Value) -> Vec<String> {
    v["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["userName"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn no_filter_returns_all_users() {
    let fx = setup().await;
    let v = list(&fx, "").await;
    // seed has alice, bob, scim-admin — 3 users
    assert_eq!(v["totalResults"], 3);
    let u = names(&v);
    assert!(u.contains(&"alice".to_string()));
    assert!(u.contains(&"bob".to_string()));
}

#[tokio::test]
async fn filter_by_username_eq() {
    let fx = setup().await;
    let v = list(&fx, "filter=userName%20eq%20%22alice%22").await;
    assert_eq!(v["totalResults"], 1);
    assert_eq!(names(&v), vec!["alice"]);
}

#[tokio::test]
async fn filter_by_username_eq_is_case_insensitive() {
    let fx = setup().await;
    let v = list(&fx, "filter=userName%20eq%20%22ALICE%22").await;
    assert_eq!(v["totalResults"], 1);
}

#[tokio::test]
async fn filter_by_external_id_eq() {
    let fx = setup().await;
    let v = list(&fx, "filter=externalId%20eq%20%22okta-alice%22").await;
    assert_eq!(v["totalResults"], 1);
    assert_eq!(names(&v), vec!["alice"]);
}

#[tokio::test]
async fn filter_username_sw() {
    let fx = setup().await;
    let v = list(&fx, "filter=userName%20sw%20%22a%22").await;
    // alice — scim-admin also starts with 's'
    let ns = names(&v);
    assert!(ns.contains(&"alice".to_string()));
    assert!(!ns.contains(&"bob".to_string()));
}

#[tokio::test]
async fn filter_username_co() {
    let fx = setup().await;
    let v = list(&fx, "filter=userName%20co%20%22lic%22").await;
    assert_eq!(v["totalResults"], 1);
    assert_eq!(names(&v), vec!["alice"]);
}

#[tokio::test]
async fn filter_username_pr() {
    let fx = setup().await;
    let v = list(&fx, "filter=userName%20pr").await;
    assert_eq!(v["totalResults"], 3);
}

#[tokio::test]
async fn filter_active_eq_true_includes_everyone() {
    let fx = setup().await;
    let v = list(&fx, "filter=active%20eq%20true").await;
    assert_eq!(v["totalResults"], 3);
}

#[tokio::test]
async fn filter_active_eq_false_after_deactivation() {
    let fx = setup().await;
    // Deactivate alice directly.
    sqlx::query!("UPDATE users SET active = 0 WHERE id = ?", fx.alice_id)
        .execute(&fx.pool)
        .await
        .unwrap();

    let v = list(&fx, "filter=active%20eq%20false").await;
    assert_eq!(v["totalResults"], 1);
    assert_eq!(names(&v), vec!["alice"]);
}

#[tokio::test]
async fn filter_and_combines() {
    let fx = setup().await;
    let v = list(&fx, "filter=userName%20eq%20%22alice%22%20and%20active%20eq%20true").await;
    assert_eq!(v["totalResults"], 1);
}

#[tokio::test]
async fn filter_or_combines() {
    let fx = setup().await;
    let v = list(
        &fx,
        "filter=userName%20eq%20%22alice%22%20or%20userName%20eq%20%22bob%22",
    )
    .await;
    assert_eq!(v["totalResults"], 2);
}

#[tokio::test]
async fn filter_not_inverts() {
    let fx = setup().await;
    let v = list(&fx, "filter=not%20(userName%20eq%20%22alice%22)").await;
    assert_eq!(v["totalResults"], 2);
}

#[tokio::test]
async fn filter_meta_lastmodified_gt_future_returns_empty() {
    let fx = setup().await;
    // A far-future timestamp — nobody should match.
    let v = list(&fx, "filter=meta.lastModified%20gt%20%222099-01-01T00:00:00Z%22").await;
    assert_eq!(v["totalResults"], 0);
}

#[tokio::test]
async fn filter_meta_lastmodified_gt_epoch_returns_all() {
    let fx = setup().await;
    let v = list(&fx, "filter=meta.lastModified%20gt%20%221970-01-01T00:00:00Z%22").await;
    assert_eq!(v["totalResults"], 3);
}

#[tokio::test]
async fn invalid_filter_returns_400_invalid_filter() {
    let fx = setup().await;
    let resp = get_with_token(&fx, "/scim/v2/Users?filter=this%20is%20nonsense", &fx.scim_token).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = body_json(resp).await;
    assert_eq!(v["scimType"], "invalidFilter");
}

#[tokio::test]
async fn unknown_attribute_is_invalid_filter() {
    let fx = setup().await;
    let resp = get_with_token(
        &fx,
        "/scim/v2/Users?filter=phoneNumbers%20eq%20%22555%22",
        &fx.scim_token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = body_json(resp).await;
    assert_eq!(v["scimType"], "invalidFilter");
}

#[tokio::test]
async fn pagination_count_clamps_and_honors_start_index() {
    let fx = setup().await;
    let v = list(&fx, "startIndex=1&count=2").await;
    assert_eq!(v["totalResults"], 3);
    assert_eq!(v["itemsPerPage"], 2);
    assert_eq!(v["startIndex"], 1);
    let first_page_count = v["Resources"].as_array().unwrap().len();
    assert_eq!(first_page_count, 2);

    let v = list(&fx, "startIndex=3&count=2").await;
    assert_eq!(v["startIndex"], 3);
    assert_eq!(v["itemsPerPage"], 1);
}
