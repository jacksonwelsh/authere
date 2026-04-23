//! SCIM error response shape (RFC 7644 §3.12) and the `AppError` bridge.
//!
//! SCIM errors are distinctive:
//! - `status` is serialized as a *string*, not a number (wire quirk from early drafts)
//! - `scimType` is a vocabulary tag like `"uniqueness"`, `"invalidFilter"`, etc.
//! - Every body must carry the Error URN in `schemas`
//! - Content-Type must be `application/scim+json`
//!
//! Every handler in this module returns `Result<_, ScimError>`. `AppError`s surfaced from
//! shared code convert via `?` through [`From<AppError>`].

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::errors::AppError;
use crate::scim::{ERROR_URN, SCIM_CONTENT_TYPE};

/// SCIM error, converted to an HTTP response on the handler boundary.
#[derive(Debug)]
pub struct ScimError {
    pub status: StatusCode,
    pub scim_type: Option<&'static str>,
    pub detail: String,
}

impl ScimError {
    pub fn unique(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            scim_type: Some("uniqueness"),
            detail: detail.into(),
        }
    }

    pub fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            scim_type: None,
            detail: "resource not found".into(),
        }
    }

    pub fn invalid_filter(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            scim_type: Some("invalidFilter"),
            detail: detail.into(),
        }
    }

    pub fn invalid_path(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            scim_type: Some("invalidPath"),
            detail: detail.into(),
        }
    }

    pub fn invalid_value(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            scim_type: Some("invalidValue"),
            detail: detail.into(),
        }
    }

    pub fn invalid_syntax(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            scim_type: Some("invalidSyntax"),
            detail: detail.into(),
        }
    }

    pub fn mutability(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            scim_type: Some("mutability"),
            detail: detail.into(),
        }
    }

    pub fn no_target(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            scim_type: Some("noTarget"),
            detail: detail.into(),
        }
    }

    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            scim_type: None,
            detail: "authentication required".into(),
        }
    }

    pub fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            scim_type: None,
            detail: "not permitted".into(),
        }
    }

    pub fn precondition_failed() -> Self {
        Self {
            status: StatusCode::PRECONDITION_FAILED,
            scim_type: None,
            detail: "resource version mismatch".into(),
        }
    }

    pub fn too_many() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            scim_type: Some("tooMany"),
            detail: "too many results".into(),
        }
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            scim_type: None,
            detail: detail.into(),
        }
    }

    pub fn rate_limited() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            scim_type: None,
            detail: "rate limit exceeded".into(),
        }
    }
}

#[derive(Serialize)]
struct Body {
    schemas: [&'static str; 1],
    // NB: string, not integer — per RFC 7644.
    status: String,
    #[serde(rename = "scimType", skip_serializing_if = "Option::is_none")]
    scim_type: Option<&'static str>,
    detail: String,
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        let body = Body {
            schemas: [ERROR_URN],
            status: self.status.as_u16().to_string(),
            scim_type: self.scim_type,
            detail: self.detail,
        };
        // If serialization fails we've got bigger problems; fall back to plaintext.
        let json = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, SCIM_CONTENT_TYPE)
            .body(axum::body::Body::from(json))
            .expect("building SCIM error response should not fail")
    }
}

impl From<AppError> for ScimError {
    fn from(err: AppError) -> Self {
        match err {
            AppError::NotFound => Self::not_found(),
            AppError::UniqueError(msg) => Self::unique(msg),
            AppError::InputError(errs) => Self::invalid_value(errs.join("; ")),
            AppError::AuthenticationRequired => Self::unauthorized(),
            AppError::Forbidden => Self::forbidden(),
            AppError::DbError(e) => {
                tracing::error!(error = %e, "scim db error");
                Self::internal("database error")
            }
            AppError::InternalError(msg) => {
                tracing::error!(error = %msg, "scim internal error");
                Self::internal("internal error")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn body_value(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn status_is_serialized_as_string() {
        let resp = ScimError::unique("dup").into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
        assert_eq!(ct.to_str().unwrap(), SCIM_CONTENT_TYPE);
        let v = body_value(resp).await;
        assert_eq!(v["status"], "409");
        assert_eq!(v["scimType"], "uniqueness");
        assert_eq!(v["schemas"], serde_json::json!([ERROR_URN]));
    }

    #[tokio::test]
    async fn not_found_has_no_scim_type() {
        let resp = ScimError::not_found().into_response();
        let v = body_value(resp).await;
        assert_eq!(v["status"], "404");
        assert!(v.get("scimType").is_none());
    }

    #[tokio::test]
    async fn invalid_filter_status_is_400() {
        let resp = ScimError::invalid_filter("bad").into_response();
        let v = body_value(resp).await;
        assert_eq!(v["status"], "400");
        assert_eq!(v["scimType"], "invalidFilter");
    }

    #[tokio::test]
    async fn rate_limited_is_429() {
        let resp = ScimError::rate_limited().into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn from_app_error_not_found() {
        let e: ScimError = AppError::NotFound.into();
        assert_eq!(e.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn from_app_error_unique() {
        let e: ScimError = AppError::UniqueError("dup".into()).into();
        assert_eq!(e.status, StatusCode::CONFLICT);
        assert_eq!(e.scim_type, Some("uniqueness"));
    }

    #[test]
    fn from_app_error_input() {
        let e: ScimError =
            AppError::InputError(vec!["bad a".into(), "bad b".into()]).into();
        assert_eq!(e.status, StatusCode::BAD_REQUEST);
        assert_eq!(e.scim_type, Some("invalidValue"));
        assert!(e.detail.contains("bad a"));
        assert!(e.detail.contains("bad b"));
    }

    #[test]
    fn from_app_error_auth() {
        let e: ScimError = AppError::AuthenticationRequired.into();
        assert_eq!(e.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn from_app_error_forbidden() {
        let e: ScimError = AppError::Forbidden.into();
        assert_eq!(e.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn precondition_failed_is_412() {
        let e = ScimError::precondition_failed();
        assert_eq!(e.status, StatusCode::PRECONDITION_FAILED);
    }
}
