//! SCIM discovery endpoints: `ServiceProviderConfig`, `ResourceTypes`, `Schemas` (RFC 7643 §5, §6).
//!
//! These are largely static JSON payloads advertising what the server supports. They must
//! be reachable with a valid SCIM bearer token — several IdPs probe these before sending any
//! user mutations, and refusing them at the auth layer would break onboarding.

use axum::extract::Path;
use axum::response::IntoResponse;
use serde_json::{Value, json};

use crate::scim::USER_SCHEMA_URN;
use crate::scim::auth::ScimAuth;
use crate::scim::error::ScimError;
use crate::scim::schema::{ListResponse, ScimJson};

const TAG: &str = "scim";

fn service_provider_config_body() -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://datatracker.ietf.org/doc/html/rfc7644",
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": 200 },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": true },
        "authenticationSchemes": [
            {
                "name": "OAuth Bearer Token",
                "description": "Authenticate with an admin-issued Authere SCIM token.",
                "specUri": "https://datatracker.ietf.org/doc/html/rfc6750",
                "documentationUri": "https://datatracker.ietf.org/doc/html/rfc7644#section-2",
                "type": "oauthbearertoken",
                "primary": true
            }
        ]
    })
}

fn user_resource_type() -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "User",
        "name": "User",
        "endpoint": "/Users",
        "description": "User Account",
        "schema": USER_SCHEMA_URN,
        "schemaExtensions": [],
        "meta": {
            "resourceType": "ResourceType",
            "location": "/scim/v2/ResourceTypes/User"
        }
    })
}

fn user_schema() -> Value {
    // Abridged core User schema — only the attributes we actually support. IdPs rely on this
    // listing to know which fields to send; attributes we omit here must also be rejected by
    // the handlers (see `scim::patch` and `scim::users`).
    json!({
        "id": USER_SCHEMA_URN,
        "name": "User",
        "description": "User Account",
        "attributes": [
            {
                "name": "userName",
                "type": "string",
                "multiValued": false,
                "required": true,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "server"
            },
            {
                "name": "name",
                "type": "complex",
                "multiValued": false,
                "required": false,
                "mutability": "readWrite",
                "returned": "default",
                "subAttributes": [
                    {"name": "formatted", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default"},
                    {"name": "familyName", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default"},
                    {"name": "givenName", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default"}
                ]
            },
            {
                "name": "displayName",
                "type": "string",
                "multiValued": false,
                "required": false,
                "mutability": "readWrite",
                "returned": "default"
            },
            {
                "name": "emails",
                "type": "complex",
                "multiValued": true,
                "required": false,
                "mutability": "readWrite",
                "returned": "default",
                "subAttributes": [
                    {"name": "value", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default"},
                    {"name": "type", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default"},
                    {"name": "primary", "type": "boolean", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default"}
                ]
            },
            {
                "name": "active",
                "type": "boolean",
                "multiValued": false,
                "required": false,
                "mutability": "readWrite",
                "returned": "default"
            }
        ],
        "meta": {
            "resourceType": "Schema",
            "location": format!("/scim/v2/Schemas/{USER_SCHEMA_URN}")
        }
    })
}

#[utoipa::path(
    get,
    path = "/scim/v2/ServiceProviderConfig",
    responses((status = 200, description = "SCIM capabilities advertisement")),
    tag = TAG,
)]
pub async fn service_provider_config(_auth: ScimAuth) -> impl IntoResponse {
    ScimJson::new(service_provider_config_body())
}

#[utoipa::path(
    get,
    path = "/scim/v2/ResourceTypes",
    responses((status = 200, description = "Supported SCIM resource types")),
    tag = TAG,
)]
pub async fn list_resource_types(_auth: ScimAuth) -> impl IntoResponse {
    ScimJson::new(ListResponse::new(vec![user_resource_type()], 1, 1))
}

#[utoipa::path(
    get,
    path = "/scim/v2/ResourceTypes/{id}",
    params(("id" = String, Path, description = "Resource type id (User)")),
    responses(
        (status = 200, description = "Resource type definition"),
        (status = 404, description = "Unknown resource type"),
    ),
    tag = TAG,
)]
pub async fn get_resource_type(
    _auth: ScimAuth,
    Path(id): Path<String>,
) -> Result<ScimJson<Value>, ScimError> {
    if id.eq_ignore_ascii_case("user") {
        Ok(ScimJson::new(user_resource_type()))
    } else {
        Err(ScimError::not_found())
    }
}

#[utoipa::path(
    get,
    path = "/scim/v2/Schemas",
    responses((status = 200, description = "Supported SCIM schemas")),
    tag = TAG,
)]
pub async fn list_schemas(_auth: ScimAuth) -> impl IntoResponse {
    ScimJson::new(ListResponse::new(vec![user_schema()], 1, 1))
}

#[utoipa::path(
    get,
    path = "/scim/v2/Schemas/{id}",
    params(("id" = String, Path, description = "Schema URN, e.g. urn:ietf:params:scim:schemas:core:2.0:User")),
    responses(
        (status = 200, description = "Schema definition"),
        (status = 404, description = "Unknown schema"),
    ),
    tag = TAG,
)]
pub async fn get_schema(
    _auth: ScimAuth,
    Path(id): Path<String>,
) -> Result<ScimJson<Value>, ScimError> {
    if id == USER_SCHEMA_URN {
        Ok(ScimJson::new(user_schema()))
    } else {
        Err(ScimError::not_found())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_provider_config_advertises_bearer_auth() {
        let v = service_provider_config_body();
        let schemes = v["authenticationSchemes"].as_array().unwrap();
        assert_eq!(schemes.len(), 1);
        assert_eq!(schemes[0]["type"], "oauthbearertoken");
    }

    #[test]
    fn service_provider_config_says_patch_yes_bulk_no() {
        let v = service_provider_config_body();
        assert_eq!(v["patch"]["supported"], true);
        assert_eq!(v["bulk"]["supported"], false);
        assert_eq!(v["filter"]["supported"], true);
        assert_eq!(v["sort"]["supported"], false);
        assert_eq!(v["etag"]["supported"], true);
    }

    #[test]
    fn user_resource_type_points_at_core_schema() {
        let v = user_resource_type();
        assert_eq!(v["id"], "User");
        assert_eq!(v["endpoint"], "/Users");
        assert_eq!(v["schema"], USER_SCHEMA_URN);
    }

    #[test]
    fn user_schema_required_fields_are_marked() {
        let v = user_schema();
        let attrs = v["attributes"].as_array().unwrap();
        let user_name = attrs
            .iter()
            .find(|a| a["name"] == "userName")
            .expect("userName attribute");
        assert_eq!(user_name["required"], true);
        assert_eq!(user_name["uniqueness"], "server");
    }

    #[test]
    fn user_schema_emails_is_multivalued() {
        let v = user_schema();
        let attrs = v["attributes"].as_array().unwrap();
        let emails = attrs.iter().find(|a| a["name"] == "emails").unwrap();
        assert_eq!(emails["multiValued"], true);
    }
}
