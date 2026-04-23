//! User lifecycle events and their SCIM-body projections.
//!
//! `build_scim_body` is pure: it takes a user snapshot + event kind and returns the JSON body
//! the outbound request should carry. The worker never reaches back to the DB to rebuild
//! a body — the payload stored on the job is authoritative.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::scim::PATCH_OP_URN;
use crate::scim::schema::ScimUser;
use crate::user::User;

/// One of five lifecycle transitions we push downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserLifecycleEvent {
    Created,
    Updated,
    Deactivated,
    Reactivated,
    Deleted,
}

impl UserLifecycleEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "create",
            Self::Updated => "update",
            Self::Deactivated => "deactivate",
            Self::Reactivated => "reactivate",
            Self::Deleted => "delete",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "create" => Some(Self::Created),
            "update" => Some(Self::Updated),
            "deactivate" => Some(Self::Deactivated),
            "reactivate" => Some(Self::Reactivated),
            "delete" => Some(Self::Deleted),
            _ => None,
        }
    }
}

/// Build the SCIM wire body for one lifecycle event. Pure — safe to unit test in isolation.
///
/// - `Created` / `Updated` → full `ScimUser` resource (POST body or PUT body)
/// - `Deactivated` / `Reactivated` → SCIM PatchOp replacing `active`
/// - `Deleted` → `null` (DELETE has no body)
pub fn build_scim_body(user: &User, event: UserLifecycleEvent, origin: &str) -> Value {
    match event {
        UserLifecycleEvent::Created | UserLifecycleEvent::Updated => {
            let scim = ScimUser::from_user(user, origin);
            serde_json::to_value(&scim).unwrap_or(Value::Null)
        }
        UserLifecycleEvent::Deactivated | UserLifecycleEvent::Reactivated => {
            let active = matches!(event, UserLifecycleEvent::Reactivated);
            json!({
                "schemas": [PATCH_OP_URN],
                "Operations": [
                    { "op": "replace", "path": "active", "value": active }
                ]
            })
        }
        UserLifecycleEvent::Deleted => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn sample_user() -> User {
        User {
            id: Uuid::nil(),
            username: "alice".into(),
            name: "Alice Example".into(),
            email: Some("alice@example.com".into()),
            active: true,
            external_id: Some("okta-42".into()),
            created_at: 1_700_000_000,
            updated_at: 1_700_000_500,
        }
    }

    #[test]
    fn event_str_roundtrip() {
        for e in [
            UserLifecycleEvent::Created,
            UserLifecycleEvent::Updated,
            UserLifecycleEvent::Deactivated,
            UserLifecycleEvent::Reactivated,
            UserLifecycleEvent::Deleted,
        ] {
            assert_eq!(UserLifecycleEvent::from_str(e.as_str()), Some(e));
        }
    }

    #[test]
    fn from_str_rejects_garbage() {
        assert!(UserLifecycleEvent::from_str("bogus").is_none());
        assert!(UserLifecycleEvent::from_str("").is_none());
    }

    #[test]
    fn build_body_created_is_full_resource() {
        let u = sample_user();
        let body = build_scim_body(&u, UserLifecycleEvent::Created, "https://x.co");
        assert_eq!(body["userName"], "alice");
        assert_eq!(body["displayName"], "Alice Example");
        assert_eq!(body["active"], true);
        assert!(body["schemas"].is_array());
        // meta.location should be set — that proves from_user ran with our origin.
        assert!(
            body["meta"]["location"]
                .as_str()
                .unwrap()
                .starts_with("https://x.co/scim/v2/Users/")
        );
    }

    #[test]
    fn build_body_updated_is_same_shape_as_created() {
        let u = sample_user();
        let created = build_scim_body(&u, UserLifecycleEvent::Created, "https://x.co");
        let updated = build_scim_body(&u, UserLifecycleEvent::Updated, "https://x.co");
        assert_eq!(created, updated);
    }

    #[test]
    fn build_body_deactivated_is_patchop_with_active_false() {
        let u = sample_user();
        let body = build_scim_body(&u, UserLifecycleEvent::Deactivated, "https://x.co");
        assert_eq!(body["schemas"][0], PATCH_OP_URN);
        let ops = body["Operations"].as_array().unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0]["op"], "replace");
        assert_eq!(ops[0]["path"], "active");
        assert_eq!(ops[0]["value"], false);
    }

    #[test]
    fn build_body_reactivated_is_patchop_with_active_true() {
        let u = sample_user();
        let body = build_scim_body(&u, UserLifecycleEvent::Reactivated, "https://x.co");
        assert_eq!(body["Operations"][0]["value"], true);
    }

    #[test]
    fn build_body_deleted_is_null() {
        let u = sample_user();
        let body = build_scim_body(&u, UserLifecycleEvent::Deleted, "https://x.co");
        assert!(body.is_null());
    }

    #[test]
    fn build_body_respects_origin_trailing_slash() {
        let u = sample_user();
        let body = build_scim_body(&u, UserLifecycleEvent::Created, "https://x.co/");
        let loc = body["meta"]["location"].as_str().unwrap();
        assert!(!loc.starts_with("https://x.co//"));
    }

    #[test]
    fn build_body_includes_external_id_when_present() {
        let u = sample_user();
        let body = build_scim_body(&u, UserLifecycleEvent::Created, "https://x.co");
        assert_eq!(body["externalId"], "okta-42");
    }

    #[test]
    fn build_body_omits_external_id_when_absent() {
        let mut u = sample_user();
        u.external_id = None;
        let body = build_scim_body(&u, UserLifecycleEvent::Created, "https://x.co");
        assert!(body.get("externalId").is_none_or(|v| v.is_null()));
    }
}
