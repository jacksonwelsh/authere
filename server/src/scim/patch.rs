//! SCIM PATCH operations (RFC 7644 §3.5.2).
//!
//! IdP behavior, not RFC purity, drives what we support. In practice Okta, Azure AD, and
//! OneLogin all send one of:
//!
//!   - Empty-path replace: `{"op":"replace","value":{"active":false}}` — Azure AD's idiom
//!   - Pathed replace/add/remove: `{"op":"replace","path":"active","value":false}` — Okta's
//!   - PATCH `name.givenName` individually — occasional; documented lossy since we store one
//!     string in `users.name`
//!   - PATCH `emails[type eq "work"].value` — accepted as `emails.value` (we only store one)
//!
//! Unsupported attributes (`groups`, `roles`, `phoneNumbers`, `addresses`, enterprise ext)
//! return `invalidPath`. `remove` on `active` is rejected because `active` is required.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::scim::PATCH_OP_URN;
use crate::scim::error::ScimError;
use crate::scim::schema::{Email, Name, ScimUser};

/// Raw PATCH body as sent by the client. See RFC 7644 §3.5.2.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PatchOp {
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(rename = "Operations", default)]
    pub operations: Vec<PatchOperation>,
}

impl PatchOp {
    pub fn validate_schema(&self) -> Result<(), ScimError> {
        if !self.schemas.iter().any(|s| s == PATCH_OP_URN) {
            return Err(ScimError::invalid_syntax(format!(
                "PATCH body must include {PATCH_OP_URN} in schemas"
            )));
        }
        if self.operations.is_empty() {
            return Err(ScimError::invalid_syntax(
                "PATCH body must include at least one operation",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PatchOperation {
    /// case-insensitive per spec; we normalize on parse
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Add,
    Remove,
    Replace,
}

impl Action {
    fn parse(raw: &str) -> Result<Self, ScimError> {
        match raw.to_ascii_lowercase().as_str() {
            "add" => Ok(Self::Add),
            "remove" => Ok(Self::Remove),
            "replace" => Ok(Self::Replace),
            other => Err(ScimError::invalid_syntax(format!(
                "unknown PATCH op: {other}"
            ))),
        }
    }
}

/// Normalize a SCIM path expression like `emails[type eq "work"].value` to one of our
/// supported paths (e.g. `emails.value`). The result is the canonical path we dispatch on.
/// Returns `invalidPath` for anything we don't handle.
fn normalize_path(raw: &str) -> Result<String, ScimError> {
    let trimmed = raw.trim();
    // Strip URN prefix — clients sometimes send urn:...:User:userName.
    let stripped = trimmed.rsplit_once(':').map(|(_, t)| t).unwrap_or(trimmed);
    // Handle the emails[... eq ...].value idiom. We always store one email, so the filter
    // inside the brackets is ignored — we just route the write to our single slot.
    if let Some(rest) = stripped.strip_prefix("emails[") {
        let close = rest
            .find(']')
            .ok_or_else(|| ScimError::invalid_path("unterminated '[' in path"))?;
        let after = &rest[close + 1..];
        return Ok(match after {
            "" | ".value" => "emails.value".to_string(),
            ".type" | ".primary" | ".display" => {
                return Err(ScimError::invalid_path(format!(
                    "emails sub-attribute {after} is not supported (we store a single email)"
                )));
            }
            other => {
                return Err(ScimError::invalid_path(format!(
                    "unsupported emails sub-attribute: {other}"
                )));
            }
        });
    }
    Ok(stripped.to_ascii_lowercase())
}

/// Apply all PATCH operations in order against a working copy of `user`. Failure at any
/// operation leaves the caller-side snapshot in an unspecified state — the caller must discard
/// and not persist; this is why we operate on an owned clone inside the handler.
pub fn apply_all(user: &mut ScimUser, ops: &[PatchOperation]) -> Result<(), ScimError> {
    for op in ops {
        apply_one(user, op)?;
    }
    Ok(())
}

fn apply_one(user: &mut ScimUser, op: &PatchOperation) -> Result<(), ScimError> {
    let action = Action::parse(&op.op)?;

    match &op.path {
        None => apply_empty_path(user, action, op.value.as_ref()),
        Some(raw) => {
            let path = normalize_path(raw)?;
            dispatch_path(user, action, &path, op.value.as_ref())
        }
    }
}

/// Empty-path PATCH: value must be an object, and each top-level key is treated as an
/// individual sub-operation with that key as the path. This is Azure AD's idiom.
fn apply_empty_path(
    user: &mut ScimUser,
    action: Action,
    value: Option<&Value>,
) -> Result<(), ScimError> {
    let obj = value
        .and_then(|v| v.as_object())
        .ok_or_else(|| ScimError::invalid_value("empty-path PATCH requires an object value"))?;
    for (k, v) in obj {
        let path = k.to_ascii_lowercase();
        dispatch_path(user, action, &path, Some(v))?;
    }
    Ok(())
}

fn dispatch_path(
    user: &mut ScimUser,
    action: Action,
    path: &str,
    value: Option<&Value>,
) -> Result<(), ScimError> {
    match path {
        "active" => set_active(user, action, value),
        "username" => set_username(user, action, value),
        "displayname" => set_display_name(user, action, value),
        "externalid" => set_external_id(user, action, value),
        "name" => set_name_object(user, action, value),
        "name.formatted" => set_name_subfield(user, action, value, NameField::Formatted),
        "name.givenname" => set_name_subfield(user, action, value, NameField::Given),
        "name.familyname" => set_name_subfield(user, action, value, NameField::Family),
        "emails" | "emails.value" => set_emails(user, action, value),
        other => Err(ScimError::invalid_path(format!(
            "attribute {other} is not writable or not supported"
        ))),
    }
}

// ----------------------------------------------------------------------------
// Individual attribute handlers.
// ----------------------------------------------------------------------------

fn set_active(
    user: &mut ScimUser,
    action: Action,
    value: Option<&Value>,
) -> Result<(), ScimError> {
    match action {
        Action::Remove => Err(ScimError::invalid_value(
            "cannot remove required attribute 'active'",
        )),
        Action::Add | Action::Replace => {
            let b = value
                .and_then(|v| match v {
                    Value::Bool(b) => Some(*b),
                    Value::String(s) => match s.to_ascii_lowercase().as_str() {
                        "true" => Some(true),
                        "false" => Some(false),
                        _ => None,
                    },
                    _ => None,
                })
                .ok_or_else(|| ScimError::invalid_value("active must be boolean"))?;
            user.active = b;
            Ok(())
        }
    }
}

fn set_username(
    user: &mut ScimUser,
    action: Action,
    value: Option<&Value>,
) -> Result<(), ScimError> {
    match action {
        Action::Remove => Err(ScimError::invalid_value(
            "cannot remove required attribute 'userName'",
        )),
        Action::Add | Action::Replace => {
            let s = require_string(value, "userName")?;
            user.user_name = s;
            Ok(())
        }
    }
}

fn set_display_name(
    user: &mut ScimUser,
    action: Action,
    value: Option<&Value>,
) -> Result<(), ScimError> {
    // Authere stores a single display string shared between SCIM's `displayName` and
    // `name.formatted`. We therefore sync both here so the new value wins during persistence
    // regardless of which one `resolve_display_name` happens to consult first.
    match action {
        Action::Remove => {
            user.display_name = None;
            if let Some(ref mut n) = user.name {
                n.formatted = None;
            }
            Ok(())
        }
        Action::Add | Action::Replace => {
            let s = require_string(value, "displayName")?;
            user.display_name = Some(s.clone());
            let mut n = user.name.clone().unwrap_or_default();
            n.formatted = Some(s);
            user.name = Some(n);
            Ok(())
        }
    }
}

fn set_external_id(
    user: &mut ScimUser,
    action: Action,
    value: Option<&Value>,
) -> Result<(), ScimError> {
    match action {
        Action::Remove => {
            user.external_id = None;
            Ok(())
        }
        Action::Add | Action::Replace => {
            let s = require_string(value, "externalId")?;
            user.external_id = Some(s);
            Ok(())
        }
    }
}

fn set_name_object(
    user: &mut ScimUser,
    action: Action,
    value: Option<&Value>,
) -> Result<(), ScimError> {
    match action {
        Action::Remove => {
            user.name = None;
            Ok(())
        }
        Action::Add | Action::Replace => {
            let v = value.ok_or_else(|| ScimError::invalid_value("name requires a value"))?;
            let name: Name = serde_json::from_value(v.clone())
                .map_err(|e| ScimError::invalid_value(format!("invalid name object: {e}")))?;
            user.name = Some(name);
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum NameField {
    Formatted,
    Given,
    Family,
}

fn set_name_subfield(
    user: &mut ScimUser,
    action: Action,
    value: Option<&Value>,
    field: NameField,
) -> Result<(), ScimError> {
    let mut n = user.name.clone().unwrap_or_default();
    match action {
        Action::Remove => match field {
            NameField::Formatted => {
                n.formatted = None;
                // displayName would otherwise shadow a cleared formatted.
                user.display_name = None;
            }
            NameField::Given => {
                n.given_name = None;
                // Patching a half-name invalidates the pre-rendered formatted string; let
                // `resolve_display_name` rebuild from remaining subfields.
                n.formatted = None;
                user.display_name = None;
            }
            NameField::Family => {
                n.family_name = None;
                n.formatted = None;
                user.display_name = None;
            }
        },
        Action::Add | Action::Replace => {
            let s = require_string(value, "name sub-attribute")?;
            match field {
                NameField::Formatted => {
                    n.formatted = Some(s.clone());
                    user.display_name = Some(s);
                }
                NameField::Given => {
                    n.given_name = Some(s);
                    n.formatted = None;
                    user.display_name = None;
                }
                NameField::Family => {
                    n.family_name = Some(s);
                    n.formatted = None;
                    user.display_name = None;
                }
            }
        }
    }
    user.name = Some(n);
    Ok(())
}

fn set_emails(
    user: &mut ScimUser,
    action: Action,
    value: Option<&Value>,
) -> Result<(), ScimError> {
    match action {
        Action::Remove => {
            user.emails.clear();
            Ok(())
        }
        Action::Add | Action::Replace => {
            let v = value.ok_or_else(|| ScimError::invalid_value("emails requires a value"))?;
            let new: Vec<Email> = match v {
                Value::Array(_) => serde_json::from_value(v.clone())
                    .map_err(|e| ScimError::invalid_value(format!("invalid emails array: {e}")))?,
                Value::String(s) => vec![Email {
                    value: s.clone(),
                    primary: Some(true),
                    email_type: Some("work".into()),
                    display: None,
                }],
                Value::Object(_) => {
                    let one: Email = serde_json::from_value(v.clone())
                        .map_err(|e| ScimError::invalid_value(format!("invalid email object: {e}")))?;
                    vec![one]
                }
                _ => {
                    return Err(ScimError::invalid_value(
                        "emails must be an array, an object, or a string",
                    ));
                }
            };
            user.emails = new;
            Ok(())
        }
    }
}

fn require_string(value: Option<&Value>, attr: &str) -> Result<String, ScimError> {
    match value {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(other) => Err(ScimError::invalid_value(format!(
            "{attr} must be a string, got {other}"
        ))),
        None => Err(ScimError::invalid_value(format!(
            "{attr} requires a value"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scim::USER_SCHEMA_URN;
    use serde_json::json;
    use uuid::Uuid;

    fn sample_user() -> ScimUser {
        ScimUser {
            schemas: vec![USER_SCHEMA_URN.into()],
            id: Some(Uuid::nil()),
            external_id: Some("orig-ext".into()),
            user_name: "alice".into(),
            name: Some(Name {
                formatted: Some("Alice Example".into()),
                given_name: Some("Alice".into()),
                family_name: Some("Example".into()),
                ..Name::default()
            }),
            display_name: Some("Alice Example".into()),
            emails: vec![Email {
                value: "alice@example.com".into(),
                primary: Some(true),
                email_type: Some("work".into()),
                display: None,
            }],
            active: true,
            meta: None,
        }
    }

    fn patch_body(ops: Value) -> PatchOp {
        serde_json::from_value(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": ops,
        }))
        .unwrap()
    }

    fn ops(v: Value) -> Vec<PatchOperation> {
        serde_json::from_value(v).unwrap()
    }

    // --- validation ---

    #[test]
    fn patch_body_requires_schema() {
        let p: PatchOp = serde_json::from_value(json!({
            "Operations": [{"op":"replace","path":"active","value":false}]
        }))
        .unwrap();
        assert!(p.validate_schema().is_err());
    }

    #[test]
    fn patch_body_requires_operations() {
        let p = patch_body(json!([]));
        let err = p.validate_schema().unwrap_err();
        assert_eq!(err.scim_type, Some("invalidSyntax"));
    }

    #[test]
    fn patch_body_validates_when_schema_and_ops_present() {
        let p = patch_body(json!([{"op":"replace","path":"active","value":false}]));
        p.validate_schema().unwrap();
    }

    // --- path-based replace ---

    #[test]
    fn replace_active_flips_flag() {
        let mut u = sample_user();
        apply_all(
            &mut u,
            &ops(json!([{"op":"replace","path":"active","value":false}])),
        )
        .unwrap();
        assert!(!u.active);
    }

    #[test]
    fn replace_username_updates_value() {
        let mut u = sample_user();
        apply_all(
            &mut u,
            &ops(json!([{"op":"replace","path":"userName","value":"alice2"}])),
        )
        .unwrap();
        assert_eq!(u.user_name, "alice2");
    }

    #[test]
    fn replace_display_name() {
        let mut u = sample_user();
        apply_all(
            &mut u,
            &ops(json!([{"op":"replace","path":"displayName","value":"New Name"}])),
        )
        .unwrap();
        assert_eq!(u.display_name.as_deref(), Some("New Name"));
    }

    #[test]
    fn replace_external_id() {
        let mut u = sample_user();
        apply_all(
            &mut u,
            &ops(json!([{"op":"replace","path":"externalId","value":"new-ext"}])),
        )
        .unwrap();
        assert_eq!(u.external_id.as_deref(), Some("new-ext"));
    }

    #[test]
    fn remove_external_id_clears_it() {
        let mut u = sample_user();
        apply_all(
            &mut u,
            &ops(json!([{"op":"remove","path":"externalId"}])),
        )
        .unwrap();
        assert!(u.external_id.is_none());
    }

    #[test]
    fn remove_active_is_invalid_value() {
        let mut u = sample_user();
        let err = apply_all(
            &mut u,
            &ops(json!([{"op":"remove","path":"active"}])),
        )
        .unwrap_err();
        assert_eq!(err.scim_type, Some("invalidValue"));
    }

    #[test]
    fn remove_username_is_invalid_value() {
        let mut u = sample_user();
        let err = apply_all(
            &mut u,
            &ops(json!([{"op":"remove","path":"userName"}])),
        )
        .unwrap_err();
        assert_eq!(err.scim_type, Some("invalidValue"));
    }

    // --- name handling ---

    #[test]
    fn replace_name_object_replaces_wholesale() {
        let mut u = sample_user();
        apply_all(
            &mut u,
            &ops(json!([{
                "op":"replace","path":"name","value":{"formatted":"New Name"}
            }])),
        )
        .unwrap();
        assert_eq!(u.name.unwrap().formatted.as_deref(), Some("New Name"));
    }

    #[test]
    fn replace_name_given_preserves_family() {
        let mut u = sample_user();
        apply_all(
            &mut u,
            &ops(json!([{
                "op":"replace","path":"name.givenName","value":"Alicia"
            }])),
        )
        .unwrap();
        let n = u.name.unwrap();
        assert_eq!(n.given_name.as_deref(), Some("Alicia"));
        assert_eq!(n.family_name.as_deref(), Some("Example"));
    }

    #[test]
    fn replace_name_family_preserves_given() {
        let mut u = sample_user();
        apply_all(
            &mut u,
            &ops(json!([{
                "op":"replace","path":"name.familyName","value":"Other"
            }])),
        )
        .unwrap();
        let n = u.name.unwrap();
        assert_eq!(n.family_name.as_deref(), Some("Other"));
        assert_eq!(n.given_name.as_deref(), Some("Alice"));
    }

    // --- emails ---

    #[test]
    fn replace_emails_array() {
        let mut u = sample_user();
        apply_all(
            &mut u,
            &ops(json!([{
                "op":"replace","path":"emails","value":[
                    {"value":"new@x.co","primary":true}
                ]
            }])),
        )
        .unwrap();
        assert_eq!(u.emails.len(), 1);
        assert_eq!(u.emails[0].value, "new@x.co");
    }

    #[test]
    fn emails_bracketed_filter_routes_to_value() {
        let mut u = sample_user();
        apply_all(
            &mut u,
            &ops(json!([{
                "op":"replace","path":"emails[type eq \"work\"].value","value":"work@x.co"
            }])),
        )
        .unwrap();
        assert_eq!(u.emails[0].value, "work@x.co");
    }

    #[test]
    fn remove_emails_clears_array() {
        let mut u = sample_user();
        apply_all(
            &mut u,
            &ops(json!([{"op":"remove","path":"emails"}])),
        )
        .unwrap();
        assert!(u.emails.is_empty());
    }

    // --- empty-path ---

    #[test]
    fn empty_path_replace_with_object_value() {
        let mut u = sample_user();
        apply_all(
            &mut u,
            &ops(json!([{
                "op":"replace","value":{"active":false,"displayName":"New"}
            }])),
        )
        .unwrap();
        assert!(!u.active);
        assert_eq!(u.display_name.as_deref(), Some("New"));
    }

    #[test]
    fn empty_path_rejects_non_object_value() {
        let mut u = sample_user();
        let err = apply_all(
            &mut u,
            &ops(json!([{"op":"replace","value":"not an object"}])),
        )
        .unwrap_err();
        assert_eq!(err.scim_type, Some("invalidValue"));
    }

    // --- unsupported / errors ---

    #[test]
    fn unsupported_path_returns_invalid_path() {
        let mut u = sample_user();
        let err = apply_all(
            &mut u,
            &ops(json!([{"op":"replace","path":"phoneNumbers","value":"555"}])),
        )
        .unwrap_err();
        assert_eq!(err.scim_type, Some("invalidPath"));
    }

    #[test]
    fn groups_write_is_rejected() {
        let mut u = sample_user();
        let err = apply_all(
            &mut u,
            &ops(json!([{"op":"add","path":"groups","value":[{"value":"admin"}]}])),
        )
        .unwrap_err();
        assert_eq!(err.scim_type, Some("invalidPath"));
    }

    #[test]
    fn unknown_op_rejected() {
        let mut u = sample_user();
        let err = apply_all(
            &mut u,
            &ops(json!([{"op":"merge","path":"active","value":true}])),
        )
        .unwrap_err();
        assert_eq!(err.scim_type, Some("invalidSyntax"));
    }

    #[test]
    fn op_is_case_insensitive() {
        let mut u = sample_user();
        apply_all(
            &mut u,
            &ops(json!([
                {"op":"REPLACE","path":"active","value":false},
                {"op":"Add","path":"displayName","value":"Hi"}
            ])),
        )
        .unwrap();
        assert!(!u.active);
        assert_eq!(u.display_name.as_deref(), Some("Hi"));
    }

    #[test]
    fn paths_are_case_insensitive() {
        let mut u = sample_user();
        apply_all(
            &mut u,
            &ops(json!([{"op":"replace","path":"USERNAME","value":"bob"}])),
        )
        .unwrap();
        assert_eq!(u.user_name, "bob");
    }

    #[test]
    fn urn_prefixed_attribute_paths_work() {
        let mut u = sample_user();
        apply_all(
            &mut u,
            &ops(json!([{
                "op":"replace",
                "path":"urn:ietf:params:scim:schemas:core:2.0:User:userName",
                "value":"bob"
            }])),
        )
        .unwrap();
        assert_eq!(u.user_name, "bob");
    }

    #[test]
    fn active_accepts_string_value_for_azure_compat() {
        let mut u = sample_user();
        apply_all(
            &mut u,
            &ops(json!([{"op":"replace","path":"active","value":"False"}])),
        )
        .unwrap();
        assert!(!u.active);
    }

    #[test]
    fn active_rejects_non_bool_non_boolean_string() {
        let mut u = sample_user();
        let err = apply_all(
            &mut u,
            &ops(json!([{"op":"replace","path":"active","value":"yes"}])),
        )
        .unwrap_err();
        assert_eq!(err.scim_type, Some("invalidValue"));
    }

    #[test]
    fn multiple_operations_applied_in_order() {
        let mut u = sample_user();
        apply_all(
            &mut u,
            &ops(json!([
                {"op":"replace","path":"userName","value":"first"},
                {"op":"replace","path":"userName","value":"second"},
                {"op":"replace","path":"active","value":false}
            ])),
        )
        .unwrap();
        assert_eq!(u.user_name, "second");
        assert!(!u.active);
    }
}
