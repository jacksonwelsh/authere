//! Per-target attribute renaming. Admins set a JSON map on their target like
//! `{"userName": "username", "displayName": "display_name"}` and we rewrite the top-level
//! keys of the SCIM body before dispatch.
//!
//! Intentionally narrow: only top-level keys are renamed, and collisions (both a `from` and
//! a matching target key already in the body) preserve the incoming value — we don't attempt
//! to merge. Anything more ambitious (nested paths, value transforms) waits for M4.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::errors::AppError;

/// Parse a stored `attribute_map` column into a rename table. `None` returns an empty map
/// (identity transform). An object of string→string is the only valid shape; anything else
/// is a validation error at the admin-input boundary, but to be robust we also reject it
/// here with a clear error.
pub fn parse_map(raw: Option<&str>) -> Result<BTreeMap<String, String>, AppError> {
    let Some(raw) = raw else {
        return Ok(BTreeMap::new());
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(BTreeMap::new());
    }
    let value: Value = serde_json::from_str(trimmed).map_err(|e| {
        AppError::InputError(vec![format!("attribute_map is not valid JSON: {e}")])
    })?;
    let obj = value.as_object().ok_or_else(|| {
        AppError::InputError(vec!["attribute_map must be a JSON object".into()])
    })?;
    let mut out = BTreeMap::new();
    for (k, v) in obj {
        let Some(v) = v.as_str() else {
            return Err(AppError::InputError(vec![format!(
                "attribute_map value for '{k}' must be a string"
            )]));
        };
        out.insert(k.clone(), v.to_string());
    }
    Ok(out)
}

/// Rewrite top-level JSON object keys per `map`. Non-object inputs pass through unchanged;
/// keys absent from `map` are kept; target keys already present in the input are preserved
/// (the rename is skipped for that pair to avoid silent overwrites).
pub fn rewrite_body(map: &BTreeMap<String, String>, body: Value) -> Value {
    if map.is_empty() {
        return body;
    }
    let Value::Object(obj) = body else {
        return body;
    };
    let mut out = serde_json::Map::with_capacity(obj.len());
    for (k, v) in obj {
        match map.get(&k) {
            Some(new_name) if !out.contains_key(new_name) => {
                out.insert(new_name.clone(), v);
            }
            _ => {
                out.insert(k, v);
            }
        }
    }
    Value::Object(out)
}

/// Apply the map embedded in `raw` to the body. Convenience over the two-step parse+rewrite
/// for callers that only need the rewritten body.
pub fn apply_map(raw: Option<&str>, body: Value) -> Value {
    match parse_map(raw) {
        Ok(m) => rewrite_body(&m, body),
        Err(_) => body, // best-effort: malformed map is ignored at dispatch time
    }
}

/// Validate a user-supplied map on the admin API boundary. Rejects non-object, non-string
/// values, empty keys, empty values. Intentionally strict — garbage-in silently-ignored
/// would be worse than a loud 400.
pub fn validate_map_input(raw: &str) -> Result<(), AppError> {
    let m = parse_map(Some(raw))?;
    for (k, v) in &m {
        if k.trim().is_empty() {
            return Err(AppError::InputError(vec![
                "attribute_map keys must be non-empty".into(),
            ]));
        }
        if v.trim().is_empty() {
            return Err(AppError::InputError(vec![format!(
                "attribute_map value for '{k}' must be non-empty"
            )]));
        }
    }
    Ok(())
}

/// Emit a canonical JSON serialization of the map — used when echoing the map back to
/// admins on GET /targets so keys come out in a stable order.
pub fn serialize_map(map: &BTreeMap<String, String>) -> String {
    json!(map).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_none_is_empty() {
        assert!(parse_map(None).unwrap().is_empty());
    }

    #[test]
    fn parse_empty_string_is_empty() {
        assert!(parse_map(Some("")).unwrap().is_empty());
        assert!(parse_map(Some("   ")).unwrap().is_empty());
    }

    #[test]
    fn parse_object_of_strings_works() {
        let m = parse_map(Some(r#"{"userName":"username","displayName":"dn"}"#)).unwrap();
        assert_eq!(m.get("userName").unwrap(), "username");
        assert_eq!(m.get("displayName").unwrap(), "dn");
    }

    #[test]
    fn parse_rejects_non_object() {
        assert!(parse_map(Some(r#"["a","b"]"#)).is_err());
        assert!(parse_map(Some("42")).is_err());
    }

    #[test]
    fn parse_rejects_non_string_values() {
        assert!(parse_map(Some(r#"{"k": 42}"#)).is_err());
        assert!(parse_map(Some(r#"{"k": ["a"]}"#)).is_err());
    }

    #[test]
    fn rewrite_empty_map_is_identity() {
        let body = json!({"userName":"alice"});
        let out = rewrite_body(&BTreeMap::new(), body.clone());
        assert_eq!(out, body);
    }

    #[test]
    fn rewrite_renames_top_level_keys() {
        let mut m = BTreeMap::new();
        m.insert("userName".into(), "username".into());
        let out = rewrite_body(&m, json!({"userName":"alice","active":true}));
        assert_eq!(out, json!({"username":"alice","active":true}));
    }

    #[test]
    fn rewrite_leaves_nested_objects_alone() {
        let mut m = BTreeMap::new();
        m.insert("name".into(), "full_name".into());
        // The nested `givenName` is inside `name`, which gets renamed to `full_name` —
        // but its children are untouched.
        let out = rewrite_body(
            &m,
            json!({"name": {"givenName": "Alice", "familyName": "X"}, "userName": "alice"}),
        );
        assert_eq!(
            out,
            json!({"full_name": {"givenName": "Alice", "familyName": "X"}, "userName": "alice"})
        );
    }

    #[test]
    fn rewrite_skips_collision_preserving_incoming_target_key() {
        // If the target key already exists in the body, the rename is a no-op for that pair.
        let mut m = BTreeMap::new();
        m.insert("userName".into(), "username".into());
        let out = rewrite_body(
            &m,
            json!({"userName":"alice","username":"preexisting"}),
        );
        // We keep `username:"preexisting"` and drop the rename silently. Admins who cared
        // about the collision would set up their body correctly; we refuse to clobber.
        assert_eq!(out["username"], "preexisting");
    }

    #[test]
    fn rewrite_non_object_passes_through() {
        let mut m = BTreeMap::new();
        m.insert("a".into(), "b".into());
        let out = rewrite_body(&m, json!([1, 2, 3]));
        assert_eq!(out, json!([1, 2, 3]));
        let out = rewrite_body(&m, Value::Null);
        assert_eq!(out, Value::Null);
    }

    #[test]
    fn apply_map_malformed_is_silent_passthrough() {
        // Dispatch time can't fail the job over a bad admin config — we log and continue.
        let body = json!({"userName":"alice"});
        let out = apply_map(Some("{not-json"), body.clone());
        assert_eq!(out, body);
    }

    #[test]
    fn validate_rejects_empty_keys_or_values() {
        assert!(validate_map_input(r#"{"": "x"}"#).is_err());
        assert!(validate_map_input(r#"{"x": ""}"#).is_err());
        assert!(validate_map_input(r#"{"x": "   "}"#).is_err());
    }

    #[test]
    fn validate_accepts_reasonable_map() {
        validate_map_input(r#"{"userName":"username"}"#).unwrap();
        validate_map_input(r#"{}"#).unwrap();
    }

    #[test]
    fn serialize_map_is_stable_order() {
        let mut m = BTreeMap::new();
        m.insert("userName".into(), "username".into());
        m.insert("displayName".into(), "dn".into());
        let s = serialize_map(&m);
        // BTreeMap gives us alphabetical order, which is stable.
        assert!(s.find("displayName").unwrap() < s.find("userName").unwrap());
    }
}
