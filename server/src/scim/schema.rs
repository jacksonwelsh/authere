//! SCIM 2.0 wire types (RFC 7643 §4) and serde helpers.
//!
//! Only the core User schema is modeled. We do not implement `/Groups` (see plan). The shape
//! here matches exactly what Okta, Azure AD, and OneLogin send/expect; when that diverges from
//! the RFC we side with the IdPs (they're the consumers in practice) and document the
//! divergence inline.
//!
//! Authere stores a single `users.name` string, so the SCIM `name` complex attribute round-trips
//! through `formatted` by default. When a client sends only `givenName`/`familyName`, we
//! concatenate; when reading, we populate `formatted` only. This is lossy on PATCH of
//! `name.givenName` etc. — documented on [`ScimUser::from_authere_user`].

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::scim::{LIST_RESPONSE_URN, SCIM_CONTENT_TYPE, USER_SCHEMA_URN};
use crate::user::User;

/// SCIM `meta` complex attribute (§3.1). We emit weak ETags (`W/"…"`) using `updated_at` as
/// the version source so no extra column is needed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Meta {
    #[serde(rename = "resourceType")]
    pub resource_type: String,
    pub created: String,
    #[serde(rename = "lastModified")]
    pub last_modified: String,
    pub location: String,
    pub version: String,
}

/// SCIM `User.name` (§4.1.1). We only populate `formatted` on the way out; on the way in we
/// accept any subset and derive a single display name.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Name {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honorific_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honorific_suffix: Option<String>,
}

impl Name {
    /// Produce a single display name from whichever name subfields the client supplied,
    /// preferring `formatted` and falling back to `given + family`. Returns `None` only when
    /// the whole `Name` is empty (caller should also check `displayName` before giving up).
    pub fn resolve(&self) -> Option<String> {
        if let Some(ref f) = self.formatted {
            let t = f.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
        match (&self.given_name, &self.family_name) {
            (Some(g), Some(f)) => Some(format!("{} {}", g.trim(), f.trim()).trim().to_string()),
            (Some(g), None) => Some(g.trim().to_string()),
            (None, Some(f)) => Some(f.trim().to_string()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Email {
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub email_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// SCIM User resource (`urn:ietf:params:scim:schemas:core:2.0:User`).
///
/// We only model the subset Authere actually round-trips. Unmodeled attributes (e.g. `phoneNumbers`,
/// `addresses`, enterprise extensions) are explicitly dropped on read and rejected on write with
/// `invalidPath` — keeping the model narrow means the filter/patch surfaces stay small.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    pub schemas: Vec<String>,
    /// Server-assigned. Absent on POST bodies from the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub user_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<Name>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<Email>,
    #[serde(default = "default_active")]
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,
}

fn default_active() -> bool {
    true
}

/// Listing response envelope (RFC 7644 §3.4.2).
#[derive(Debug, Clone, Serialize)]
pub struct ListResponse<T: Serialize> {
    pub schemas: [&'static str; 1],
    #[serde(rename = "totalResults")]
    pub total_results: usize,
    #[serde(rename = "startIndex")]
    pub start_index: usize,
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: usize,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

impl<T: Serialize> ListResponse<T> {
    pub fn new(resources: Vec<T>, total_results: usize, start_index: usize) -> Self {
        let items_per_page = resources.len();
        Self {
            schemas: [LIST_RESPONSE_URN],
            total_results,
            start_index,
            items_per_page,
            resources,
        }
    }
}

/// Response wrapper that sets `Content-Type: application/scim+json`. Azure AD rejects
/// `application/json`; all SCIM responses must go through this type.
pub struct ScimJson<T: Serialize> {
    pub status: StatusCode,
    pub body: T,
    pub headers: Vec<(header::HeaderName, HeaderValue)>,
}

impl<T: Serialize> ScimJson<T> {
    pub fn new(body: T) -> Self {
        Self {
            status: StatusCode::OK,
            body,
            headers: Vec::new(),
        }
    }

    pub fn status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    pub fn header(mut self, name: header::HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }
}

impl<T: Serialize> IntoResponse for ScimJson<T> {
    fn into_response(self) -> Response {
        let bytes = match serde_json::to_vec(&self.body) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "failed to serialize SCIM response body");
                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(header::CONTENT_TYPE, SCIM_CONTENT_TYPE)
                    .body(axum::body::Body::from(r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"500","detail":"serialization failed"}"#))
                    .expect("fallback response");
            }
        };
        let mut builder = Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, SCIM_CONTENT_TYPE);
        for (n, v) in self.headers {
            builder = builder.header(n, v);
        }
        builder
            .body(axum::body::Body::from(bytes))
            .expect("building SCIM response should not fail")
    }
}

/// RFC3339 / ISO-8601 UTC formatter for unix epoch seconds. Uses the civil-date algorithm from
/// Howard Hinnant's "Date Algorithms" paper (public domain) so we don't pull in chrono/time.
/// Handles negative inputs by clamping to epoch (SCIM doesn't care about pre-1970 timestamps).
pub fn format_timestamp(epoch: i64) -> String {
    let seconds_per_day: i64 = 86_400;
    let epoch = epoch.max(0);
    let days = epoch / seconds_per_day;
    let secs_of_day = epoch % seconds_per_day;
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    // https://howardhinnant.github.io/date_algorithms.html#civil_from_days
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

pub fn make_meta(user: &User, origin: &str) -> Meta {
    Meta {
        resource_type: "User".to_string(),
        created: format_timestamp(user.created_at),
        last_modified: format_timestamp(user.updated_at),
        location: format!("{}/scim/v2/Users/{}", origin.trim_end_matches('/'), user.id),
        version: weak_etag(user.updated_at),
    }
}

pub fn weak_etag(updated_at: i64) -> String {
    format!("W/\"{}\"", updated_at)
}

impl ScimUser {
    /// Build a wire-ready `ScimUser` from the internal [`User`]. `origin` is the scheme+host
    /// prefix used to construct `meta.location` (e.g. `"https://auth.example.com"`).
    pub fn from_user(user: &User, origin: &str) -> Self {
        let emails = match &user.email {
            Some(addr) => vec![Email {
                value: addr.clone(),
                primary: Some(true),
                email_type: Some("work".into()),
                display: None,
            }],
            None => Vec::new(),
        };
        let name = Some(Name {
            formatted: Some(user.name.clone()),
            ..Name::default()
        });
        ScimUser {
            schemas: vec![USER_SCHEMA_URN.to_string()],
            id: Some(user.id),
            external_id: user.external_id.clone(),
            user_name: user.username.clone(),
            name,
            display_name: Some(user.name.clone()),
            emails,
            active: user.active,
            meta: Some(make_meta(user, origin)),
        }
    }

    /// Resolve a single display name for persistence, checking `name.formatted`, then
    /// `displayName`, then `givenName + familyName`. Returns `None` if nothing usable.
    pub fn resolve_display_name(&self) -> Option<String> {
        if let Some(ref n) = self.name
            && let Some(s) = n.resolve()
        {
            return Some(s);
        }
        self.display_name.as_ref().and_then(|d| {
            let t = d.trim();
            if t.is_empty() { None } else { Some(t.to_string()) }
        })
    }

    /// Pull the single email we store out of the emails array, preferring the one marked
    /// `primary: true` and falling back to the first entry. Returns `None` on empty array.
    pub fn resolve_email(&self) -> Option<String> {
        if self.emails.is_empty() {
            return None;
        }
        self.emails
            .iter()
            .find(|e| e.primary.unwrap_or(false))
            .or_else(|| self.emails.first())
            .map(|e| e.value.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
    fn from_user_populates_all_emitted_fields() {
        let u = sample_user();
        let s = ScimUser::from_user(&u, "https://auth.example.com");

        assert_eq!(s.schemas, vec![USER_SCHEMA_URN.to_string()]);
        assert_eq!(s.id, Some(u.id));
        assert_eq!(s.external_id.as_deref(), Some("okta-42"));
        assert_eq!(s.user_name, "alice");
        assert_eq!(s.display_name.as_deref(), Some("Alice Example"));
        assert_eq!(s.emails.len(), 1);
        assert_eq!(s.emails[0].value, "alice@example.com");
        assert_eq!(s.emails[0].primary, Some(true));
        assert!(s.active);
        let meta = s.meta.unwrap();
        assert_eq!(meta.resource_type, "User");
        assert_eq!(meta.location, "https://auth.example.com/scim/v2/Users/00000000-0000-0000-0000-000000000000");
        assert_eq!(meta.version, "W/\"1700000500\"");
        assert!(meta.created.starts_with("2023"));
        assert!(meta.last_modified.starts_with("2023"));
    }

    #[test]
    fn from_user_trims_trailing_slash_on_origin() {
        let u = sample_user();
        let s = ScimUser::from_user(&u, "https://auth.example.com/");
        let meta = s.meta.unwrap();
        assert_eq!(
            meta.location,
            "https://auth.example.com/scim/v2/Users/00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn from_user_emits_empty_emails_when_missing() {
        let mut u = sample_user();
        u.email = None;
        let s = ScimUser::from_user(&u, "https://auth.example.com");
        assert!(s.emails.is_empty());
    }

    #[test]
    fn name_resolve_prefers_formatted() {
        let n = Name {
            formatted: Some("  Alice Example  ".into()),
            given_name: Some("Alice".into()),
            family_name: Some("Other".into()),
            ..Name::default()
        };
        assert_eq!(n.resolve().as_deref(), Some("Alice Example"));
    }

    #[test]
    fn name_resolve_falls_back_to_given_family() {
        let n = Name {
            given_name: Some("Alice".into()),
            family_name: Some("Example".into()),
            ..Name::default()
        };
        assert_eq!(n.resolve().as_deref(), Some("Alice Example"));
    }

    #[test]
    fn name_resolve_just_given() {
        let n = Name {
            given_name: Some("Alice".into()),
            ..Name::default()
        };
        assert_eq!(n.resolve().as_deref(), Some("Alice"));
    }

    #[test]
    fn name_resolve_empty_returns_none() {
        assert!(Name::default().resolve().is_none());
    }

    #[test]
    fn name_resolve_blank_formatted_falls_through() {
        let n = Name {
            formatted: Some("   ".into()),
            given_name: Some("Alice".into()),
            ..Name::default()
        };
        assert_eq!(n.resolve().as_deref(), Some("Alice"));
    }

    #[test]
    fn resolve_display_name_prefers_name_then_display_name() {
        let u = ScimUser {
            schemas: vec![USER_SCHEMA_URN.into()],
            id: None,
            external_id: None,
            user_name: "a".into(),
            name: Some(Name { formatted: Some("From name".into()), ..Name::default() }),
            display_name: Some("From displayName".into()),
            emails: vec![],
            active: true,
            meta: None,
        };
        assert_eq!(u.resolve_display_name().as_deref(), Some("From name"));

        let u_no_name = ScimUser { name: None, ..u };
        assert_eq!(u_no_name.resolve_display_name().as_deref(), Some("From displayName"));
    }

    #[test]
    fn resolve_display_name_empty_returns_none() {
        let u = ScimUser {
            schemas: vec![USER_SCHEMA_URN.into()],
            id: None,
            external_id: None,
            user_name: "a".into(),
            name: None,
            display_name: Some("   ".into()),
            emails: vec![],
            active: true,
            meta: None,
        };
        assert!(u.resolve_display_name().is_none());
    }

    #[test]
    fn resolve_email_prefers_primary() {
        let u = ScimUser {
            schemas: vec![USER_SCHEMA_URN.into()],
            id: None,
            external_id: None,
            user_name: "a".into(),
            name: None,
            display_name: None,
            emails: vec![
                Email { value: "first@x.co".into(), primary: Some(false), email_type: None, display: None },
                Email { value: "primary@x.co".into(), primary: Some(true), email_type: None, display: None },
            ],
            active: true,
            meta: None,
        };
        assert_eq!(u.resolve_email().as_deref(), Some("primary@x.co"));
    }

    #[test]
    fn resolve_email_falls_back_to_first() {
        let u = ScimUser {
            schemas: vec![USER_SCHEMA_URN.into()],
            id: None,
            external_id: None,
            user_name: "a".into(),
            name: None,
            display_name: None,
            emails: vec![
                Email { value: "only@x.co".into(), primary: None, email_type: None, display: None },
            ],
            active: true,
            meta: None,
        };
        assert_eq!(u.resolve_email().as_deref(), Some("only@x.co"));
    }

    #[test]
    fn scim_user_deserializes_minimal_post() {
        // What Okta sends on a minimal create
        let body = json!({
            "schemas": [USER_SCHEMA_URN],
            "userName": "alice",
            "name": { "givenName": "Alice", "familyName": "Example" },
            "emails": [{ "value": "alice@example.com", "primary": true }],
            "active": true
        });
        let u: ScimUser = serde_json::from_value(body).unwrap();
        assert_eq!(u.user_name, "alice");
        assert_eq!(u.resolve_display_name().as_deref(), Some("Alice Example"));
        assert_eq!(u.resolve_email().as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn scim_user_defaults_active_true() {
        let body = json!({
            "schemas": [USER_SCHEMA_URN],
            "userName": "alice"
        });
        let u: ScimUser = serde_json::from_value(body).unwrap();
        assert!(u.active, "missing `active` must default to true");
    }

    #[test]
    fn weak_etag_format() {
        assert_eq!(weak_etag(1700000000), "W/\"1700000000\"");
    }

    #[test]
    fn format_timestamp_handles_zero() {
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_timestamp_known_point() {
        // 2023-11-14T22:13:20Z per `date -u -r 1700000000`
        assert_eq!(format_timestamp(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn format_timestamp_leap_year_boundary() {
        // 2024-02-29T00:00:00Z = 1709164800
        assert_eq!(format_timestamp(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn format_timestamp_clamps_negative() {
        assert_eq!(format_timestamp(-100), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn list_response_sets_items_per_page_from_vec_len() {
        let lr = ListResponse::new(vec![1u8, 2, 3], 17, 1);
        assert_eq!(lr.items_per_page, 3);
        assert_eq!(lr.total_results, 17);
        assert_eq!(lr.start_index, 1);
    }
}
