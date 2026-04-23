use rand::RngCore;
use rand::rngs::OsRng;
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::db::DbEntity;
use crate::errors::AppError;

/// The kind of application. `forward_auth` apps are reverse-proxy targets gated by Caddy's
/// `forward_auth` directive; `oidc` apps are OpenID Connect relying parties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AppType {
    ForwardAuth,
    Oidc,
}

impl AppType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AppType::ForwardAuth => "forward_auth",
            AppType::Oidc => "oidc",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "forward_auth" => Some(AppType::ForwardAuth),
            "oidc" => Some(AppType::Oidc),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct Application {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub app_type: AppType,
    pub host_pattern: Option<String>,
    pub path_prefix: Option<String>,
    pub required_roles: Vec<String>,
    pub enabled: bool,
    pub oidc_client_id: Option<String>,
    /// Redirect URIs permitted for the authorization endpoint. Empty for forward_auth apps.
    pub oidc_redirect_uris: Vec<String>,
    /// Redirect URIs permitted for the end_session endpoint.
    pub oidc_post_logout_redirect_uris: Vec<String>,
    /// True when the OIDC client has a shared secret; false means it is a public client
    /// authenticated only via PKCE.
    pub oidc_confidential: bool,
    pub created_at: i64,
    pub updated_at: i64,

    /// Secret hash never serialized to API clients.
    #[serde(skip)]
    oidc_client_secret_hash: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateApplicationInput {
    pub name: String,
    pub slug: String,
    /// Defaults to `forward_auth` when omitted, preserving existing API clients.
    #[serde(default)]
    pub app_type: Option<AppType>,
    pub host_pattern: Option<String>,
    pub path_prefix: Option<String>,
    pub required_roles: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub oidc_redirect_uris: Option<Vec<String>>,
    pub oidc_post_logout_redirect_uris: Option<Vec<String>>,
    /// If true (default for OIDC apps), a client secret is generated and returned once.
    /// If false, the app is a public client — PKCE-only, no secret.
    pub oidc_confidential: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateApplicationInput {
    pub name: Option<String>,
    pub host_pattern: Option<String>,
    pub path_prefix: Option<String>,
    pub required_roles: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub oidc_redirect_uris: Option<Vec<String>>,
    pub oidc_post_logout_redirect_uris: Option<Vec<String>>,
}

#[derive(Debug, sqlx::FromRow)]
struct ApplicationRow {
    id: Uuid,
    name: String,
    slug: String,
    host_pattern: Option<String>,
    path_prefix: Option<String>,
    required_roles: Option<String>,
    enabled: i64,
    created_at: i64,
    updated_at: i64,
    app_type: String,
    oidc_client_id: Option<String>,
    oidc_client_secret_hash: Option<String>,
    oidc_redirect_uris: Option<String>,
    oidc_post_logout_redirect_uris: Option<String>,
}

impl From<ApplicationRow> for Application {
    fn from(row: ApplicationRow) -> Self {
        let required_roles: Vec<String> = row
            .required_roles
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        let oidc_redirect_uris: Vec<String> = row
            .oidc_redirect_uris
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        let oidc_post_logout_redirect_uris: Vec<String> = row
            .oidc_post_logout_redirect_uris
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        let app_type = AppType::from_str(&row.app_type).unwrap_or(AppType::ForwardAuth);
        let oidc_confidential = row.oidc_client_secret_hash.is_some();

        Application {
            id: row.id,
            name: row.name,
            slug: row.slug,
            app_type,
            host_pattern: row.host_pattern,
            path_prefix: row.path_prefix,
            required_roles,
            enabled: row.enabled != 0,
            oidc_client_id: row.oidc_client_id,
            oidc_redirect_uris,
            oidc_post_logout_redirect_uris,
            oidc_confidential,
            created_at: row.created_at,
            updated_at: row.updated_at,
            oidc_client_secret_hash: row.oidc_client_secret_hash,
        }
    }
}

fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

/// SHA-256-then-hex a secret. Follows the same pattern as SCIM tokens: the OIDC client
/// secret is 32 bytes of `OsRng` entropy, so argon2 would add no defense-in-depth — it exists
/// to slow down dictionary attacks on human-chosen passwords.
pub fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a fresh OIDC client_id. 32 hex chars = 128 bits, enough to be globally unique.
pub fn generate_client_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Generate a fresh OIDC client_secret. 32 bytes = 256 bits of entropy, hex-encoded.
/// The returned tuple is `(plaintext, hash)` — hand the plaintext to the admin immediately
/// and only persist the hash.
pub fn generate_client_secret() -> (String, String) {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let plaintext = hex::encode(bytes);
    let hash = hash_secret(&plaintext);
    (plaintext, hash)
}

impl Application {
    /// Build a new forward-auth application in memory (not persisted).
    pub fn new(input: CreateApplicationInput) -> Self {
        let now = current_timestamp();
        Self {
            id: Uuid::now_v7(),
            name: input.name,
            slug: input.slug,
            app_type: input.app_type.unwrap_or(AppType::ForwardAuth),
            host_pattern: input.host_pattern,
            path_prefix: input.path_prefix,
            required_roles: input.required_roles.unwrap_or_default(),
            enabled: input.enabled.unwrap_or(true),
            oidc_client_id: None,
            oidc_redirect_uris: input.oidc_redirect_uris.unwrap_or_default(),
            oidc_post_logout_redirect_uris: input.oidc_post_logout_redirect_uris.unwrap_or_default(),
            oidc_confidential: false,
            created_at: now,
            updated_at: now,
            oidc_client_secret_hash: None,
        }
    }

    /// Build a new OIDC application in memory (not persisted). Always allocates a client_id.
    /// If `confidential` is true, also generates a secret and returns its plaintext; otherwise
    /// the app is a public client (PKCE-only) and the returned plaintext is `None`.
    pub fn new_oidc(mut input: CreateApplicationInput) -> (Self, Option<String>) {
        input.app_type = Some(AppType::Oidc);
        let confidential = input.oidc_confidential.unwrap_or(true);
        let mut app = Self::new(input);
        app.oidc_client_id = Some(generate_client_id());
        let plaintext = if confidential {
            let (plain, hash) = generate_client_secret();
            app.oidc_client_secret_hash = Some(hash);
            app.oidc_confidential = true;
            Some(plain)
        } else {
            app.oidc_confidential = false;
            None
        };
        (app, plaintext)
    }

    /// List all applications
    pub async fn list(conn: &mut SqliteConnection) -> Result<Vec<Application>, AppError> {
        let rows: Vec<ApplicationRow> = sqlx::query_as(
            r#"SELECT id, name, slug, host_pattern, path_prefix, required_roles, enabled,
                      created_at, updated_at, app_type, oidc_client_id, oidc_client_secret_hash,
                      oidc_redirect_uris, oidc_post_logout_redirect_uris
               FROM applications ORDER BY name"#
        )
        .fetch_all(conn)
        .await?;

        Ok(rows.into_iter().map(Application::from).collect())
    }

    /// List only enabled applications
    pub async fn list_enabled(conn: &mut SqliteConnection) -> Result<Vec<Application>, AppError> {
        let rows: Vec<ApplicationRow> = sqlx::query_as(
            r#"SELECT id, name, slug, host_pattern, path_prefix, required_roles, enabled,
                      created_at, updated_at, app_type, oidc_client_id, oidc_client_secret_hash,
                      oidc_redirect_uris, oidc_post_logout_redirect_uris
               FROM applications WHERE enabled = 1 ORDER BY name"#
        )
        .fetch_all(conn)
        .await?;

        Ok(rows.into_iter().map(Application::from).collect())
    }

    /// Get application by slug
    pub async fn get_by_slug(slug: &str, conn: &mut SqliteConnection) -> Result<Option<Application>, AppError> {
        let row: Option<ApplicationRow> = sqlx::query_as(
            r#"SELECT id, name, slug, host_pattern, path_prefix, required_roles, enabled,
                      created_at, updated_at, app_type, oidc_client_id, oidc_client_secret_hash,
                      oidc_redirect_uris, oidc_post_logout_redirect_uris
               FROM applications WHERE slug = ?"#
        )
        .bind(slug)
        .fetch_optional(conn)
        .await?;

        Ok(row.map(Application::from))
    }

    /// Get application by OIDC client_id. Only returns rows where `app_type = 'oidc'`.
    pub async fn get_by_oidc_client_id(
        client_id: &str,
        conn: &mut SqliteConnection,
    ) -> Result<Option<Application>, AppError> {
        let row: Option<ApplicationRow> = sqlx::query_as(
            r#"SELECT id, name, slug, host_pattern, path_prefix, required_roles, enabled,
                      created_at, updated_at, app_type, oidc_client_id, oidc_client_secret_hash,
                      oidc_redirect_uris, oidc_post_logout_redirect_uris
               FROM applications WHERE oidc_client_id = ? AND app_type = 'oidc'"#
        )
        .bind(client_id)
        .fetch_optional(conn)
        .await?;

        Ok(row.map(Application::from))
    }

    /// Find forward_auth application matching the given host and path. OIDC apps are skipped.
    pub async fn find_matching(
        host: &str,
        path: &str,
        conn: &mut SqliteConnection,
    ) -> Result<Option<Application>, AppError> {
        let apps = Application::list_enabled(conn).await?;

        for app in apps {
            if app.app_type == AppType::ForwardAuth && app.matches(host, path) {
                return Ok(Some(app));
            }
        }

        Ok(None)
    }

    /// Check if this application matches the given host and path
    pub fn matches(&self, host: &str, path: &str) -> bool {
        // Check host pattern
        if let Some(pattern) = &self.host_pattern {
            if pattern == host {
                // Exact match, check path
            } else if let Ok(re) = RegexBuilder::new(&format!("^(?:{pattern})$"))
                .size_limit(10_000)
                .build()
            {
                if !re.is_match(host) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Check path prefix
        if let Some(prefix) = &self.path_prefix {
            if !path.starts_with(prefix) {
                return false;
            }
        }

        true
    }

    /// Check if the given roles satisfy this application's requirements.
    /// `required_roles` may contain role IDs (UUIDs) or role names;
    /// `user_roles` contains role names from the access token.
    pub fn check_access(&self, user_roles: &[String]) -> bool {
        if self.required_roles.is_empty() {
            return true;
        }

        for required in &self.required_roles {
            if user_roles.contains(required) {
                return true;
            }
        }

        false
    }

    /// Like `check_access`, but resolves role IDs stored in `required_roles`
    /// to names via the database before comparing.
    pub async fn check_access_resolved(
        &self,
        user_roles: &[String],
        conn: &mut SqliteConnection,
    ) -> Result<bool, AppError> {
        if self.required_roles.is_empty() {
            return Ok(true);
        }

        let mut required_names = Vec::with_capacity(self.required_roles.len());
        for entry in &self.required_roles {
            if let Ok(id) = Uuid::parse_str(entry) {
                if let Some(role) = crate::role::Role::get(id, conn).await? {
                    required_names.push(role.name);
                }
            } else {
                required_names.push(entry.clone());
            }
        }

        for name in &required_names {
            if user_roles.contains(name) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Verify a presented OIDC client secret. Returns `false` when the client is public
    /// (no stored hash), when no secret was presented, or when the hashes don't match.
    pub fn verify_client_secret(&self, presented: &str) -> bool {
        let Some(hash) = &self.oidc_client_secret_hash else {
            return false;
        };
        hash_secret(presented) == *hash
    }

    /// Exact-match check against this app's registered redirect URIs.
    pub fn validate_redirect_uri(&self, uri: &str) -> bool {
        self.oidc_redirect_uris.iter().any(|u| u == uri)
    }

    /// Exact-match check against this app's registered post-logout redirect URIs.
    pub fn validate_post_logout_redirect_uri(&self, uri: &str) -> bool {
        self.oidc_post_logout_redirect_uris.iter().any(|u| u == uri)
    }

    /// Update the application. Updates to `app_type` are not supported — callers create a
    /// new application if they need to switch types.
    pub async fn update(
        &mut self,
        input: UpdateApplicationInput,
        conn: &mut SqliteConnection,
    ) -> Result<(), AppError> {
        if let Some(name) = input.name {
            self.name = name;
        }
        if let Some(host_pattern) = input.host_pattern {
            self.host_pattern = Some(host_pattern);
        }
        if let Some(path_prefix) = input.path_prefix {
            self.path_prefix = Some(path_prefix);
        }
        if let Some(required_roles) = input.required_roles {
            self.required_roles = required_roles;
        }
        if let Some(enabled) = input.enabled {
            self.enabled = enabled;
        }
        if let Some(uris) = input.oidc_redirect_uris {
            self.oidc_redirect_uris = uris;
        }
        if let Some(uris) = input.oidc_post_logout_redirect_uris {
            self.oidc_post_logout_redirect_uris = uris;
        }

        self.updated_at = current_timestamp();

        let roles_json = serde_json::to_string(&self.required_roles)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize roles: {e}")))?;
        let enabled_int: i64 = if self.enabled { 1 } else { 0 };
        let redirect_uris_json = serde_json::to_string(&self.oidc_redirect_uris)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize redirect URIs: {e}")))?;
        let post_logout_json = serde_json::to_string(&self.oidc_post_logout_redirect_uris)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize post-logout URIs: {e}")))?;

        sqlx::query!(
            r#"UPDATE applications SET name = ?, host_pattern = ?, path_prefix = ?,
                      required_roles = ?, enabled = ?, updated_at = ?,
                      oidc_redirect_uris = ?, oidc_post_logout_redirect_uris = ?
               WHERE id = ?"#,
            self.name,
            self.host_pattern,
            self.path_prefix,
            roles_json,
            enabled_int,
            self.updated_at,
            redirect_uris_json,
            post_logout_json,
            self.id
        )
        .execute(conn)
        .await?;

        Ok(())
    }

    /// Delete the application
    pub async fn delete(id: Uuid, conn: &mut SqliteConnection) -> Result<bool, AppError> {
        let result = sqlx::query!("DELETE FROM applications WHERE id = ?", id)
            .execute(conn)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Validate application input. Branches on `app_type`: forward_auth requires `host_pattern`,
    /// OIDC requires at least one redirect URI.
    pub fn validate_input(input: &CreateApplicationInput) -> Result<(), AppError> {
        let mut errors = Vec::new();

        if input.name.is_empty() || input.name.len() > 128 {
            errors.push("Application name must be between 1 and 128 characters".to_string());
        }

        if input.slug.is_empty() || input.slug.len() > 64 {
            errors.push("Slug must be between 1 and 64 characters".to_string());
        }

        if !input.slug.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            errors.push("Slug must contain only alphanumeric characters, hyphens, and underscores".to_string());
        }

        let app_type = input.app_type.unwrap_or(AppType::ForwardAuth);
        match app_type {
            AppType::ForwardAuth => {
                if input.host_pattern.as_deref().unwrap_or("").is_empty() {
                    errors.push("Forward-auth apps require a host pattern".to_string());
                }
                if let Some(pattern) = &input.host_pattern {
                    if !pattern.is_empty()
                        && RegexBuilder::new(&format!("^(?:{pattern})$"))
                            .size_limit(10_000)
                            .build()
                            .is_err()
                    {
                        errors.push("Invalid host pattern regex".to_string());
                    }
                }
            }
            AppType::Oidc => {
                let uris = input.oidc_redirect_uris.as_deref().unwrap_or(&[]);
                if uris.is_empty() {
                    errors.push("OIDC apps require at least one redirect URI".to_string());
                }
                for uri in uris {
                    if let Err(e) = validate_oidc_redirect_uri(uri) {
                        errors.push(e);
                    }
                }
                for uri in input.oidc_post_logout_redirect_uris.as_deref().unwrap_or(&[]) {
                    if let Err(e) = validate_oidc_redirect_uri(uri) {
                        errors.push(format!("post-logout: {e}"));
                    }
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(AppError::InputError(errors))
        }
    }
}

/// OIDC redirect URIs must be absolute, have no fragment, and use https:// (http:// is only
/// permitted for localhost loopbacks — see RFC 8252 §7.3).
fn validate_oidc_redirect_uri(uri: &str) -> Result<(), String> {
    let parsed = url::Url::parse(uri).map_err(|_| format!("redirect_uri is not a valid URL: {uri}"))?;
    if parsed.fragment().is_some() {
        return Err(format!("redirect_uri must not contain a fragment: {uri}"));
    }
    let host = parsed.host_str().unwrap_or("");
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            if host == "localhost" || host == "127.0.0.1" || host == "[::1]" {
                Ok(())
            } else {
                Err(format!("http:// redirect_uris are only allowed for localhost: {uri}"))
            }
        }
        // Native app custom schemes (e.g. `com.example.app:/cb`) are a valid OAuth pattern
        // (RFC 8252) — accept any scheme that isn't http/https as a custom scheme.
        other if !other.is_empty() => Ok(()),
        _ => Err(format!("redirect_uri has no scheme: {uri}")),
    }
}

impl DbEntity for Application {
    async fn save(&self, conn: &mut SqliteConnection) -> Result<(), AppError> {
        let roles_json = serde_json::to_string(&self.required_roles)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize roles: {e}")))?;
        let enabled_int: i64 = if self.enabled { 1 } else { 0 };
        let app_type_str = self.app_type.as_str();
        let redirect_uris_json = serde_json::to_string(&self.oidc_redirect_uris)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize redirect URIs: {e}")))?;
        let post_logout_json = serde_json::to_string(&self.oidc_post_logout_redirect_uris)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize post-logout URIs: {e}")))?;

        sqlx::query!(
            r#"INSERT INTO applications (id, name, slug, host_pattern, path_prefix, required_roles,
                                        enabled, created_at, updated_at, app_type,
                                        oidc_client_id, oidc_client_secret_hash,
                                        oidc_redirect_uris, oidc_post_logout_redirect_uris)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
            self.id,
            self.name,
            self.slug,
            self.host_pattern,
            self.path_prefix,
            roles_json,
            enabled_int,
            self.created_at,
            self.updated_at,
            app_type_str,
            self.oidc_client_id,
            self.oidc_client_secret_hash,
            redirect_uris_json,
            post_logout_json,
        )
        .execute(conn)
        .await?;

        Ok(())
    }

    async fn get(id: Uuid, conn: &mut SqliteConnection) -> Result<Option<Self>, AppError> {
        let row: Option<ApplicationRow> = sqlx::query_as(
            r#"SELECT id, name, slug, host_pattern, path_prefix, required_roles, enabled,
                      created_at, updated_at, app_type, oidc_client_id, oidc_client_secret_hash,
                      oidc_redirect_uris, oidc_post_logout_redirect_uris
               FROM applications WHERE id = ?"#
        )
        .bind(id)
        .fetch_optional(conn)
        .await?;

        Ok(row.map(Application::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fa_app() -> Application {
        Application {
            id: Uuid::now_v7(),
            name: "Test".to_string(),
            slug: "test".to_string(),
            app_type: AppType::ForwardAuth,
            host_pattern: Some("app.example.com".to_string()),
            path_prefix: None,
            required_roles: vec![],
            enabled: true,
            oidc_client_id: None,
            oidc_redirect_uris: vec![],
            oidc_post_logout_redirect_uris: vec![],
            oidc_confidential: false,
            created_at: 0,
            updated_at: 0,
            oidc_client_secret_hash: None,
        }
    }

    #[test]
    fn test_matches_exact_host() {
        let app = fa_app();
        assert!(app.matches("app.example.com", "/"));
        assert!(!app.matches("other.example.com", "/"));
    }

    #[test]
    fn test_matches_host_regex() {
        let mut app = fa_app();
        app.host_pattern = Some(r".*\.example\.com".to_string());
        assert!(app.matches("app.example.com", "/"));
        assert!(app.matches("other.example.com", "/"));
        assert!(!app.matches("example.org", "/"));
    }

    #[test]
    fn test_matches_path_prefix() {
        let mut app = fa_app();
        app.host_pattern = None;
        app.path_prefix = Some("/api/".to_string());
        assert!(app.matches("any.host", "/api/users"));
        assert!(app.matches("any.host", "/api/"));
        assert!(!app.matches("any.host", "/web/"));
    }

    #[test]
    fn test_check_access_no_roles_required() {
        let app = fa_app();
        assert!(app.check_access(&[]));
        assert!(app.check_access(&["user".to_string()]));
    }

    #[test]
    fn test_check_access_with_roles() {
        let mut app = fa_app();
        app.required_roles = vec!["admin".to_string(), "power_user".to_string()];
        assert!(!app.check_access(&[]));
        assert!(!app.check_access(&["user".to_string()]));
        assert!(app.check_access(&["admin".to_string()]));
        assert!(app.check_access(&["power_user".to_string()]));
        assert!(app.check_access(&["user".to_string(), "admin".to_string()]));
    }

    #[test]
    fn test_validate_input_valid_forward_auth() {
        let input = CreateApplicationInput {
            name: "My App".to_string(),
            slug: "my-app".to_string(),
            app_type: None,
            host_pattern: Some("app.example.com".to_string()),
            path_prefix: None,
            required_roles: Some(vec!["user".to_string()]),
            enabled: Some(true),
            oidc_redirect_uris: None,
            oidc_post_logout_redirect_uris: None,
            oidc_confidential: None,
        };
        assert!(Application::validate_input(&input).is_ok());
    }

    #[test]
    fn test_validate_input_forward_auth_requires_host() {
        let input = CreateApplicationInput {
            name: "My App".into(),
            slug: "my-app".into(),
            app_type: Some(AppType::ForwardAuth),
            host_pattern: None,
            path_prefix: None,
            required_roles: None,
            enabled: None,
            oidc_redirect_uris: None,
            oidc_post_logout_redirect_uris: None,
            oidc_confidential: None,
        };
        assert!(Application::validate_input(&input).is_err());
    }

    #[test]
    fn test_validate_input_invalid_slug() {
        let input = CreateApplicationInput {
            name: "My App".to_string(),
            slug: "my app".to_string(),
            app_type: None,
            host_pattern: Some("host".into()),
            path_prefix: None,
            required_roles: None,
            enabled: None,
            oidc_redirect_uris: None,
            oidc_post_logout_redirect_uris: None,
            oidc_confidential: None,
        };
        assert!(Application::validate_input(&input).is_err());
    }

    #[test]
    fn test_validate_input_invalid_regex() {
        let input = CreateApplicationInput {
            name: "My App".to_string(),
            slug: "my-app".to_string(),
            app_type: None,
            host_pattern: Some("[invalid".to_string()),
            path_prefix: None,
            required_roles: None,
            enabled: None,
            oidc_redirect_uris: None,
            oidc_post_logout_redirect_uris: None,
            oidc_confidential: None,
        };
        assert!(Application::validate_input(&input).is_err());
    }

    #[test]
    fn test_validate_input_oidc_requires_redirect_uri() {
        let input = CreateApplicationInput {
            name: "RP".into(),
            slug: "rp".into(),
            app_type: Some(AppType::Oidc),
            host_pattern: None,
            path_prefix: None,
            required_roles: None,
            enabled: None,
            oidc_redirect_uris: None,
            oidc_post_logout_redirect_uris: None,
            oidc_confidential: None,
        };
        assert!(Application::validate_input(&input).is_err());
    }

    #[test]
    fn test_validate_input_oidc_valid_https_redirect() {
        let input = CreateApplicationInput {
            name: "RP".into(),
            slug: "rp".into(),
            app_type: Some(AppType::Oidc),
            host_pattern: None,
            path_prefix: None,
            required_roles: None,
            enabled: None,
            oidc_redirect_uris: Some(vec!["https://app.example.com/cb".into()]),
            oidc_post_logout_redirect_uris: None,
            oidc_confidential: Some(true),
        };
        assert!(Application::validate_input(&input).is_ok());
    }

    #[test]
    fn test_validate_input_oidc_rejects_non_localhost_http() {
        let input = CreateApplicationInput {
            name: "RP".into(),
            slug: "rp".into(),
            app_type: Some(AppType::Oidc),
            host_pattern: None,
            path_prefix: None,
            required_roles: None,
            enabled: None,
            oidc_redirect_uris: Some(vec!["http://evil.example.com/cb".into()]),
            oidc_post_logout_redirect_uris: None,
            oidc_confidential: None,
        };
        assert!(Application::validate_input(&input).is_err());
    }

    #[test]
    fn test_validate_input_oidc_accepts_localhost_http() {
        let input = CreateApplicationInput {
            name: "RP".into(),
            slug: "rp".into(),
            app_type: Some(AppType::Oidc),
            host_pattern: None,
            path_prefix: None,
            required_roles: None,
            enabled: None,
            oidc_redirect_uris: Some(vec!["http://localhost:8080/cb".into()]),
            oidc_post_logout_redirect_uris: None,
            oidc_confidential: Some(false),
        };
        assert!(Application::validate_input(&input).is_ok());
    }

    #[test]
    fn test_validate_input_oidc_rejects_fragment() {
        let input = CreateApplicationInput {
            name: "RP".into(),
            slug: "rp".into(),
            app_type: Some(AppType::Oidc),
            host_pattern: None,
            path_prefix: None,
            required_roles: None,
            enabled: None,
            oidc_redirect_uris: Some(vec!["https://app.example.com/cb#frag".into()]),
            oidc_post_logout_redirect_uris: None,
            oidc_confidential: None,
        };
        assert!(Application::validate_input(&input).is_err());
    }

    #[test]
    fn test_redirect_uri_exact_match_is_case_sensitive_on_path() {
        let mut app = fa_app();
        app.app_type = AppType::Oidc;
        app.oidc_redirect_uris = vec!["https://app.example.com/Callback".into()];
        assert!(app.validate_redirect_uri("https://app.example.com/Callback"));
        assert!(!app.validate_redirect_uri("https://app.example.com/callback"));
    }

    #[test]
    fn test_post_logout_redirect_uri_match() {
        let mut app = fa_app();
        app.app_type = AppType::Oidc;
        app.oidc_post_logout_redirect_uris = vec!["https://app.example.com/out".into()];
        assert!(app.validate_post_logout_redirect_uri("https://app.example.com/out"));
        assert!(!app.validate_post_logout_redirect_uri("https://app.example.com/elsewhere"));
    }

    #[test]
    fn test_verify_client_secret_matches_plaintext() {
        let (plaintext, hash) = generate_client_secret();
        let mut app = fa_app();
        app.app_type = AppType::Oidc;
        app.oidc_client_secret_hash = Some(hash);
        assert!(app.verify_client_secret(&plaintext));
        assert!(!app.verify_client_secret("wrong"));
    }

    #[test]
    fn test_verify_client_secret_public_client_always_false() {
        let mut app = fa_app();
        app.app_type = AppType::Oidc;
        app.oidc_client_secret_hash = None;
        assert!(!app.verify_client_secret(""));
        assert!(!app.verify_client_secret("anything"));
    }

    #[test]
    fn test_new_oidc_app_generates_client_id_and_secret() {
        let input = CreateApplicationInput {
            name: "RP".into(),
            slug: "rp".into(),
            app_type: Some(AppType::Oidc),
            host_pattern: None,
            path_prefix: None,
            required_roles: None,
            enabled: None,
            oidc_redirect_uris: Some(vec!["https://app.example.com/cb".into()]),
            oidc_post_logout_redirect_uris: None,
            oidc_confidential: Some(true),
        };
        let (app, secret) = Application::new_oidc(input);
        assert_eq!(app.app_type, AppType::Oidc);
        assert!(app.oidc_client_id.is_some());
        assert!(app.oidc_confidential);
        assert!(secret.is_some());
        assert!(app.verify_client_secret(&secret.unwrap()));
    }

    #[test]
    fn test_new_oidc_public_client_has_no_secret() {
        let input = CreateApplicationInput {
            name: "SPA".into(),
            slug: "spa".into(),
            app_type: Some(AppType::Oidc),
            host_pattern: None,
            path_prefix: None,
            required_roles: None,
            enabled: None,
            oidc_redirect_uris: Some(vec!["https://spa.example.com/cb".into()]),
            oidc_post_logout_redirect_uris: None,
            oidc_confidential: Some(false),
        };
        let (app, secret) = Application::new_oidc(input);
        assert!(secret.is_none());
        assert!(!app.oidc_confidential);
        assert!(app.oidc_client_secret_hash.is_none());
    }

    #[test]
    fn test_generate_client_secret_is_unique() {
        let (a, _) = generate_client_secret();
        let (b, _) = generate_client_secret();
        assert_ne!(a, b);
    }

    #[test]
    fn test_hash_secret_deterministic() {
        assert_eq!(hash_secret("abc"), hash_secret("abc"));
        assert_ne!(hash_secret("abc"), hash_secret("abd"));
    }

    #[test]
    fn test_app_type_serde() {
        assert_eq!(serde_json::to_string(&AppType::ForwardAuth).unwrap(), "\"forward_auth\"");
        assert_eq!(serde_json::to_string(&AppType::Oidc).unwrap(), "\"oidc\"");
        let fa: AppType = serde_json::from_str("\"forward_auth\"").unwrap();
        assert_eq!(fa, AppType::ForwardAuth);
    }

    #[test]
    fn test_application_serialization_omits_secret_hash() {
        let mut app = fa_app();
        app.oidc_client_secret_hash = Some("should-not-leak".into());
        let json = serde_json::to_string(&app).unwrap();
        assert!(!json.contains("should-not-leak"));
        assert!(!json.contains("client_secret_hash"));
    }

    #[test]
    fn test_matches_host_and_path_combined() {
        let mut app = fa_app();
        app.path_prefix = Some("/api/".to_string());
        assert!(app.matches("app.example.com", "/api/users"));
        assert!(!app.matches("app.example.com", "/web/"));
        assert!(!app.matches("other.example.com", "/api/users"));
    }

    #[test]
    fn test_matches_no_patterns() {
        let mut app = fa_app();
        app.host_pattern = None;
        app.path_prefix = None;
        assert!(app.matches("any.host", "/any/path"));
    }
}
