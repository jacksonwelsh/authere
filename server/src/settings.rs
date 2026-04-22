use std::net::SocketAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;
use utoipa::ToSchema;

use crate::errors::AppError;

pub const KEY_OPEN_REGISTRATION: &str = "open_registration";
pub const KEY_LDAP_ENABLED: &str = "ldap_enabled";
pub const KEY_LDAP_BASE_DN: &str = "ldap_base_dn";
pub const KEY_LDAP_BIND_ADDRESS: &str = "ldap_bind_address";
pub const KEY_LDAP_SERVICE_PASSWORD_HASH: &str = "ldap_service_password_hash";
pub const KEY_LDAP_PASSWORD_MODE: &str = "ldap_password_mode";

pub const DEFAULT_LDAP_BASE_DN: &str = "dc=authere,dc=local";
pub const DEFAULT_LDAP_BIND_ADDRESS: &str = "0.0.0.0:3389";

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LdapPasswordMode {
    /// Default. Users without TOTP may use their primary password or an app password;
    /// users with TOTP must use an app password.
    PrimaryAndApp,
    /// App password only, for everyone. Primary password is never accepted on LDAP.
    AppOnly,
    /// Primary password only. App passwords are disabled. Users with TOTP cannot bind.
    PrimaryOnly,
}

impl LdapPasswordMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            LdapPasswordMode::PrimaryAndApp => "primary_and_app",
            LdapPasswordMode::AppOnly => "app_only",
            LdapPasswordMode::PrimaryOnly => "primary_only",
        }
    }

    pub fn app_passwords_enabled(&self) -> bool {
        !matches!(self, LdapPasswordMode::PrimaryOnly)
    }
}

impl FromStr for LdapPasswordMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "primary_and_app" => Ok(LdapPasswordMode::PrimaryAndApp),
            "app_only" => Ok(LdapPasswordMode::AppOnly),
            "primary_only" => Ok(LdapPasswordMode::PrimaryOnly),
            other => Err(format!("Unknown LDAP password mode: {other}")),
        }
    }
}

impl Default for LdapPasswordMode {
    fn default() -> Self {
        LdapPasswordMode::PrimaryAndApp
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LdapSettings {
    pub enabled: bool,
    pub base_dn: String,
    pub bind_address: String,
    pub service_account_dn: String,
    pub service_password_set: bool,
    pub password_mode: LdapPasswordMode,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct LdapSettingsInput {
    pub enabled: Option<bool>,
    pub base_dn: Option<String>,
    pub bind_address: Option<String>,
    pub password_mode: Option<LdapPasswordMode>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SettingsResponse {
    pub open_registration: bool,
    pub ldap: LdapSettings,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSettingsInput {
    pub open_registration: Option<bool>,
    pub ldap: Option<LdapSettingsInput>,
}

/// Internal view of LDAP configuration, used by the LDAP listener.
#[derive(Debug, Clone)]
pub struct LdapConfig {
    pub enabled: bool,
    pub base_dn: String,
    pub bind_address: SocketAddr,
    pub service_password_hash: Option<String>,
    pub password_mode: LdapPasswordMode,
}

impl LdapConfig {
    pub fn service_account_dn(&self) -> String {
        format!("cn=service,{}", self.base_dn)
    }

    pub fn people_base_dn(&self) -> String {
        format!("ou=people,{}", self.base_dn)
    }

    pub fn groups_base_dn(&self) -> String {
        format!("ou=groups,{}", self.base_dn)
    }
}

pub async fn get_setting(key: &str, conn: &mut SqliteConnection) -> Result<Option<String>, AppError> {
    let row = sqlx::query!("SELECT value FROM settings WHERE key = ?", key)
        .fetch_optional(conn)
        .await?;
    Ok(row.map(|r| r.value))
}

pub async fn set_setting(key: &str, value: &str, conn: &mut SqliteConnection) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
        key,
        value
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn open_registration_enabled(conn: &mut SqliteConnection) -> Result<bool, AppError> {
    let value = get_setting(KEY_OPEN_REGISTRATION, conn).await?;
    Ok(value.as_deref() == Some("true"))
}

/// Load the typed LDAP config from the settings KV store. Missing/blank values fall back to
/// sensible defaults so the server can always render *something* to the admin.
pub async fn load_ldap_config(conn: &mut SqliteConnection) -> Result<LdapConfig, AppError> {
    let enabled = get_setting(KEY_LDAP_ENABLED, conn).await?.as_deref() == Some("true");
    let base_dn = get_setting(KEY_LDAP_BASE_DN, conn)
        .await?
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_LDAP_BASE_DN.to_string());
    let bind_address_str = get_setting(KEY_LDAP_BIND_ADDRESS, conn)
        .await?
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_LDAP_BIND_ADDRESS.to_string());
    let bind_address = bind_address_str
        .parse::<SocketAddr>()
        .map_err(|e| AppError::InternalError(format!("invalid ldap_bind_address: {e}")))?;

    let service_password_hash = get_setting(KEY_LDAP_SERVICE_PASSWORD_HASH, conn)
        .await?
        .filter(|s| !s.is_empty());

    let password_mode = get_setting(KEY_LDAP_PASSWORD_MODE, conn)
        .await?
        .and_then(|s| LdapPasswordMode::from_str(&s).ok())
        .unwrap_or_default();

    Ok(LdapConfig {
        enabled,
        base_dn,
        bind_address,
        service_password_hash,
        password_mode,
    })
}

pub fn to_ldap_settings(cfg: &LdapConfig) -> LdapSettings {
    LdapSettings {
        enabled: cfg.enabled,
        base_dn: cfg.base_dn.clone(),
        bind_address: cfg.bind_address.to_string(),
        service_account_dn: cfg.service_account_dn(),
        service_password_set: cfg.service_password_hash.is_some(),
        password_mode: cfg.password_mode,
    }
}

/// Validate a Base DN as a non-empty string matching a loose LDAP DN shape. We rely on
/// ldap3_proto's filter parser elsewhere; the check here just rejects obvious garbage before
/// it gets persisted.
pub fn validate_base_dn(dn: &str) -> Result<(), String> {
    let trimmed = dn.trim();
    if trimmed.is_empty() {
        return Err("Base DN cannot be empty".to_string());
    }
    if trimmed.len() > 512 {
        return Err("Base DN is too long".to_string());
    }
    for rdn in trimmed.split(',') {
        let rdn = rdn.trim();
        if rdn.is_empty() {
            return Err("Base DN contains an empty component".to_string());
        }
        let (attr, value) = rdn.split_once('=').ok_or_else(|| {
            format!("Base DN component '{rdn}' is missing an '=' separator")
        })?;
        if attr.trim().is_empty() || value.trim().is_empty() {
            return Err(format!("Base DN component '{rdn}' has an empty attribute or value"));
        }
    }
    Ok(())
}

pub fn validate_bind_address(addr: &str) -> Result<SocketAddr, String> {
    addr.parse::<SocketAddr>()
        .map_err(|e| format!("Invalid bind address '{addr}': {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_mode_parses_known_values() {
        assert_eq!(
            LdapPasswordMode::from_str("primary_and_app").unwrap(),
            LdapPasswordMode::PrimaryAndApp
        );
        assert_eq!(
            LdapPasswordMode::from_str("app_only").unwrap(),
            LdapPasswordMode::AppOnly
        );
        assert_eq!(
            LdapPasswordMode::from_str("primary_only").unwrap(),
            LdapPasswordMode::PrimaryOnly
        );
    }

    #[test]
    fn password_mode_rejects_unknown_values() {
        assert!(LdapPasswordMode::from_str("whatever").is_err());
        assert!(LdapPasswordMode::from_str("").is_err());
    }

    #[test]
    fn password_mode_round_trip_via_as_str() {
        for mode in [
            LdapPasswordMode::PrimaryAndApp,
            LdapPasswordMode::AppOnly,
            LdapPasswordMode::PrimaryOnly,
        ] {
            assert_eq!(LdapPasswordMode::from_str(mode.as_str()).unwrap(), mode);
        }
    }

    #[test]
    fn app_passwords_enabled_matches_mode() {
        assert!(LdapPasswordMode::PrimaryAndApp.app_passwords_enabled());
        assert!(LdapPasswordMode::AppOnly.app_passwords_enabled());
        assert!(!LdapPasswordMode::PrimaryOnly.app_passwords_enabled());
    }

    #[test]
    fn password_mode_default_is_primary_and_app() {
        assert_eq!(LdapPasswordMode::default(), LdapPasswordMode::PrimaryAndApp);
    }

    #[test]
    fn ldap_config_derives_account_and_base_dns() {
        let cfg = LdapConfig {
            enabled: true,
            base_dn: "dc=example,dc=com".to_string(),
            bind_address: "0.0.0.0:3389".parse().unwrap(),
            service_password_hash: None,
            password_mode: LdapPasswordMode::PrimaryAndApp,
        };
        assert_eq!(cfg.service_account_dn(), "cn=service,dc=example,dc=com");
        assert_eq!(cfg.people_base_dn(), "ou=people,dc=example,dc=com");
        assert_eq!(cfg.groups_base_dn(), "ou=groups,dc=example,dc=com");
    }

    #[test]
    fn to_ldap_settings_exposes_password_set_without_hash() {
        let cfg = LdapConfig {
            enabled: true,
            base_dn: DEFAULT_LDAP_BASE_DN.to_string(),
            bind_address: DEFAULT_LDAP_BIND_ADDRESS.parse().unwrap(),
            service_password_hash: Some("$argon2id$v=19$...".to_string()),
            password_mode: LdapPasswordMode::AppOnly,
        };
        let s = to_ldap_settings(&cfg);
        assert!(s.enabled);
        assert_eq!(s.base_dn, DEFAULT_LDAP_BASE_DN);
        assert_eq!(s.bind_address, "0.0.0.0:3389");
        assert_eq!(s.service_account_dn, format!("cn=service,{DEFAULT_LDAP_BASE_DN}"));
        assert!(s.service_password_set);
        assert_eq!(s.password_mode, LdapPasswordMode::AppOnly);
    }

    #[test]
    fn service_password_set_is_false_when_hash_missing() {
        let cfg = LdapConfig {
            enabled: false,
            base_dn: DEFAULT_LDAP_BASE_DN.to_string(),
            bind_address: DEFAULT_LDAP_BIND_ADDRESS.parse().unwrap(),
            service_password_hash: None,
            password_mode: LdapPasswordMode::default(),
        };
        let s = to_ldap_settings(&cfg);
        assert!(!s.service_password_set);
    }

    #[test]
    fn validate_base_dn_accepts_valid_dns() {
        validate_base_dn("dc=authere,dc=local").unwrap();
        validate_base_dn("dc=example,dc=com").unwrap();
        validate_base_dn("o=Example Corp,dc=example,dc=com").unwrap();
    }

    #[test]
    fn validate_base_dn_rejects_invalid_shapes() {
        assert!(validate_base_dn("").is_err());
        assert!(validate_base_dn("   ").is_err());
        assert!(validate_base_dn("nocomponent").is_err());
        assert!(validate_base_dn("=noattr").is_err());
        assert!(validate_base_dn("attr=").is_err());
        assert!(validate_base_dn("dc=a,,dc=b").is_err());
    }

    #[test]
    fn validate_bind_address_accepts_ipv4_and_ipv6() {
        validate_bind_address("0.0.0.0:3389").unwrap();
        validate_bind_address("127.0.0.1:389").unwrap();
        validate_bind_address("[::1]:389").unwrap();
    }

    #[test]
    fn validate_bind_address_rejects_garbage() {
        assert!(validate_bind_address("").is_err());
        assert!(validate_bind_address("example.com:389").is_err());
        assert!(validate_bind_address("0.0.0.0").is_err());
    }
}
