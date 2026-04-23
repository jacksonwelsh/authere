//! `provisioning_targets` access + AES-GCM token encryption.
//!
//! Auth tokens for downstream targets are secrets; we encrypt them at rest with AES-256-GCM
//! under a master key sourced from the `AUTHERE_PROVISIONING_KEY` env var (hex-encoded
//! 32 bytes). If the env var is missing or malformed the server refuses to load the key —
//! targets simply cannot be created or decrypted without it.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;
use uuid::Uuid;

use crate::errors::AppError;

pub const KIND_GENERIC_SCIM: &str = "generic_scim";
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

/// Minimum acceptable shape for a downstream target. The DB row is mapped onto this type by
/// the query helpers below.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningTarget {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub base_url: String,
    #[serde(skip_serializing)]
    pub auth_token_ciphertext: Vec<u8>,
    #[serde(skip_serializing)]
    pub auth_token_nonce: Vec<u8>,
    pub enabled: bool,
    pub created_at: i64,
    pub created_by: Option<Uuid>,
    pub updated_at: i64,
    /// Epoch seconds when the first-time backfill (enumerate all active users → enqueue
    /// create jobs) completed. NULL means backfill hasn't run yet — the admin API triggers
    /// it on first enable.
    pub backfill_done_at: Option<i64>,
    /// Optional JSON object of `{"from": "to"}` strings. When present, the worker rewrites
    /// top-level SCIM body keys per this map before dispatch. `None` = identity.
    pub attribute_map: Option<String>,
    /// Optional webhook. When a job for this target transitions to `dead`, the worker
    /// POSTs a small JSON envelope here. Best-effort; webhook failures don't reopen the job.
    pub dead_letter_webhook_url: Option<String>,
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

/// Parse a hex-encoded key. Pure — safe to unit test without touching env vars.
pub fn parse_master_key(hex_key: &str) -> Result<[u8; KEY_LEN], AppError> {
    let bytes = hex::decode(hex_key.trim())
        .map_err(|e| AppError::InternalError(format!("AUTHERE_PROVISIONING_KEY not hex: {e}")))?;
    if bytes.len() != KEY_LEN {
        return Err(AppError::InternalError(format!(
            "AUTHERE_PROVISIONING_KEY must be {} bytes hex-encoded, got {}",
            KEY_LEN,
            bytes.len()
        )));
    }
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Read a hex-encoded master key from a file on disk. Fails if the file isn't readable or
/// if (on Unix) the file is world- or group-readable. This gives operators an alternative
/// to stuffing the key into the process env, where it's visible to anyone who can read
/// /proc/<pid>/environ.
pub fn load_master_key_from_file(path: &std::path::Path) -> Result<[u8; KEY_LEN], AppError> {
    check_key_file_perms(path)?;
    let contents = std::fs::read_to_string(path).map_err(|e| {
        AppError::InternalError(format!(
            "failed to read AUTHERE_PROVISIONING_KEY_FILE ({}): {e}",
            path.display()
        ))
    })?;
    parse_master_key(&contents)
}

/// On Unix, refuse to load a key file that's readable by anyone other than the owner.
/// On non-Unix platforms this is a no-op — the caller inherits whatever ACLs the OS enforces.
fn check_key_file_perms(path: &std::path::Path) -> Result<(), AppError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| {
            AppError::InternalError(format!("cannot stat {}: {e}", path.display()))
        })?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(AppError::InternalError(format!(
                "AUTHERE_PROVISIONING_KEY_FILE {} has mode {:o}; must be 0600 or stricter (not group/world readable)",
                path.display(),
                mode
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Resolve the master key from the first configured source:
///   1. `AUTHERE_PROVISIONING_KEY_FILE` (preferred in production — key stays off the env)
///   2. `AUTHERE_PROVISIONING_KEY` (inline hex, simplest for dev)
///
/// Returns an error if neither is set or the chosen source can't be parsed.
pub fn load_master_key() -> Result<[u8; KEY_LEN], AppError> {
    if let Ok(path) = std::env::var("AUTHERE_PROVISIONING_KEY_FILE") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return load_master_key_from_file(std::path::Path::new(trimmed));
        }
    }
    let hex_key = std::env::var("AUTHERE_PROVISIONING_KEY").map_err(|_| {
        AppError::InternalError(
            "neither AUTHERE_PROVISIONING_KEY_FILE nor AUTHERE_PROVISIONING_KEY is set — outbound provisioning is disabled".into(),
        )
    })?;
    parse_master_key(&hex_key)
}

/// Encrypt a plaintext token under the given key. Returns `(ciphertext, nonce)` — both stored
/// on the `provisioning_targets` row verbatim.
pub fn encrypt_token(plaintext: &str, key: &[u8; KEY_LEN]) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| AppError::InternalError(format!("encryption failed: {e}")))?;
    Ok((ct, nonce_bytes.to_vec()))
}

/// Decrypt a stored token. On tamper / wrong key / corrupted nonce this returns an error.
pub fn decrypt_token(
    ciphertext: &[u8],
    nonce: &[u8],
    key: &[u8; KEY_LEN],
) -> Result<String, AppError> {
    if nonce.len() != NONCE_LEN {
        return Err(AppError::InternalError(format!(
            "stored nonce length is {}, expected {}",
            nonce.len(),
            NONCE_LEN
        )));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plaintext_bytes = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| AppError::InternalError(format!("decryption failed: {e}")))?;
    String::from_utf8(plaintext_bytes)
        .map_err(|e| AppError::InternalError(format!("decrypted token not utf-8: {e}")))
}

/// Create a new target. The plaintext token is encrypted on the way in; the caller never
/// sees the stored bytes.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    name: &str,
    kind: &str,
    base_url: &str,
    auth_token: &str,
    enabled: bool,
    created_by: Option<Uuid>,
    attribute_map: Option<&str>,
    dead_letter_webhook_url: Option<&str>,
    key: &[u8; KEY_LEN],
    conn: &mut SqliteConnection,
) -> Result<ProvisioningTarget, AppError> {
    let id = Uuid::now_v7();
    let now = now_epoch();
    let (ct, nonce) = encrypt_token(auth_token, key)?;
    let enabled_int = if enabled { 1i64 } else { 0i64 };

    sqlx::query!(
        r#"INSERT INTO provisioning_targets
            (id, name, kind, base_url, auth_token_ciphertext, auth_token_nonce,
             enabled, created_at, created_by, updated_at, attribute_map,
             dead_letter_webhook_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        id, name, kind, base_url, ct, nonce, enabled_int, now, created_by, now,
        attribute_map, dead_letter_webhook_url
    )
    .execute(conn)
    .await?;

    Ok(ProvisioningTarget {
        id,
        name: name.to_string(),
        kind: kind.to_string(),
        base_url: base_url.to_string(),
        auth_token_ciphertext: ct,
        auth_token_nonce: nonce,
        enabled,
        created_at: now,
        created_by,
        updated_at: now,
        backfill_done_at: None,
        attribute_map: attribute_map.map(String::from),
        dead_letter_webhook_url: dead_letter_webhook_url.map(String::from),
    })
}

pub async fn get(id: Uuid, conn: &mut SqliteConnection) -> Result<Option<ProvisioningTarget>, AppError> {
    let row = sqlx::query!(
        r#"SELECT id as "id: Uuid", name, kind, base_url,
                  auth_token_ciphertext, auth_token_nonce,
                  enabled as "enabled!: bool",
                  created_at, created_by as "created_by: Uuid", updated_at,
                  backfill_done_at, attribute_map, dead_letter_webhook_url
           FROM provisioning_targets WHERE id = ?"#,
        id
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|r| ProvisioningTarget {
        id: r.id,
        name: r.name,
        kind: r.kind,
        base_url: r.base_url,
        auth_token_ciphertext: r.auth_token_ciphertext,
        auth_token_nonce: r.auth_token_nonce,
        enabled: r.enabled,
        created_at: r.created_at,
        created_by: r.created_by,
        updated_at: r.updated_at,
        backfill_done_at: r.backfill_done_at,
        attribute_map: r.attribute_map,
        dead_letter_webhook_url: r.dead_letter_webhook_url,
    }))
}

pub async fn list(conn: &mut SqliteConnection) -> Result<Vec<ProvisioningTarget>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT id as "id: Uuid", name, kind, base_url,
                  auth_token_ciphertext, auth_token_nonce,
                  enabled as "enabled!: bool",
                  created_at, created_by as "created_by: Uuid", updated_at,
                  backfill_done_at, attribute_map, dead_letter_webhook_url
           FROM provisioning_targets ORDER BY created_at DESC"#
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| ProvisioningTarget {
            id: r.id,
            name: r.name,
            kind: r.kind,
            base_url: r.base_url,
            auth_token_ciphertext: r.auth_token_ciphertext,
            auth_token_nonce: r.auth_token_nonce,
            enabled: r.enabled,
            created_at: r.created_at,
            created_by: r.created_by,
            updated_at: r.updated_at,
            backfill_done_at: r.backfill_done_at,
            attribute_map: r.attribute_map,
            dead_letter_webhook_url: r.dead_letter_webhook_url,
        })
        .collect())
}

/// Mark a target's initial-sync backfill as done. Idempotent: overwrites any existing
/// timestamp with the current one.
pub async fn mark_backfill_done(id: Uuid, conn: &mut SqliteConnection) -> Result<(), AppError> {
    let now = now_epoch();
    sqlx::query!(
        "UPDATE provisioning_targets SET backfill_done_at = ?, updated_at = ? WHERE id = ?",
        now,
        now,
        id
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn list_enabled(conn: &mut SqliteConnection) -> Result<Vec<ProvisioningTarget>, AppError> {
    Ok(list(conn).await?.into_iter().filter(|t| t.enabled).collect())
}

/// Partial update. Any `Some` field is written; `None` means "leave alone". `new_auth_token`
/// re-encrypts with a fresh nonce when supplied. `new_attribute_map` accepts `Some(Some(_))`
/// to set, `Some(None)` to clear, and `None` to leave unchanged.
#[allow(clippy::too_many_arguments)]
pub async fn update(
    id: Uuid,
    new_name: Option<&str>,
    new_base_url: Option<&str>,
    new_enabled: Option<bool>,
    new_auth_token: Option<&str>,
    new_attribute_map: Option<Option<&str>>,
    new_dead_letter_webhook_url: Option<Option<&str>>,
    key: &[u8; KEY_LEN],
    conn: &mut SqliteConnection,
) -> Result<bool, AppError> {
    let Some(mut existing) = get(id, conn).await? else {
        return Ok(false);
    };
    if let Some(n) = new_name {
        existing.name = n.to_string();
    }
    if let Some(u) = new_base_url {
        existing.base_url = u.to_string();
    }
    if let Some(e) = new_enabled {
        existing.enabled = e;
    }
    if let Some(tok) = new_auth_token {
        let (ct, nonce) = encrypt_token(tok, key)?;
        existing.auth_token_ciphertext = ct;
        existing.auth_token_nonce = nonce;
    }
    if let Some(am) = new_attribute_map {
        existing.attribute_map = am.map(String::from);
    }
    if let Some(url) = new_dead_letter_webhook_url {
        existing.dead_letter_webhook_url = url.map(String::from);
    }
    existing.updated_at = now_epoch();
    let enabled_int = if existing.enabled { 1i64 } else { 0i64 };

    sqlx::query!(
        r#"UPDATE provisioning_targets
              SET name = ?, base_url = ?, enabled = ?,
                  auth_token_ciphertext = ?, auth_token_nonce = ?,
                  attribute_map = ?, dead_letter_webhook_url = ?,
                  updated_at = ?
            WHERE id = ?"#,
        existing.name,
        existing.base_url,
        enabled_int,
        existing.auth_token_ciphertext,
        existing.auth_token_nonce,
        existing.attribute_map,
        existing.dead_letter_webhook_url,
        existing.updated_at,
        id
    )
    .execute(conn)
    .await?;
    Ok(true)
}

pub async fn delete(id: Uuid, conn: &mut SqliteConnection) -> Result<bool, AppError> {
    let res = sqlx::query!("DELETE FROM provisioning_targets WHERE id = ?", id)
        .execute(conn)
        .await?;
    Ok(res.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key() -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let k = fixed_key();
        let (ct, nonce) = encrypt_token("hunter2hunter2", &k).unwrap();
        let plain = decrypt_token(&ct, &nonce, &k).unwrap();
        assert_eq!(plain, "hunter2hunter2");
    }

    #[test]
    fn encrypt_produces_fresh_nonce() {
        let k = fixed_key();
        let (ct1, n1) = encrypt_token("same", &k).unwrap();
        let (ct2, n2) = encrypt_token("same", &k).unwrap();
        assert_ne!(n1, n2);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let k = fixed_key();
        let (mut ct, nonce) = encrypt_token("secret", &k).unwrap();
        ct[0] ^= 0xFF;
        assert!(decrypt_token(&ct, &nonce, &k).is_err());
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let k = fixed_key();
        let (ct, nonce) = encrypt_token("secret", &k).unwrap();
        let mut wrong = k;
        wrong[0] ^= 0xFF;
        assert!(decrypt_token(&ct, &nonce, &wrong).is_err());
    }

    #[test]
    fn decrypt_rejects_nonce_of_wrong_length() {
        let k = fixed_key();
        let (ct, _) = encrypt_token("secret", &k).unwrap();
        assert!(decrypt_token(&ct, &[0u8; 8], &k).is_err());
    }

    #[test]
    fn parse_master_key_rejects_short_hex() {
        assert!(parse_master_key("deadbeef").is_err());
    }

    #[test]
    fn parse_master_key_rejects_non_hex() {
        assert!(parse_master_key("not-hex-at-all").is_err());
    }

    #[test]
    fn parse_master_key_accepts_valid_hex() {
        let hex = "0".repeat(KEY_LEN * 2);
        let k = parse_master_key(&hex).unwrap();
        assert_eq!(k, [0u8; KEY_LEN]);
    }

    #[test]
    fn parse_master_key_trims_whitespace() {
        let hex = format!("  {}  ", "a".repeat(KEY_LEN * 2));
        let k = parse_master_key(&hex).unwrap();
        assert_eq!(k, [0xaa; KEY_LEN]);
    }

    #[cfg(unix)]
    #[test]
    fn load_master_key_from_file_rejects_world_readable() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir();
        let path = dir.join(format!("provisioning-key-{}.hex", Uuid::now_v7()));
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "{}", "a".repeat(KEY_LEN * 2)).unwrap();
        drop(f);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = load_master_key_from_file(&path).expect_err("must reject loose perms");
        match err {
            AppError::InternalError(msg) => assert!(msg.contains("0600"), "msg was: {msg}"),
            other => panic!("wrong error variant: {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn load_master_key_from_file_reads_strict_perms() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir();
        let path = dir.join(format!("provisioning-key-{}.hex", Uuid::now_v7()));
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "{}", "a".repeat(KEY_LEN * 2)).unwrap();
        drop(f);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let key = load_master_key_from_file(&path).unwrap();
        assert_eq!(key, [0xaa; KEY_LEN]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_master_key_from_file_fails_on_missing_file() {
        let bogus = std::path::PathBuf::from("/definitely/not/a/real/path.hex");
        assert!(load_master_key_from_file(&bogus).is_err());
    }
}
