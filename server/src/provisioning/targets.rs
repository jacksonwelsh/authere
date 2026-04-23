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

/// Decode the hex-encoded master key out of the `AUTHERE_PROVISIONING_KEY` env var. Returns
/// an error on missing / malformed input — callers treat this as fatal.
pub fn load_master_key() -> Result<[u8; KEY_LEN], AppError> {
    let hex_key = std::env::var("AUTHERE_PROVISIONING_KEY").map_err(|_| {
        AppError::InternalError(
            "AUTHERE_PROVISIONING_KEY is not set — outbound provisioning is disabled".into(),
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
pub async fn create(
    name: &str,
    kind: &str,
    base_url: &str,
    auth_token: &str,
    enabled: bool,
    created_by: Option<Uuid>,
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
             enabled, created_at, created_by, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        id, name, kind, base_url, ct, nonce, enabled_int, now, created_by, now
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
    })
}

pub async fn get(id: Uuid, conn: &mut SqliteConnection) -> Result<Option<ProvisioningTarget>, AppError> {
    let row = sqlx::query!(
        r#"SELECT id as "id: Uuid", name, kind, base_url,
                  auth_token_ciphertext, auth_token_nonce,
                  enabled as "enabled!: bool",
                  created_at, created_by as "created_by: Uuid", updated_at
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
    }))
}

pub async fn list(conn: &mut SqliteConnection) -> Result<Vec<ProvisioningTarget>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT id as "id: Uuid", name, kind, base_url,
                  auth_token_ciphertext, auth_token_nonce,
                  enabled as "enabled!: bool",
                  created_at, created_by as "created_by: Uuid", updated_at
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
        })
        .collect())
}

pub async fn list_enabled(conn: &mut SqliteConnection) -> Result<Vec<ProvisioningTarget>, AppError> {
    Ok(list(conn).await?.into_iter().filter(|t| t.enabled).collect())
}

/// Partial update. Any `Some` field is written; `None` means "leave alone". `new_auth_token`
/// re-encrypts with a fresh nonce when supplied.
#[allow(clippy::too_many_arguments)]
pub async fn update(
    id: Uuid,
    new_name: Option<&str>,
    new_base_url: Option<&str>,
    new_enabled: Option<bool>,
    new_auth_token: Option<&str>,
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
    existing.updated_at = now_epoch();
    let enabled_int = if existing.enabled { 1i64 } else { 0i64 };

    sqlx::query!(
        r#"UPDATE provisioning_targets
              SET name = ?, base_url = ?, enabled = ?,
                  auth_token_ciphertext = ?, auth_token_nonce = ?,
                  updated_at = ?
            WHERE id = ?"#,
        existing.name,
        existing.base_url,
        enabled_int,
        existing.auth_token_ciphertext,
        existing.auth_token_nonce,
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
}
