//! Short-lived authorization codes for the OIDC Authorization Code flow.
//!
//! Codes are 32 bytes of entropy, hex-encoded, and stored SHA-256 hashed (same treatment as
//! SCIM tokens and refresh tokens). Each code is single-use and tied to a specific client +
//! redirect_uri + PKCE challenge. Consumption flips `consumed_at`; replay attempts fail the
//! single-UPDATE guard.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;
use uuid::Uuid;

use crate::errors::AppError;
use crate::oidc::token::AUTHORIZATION_CODE_LIFETIME;

/// A fresh code on its way back to the RP. The plaintext appears in the redirect and must
/// not be logged; the hash is what persists.
pub struct IssuedCode {
    pub plaintext: String,
}

/// The code record loaded for a token-endpoint exchange. `consumed_at` is populated by
/// `consume` before this is returned.
pub struct ConsumedCode {
    pub application_id: Uuid,
    pub user_id: Uuid,
    pub redirect_uri: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub auth_time: i64,
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

pub fn hash_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hex::encode(hasher.finalize())
}

fn generate_plaintext() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Insert a new authorization code and return its plaintext.
#[allow(clippy::too_many_arguments)]
pub async fn issue(
    application_id: Uuid,
    user_id: Uuid,
    redirect_uri: &str,
    scope: &str,
    nonce: Option<&str>,
    code_challenge: &str,
    code_challenge_method: &str,
    auth_time: i64,
    conn: &mut SqliteConnection,
) -> Result<IssuedCode, AppError> {
    let plaintext = generate_plaintext();
    let hash = hash_code(&plaintext);
    let now = now_epoch();
    let expires_at = now + AUTHORIZATION_CODE_LIFETIME;

    sqlx::query!(
        r#"INSERT INTO oidc_authorization_codes
               (code_hash, application_id, user_id, redirect_uri, scope, nonce,
                code_challenge, code_challenge_method, auth_time, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        hash,
        application_id,
        user_id,
        redirect_uri,
        scope,
        nonce,
        code_challenge,
        code_challenge_method,
        auth_time,
        expires_at,
    )
    .execute(conn)
    .await?;

    Ok(IssuedCode { plaintext })
}

/// Atomically consume a code: marks `consumed_at = now` only if the code is not already
/// consumed and not expired. Returns `Ok(Some(...))` when this call claimed the code,
/// `Ok(None)` for unknown/replayed/expired codes.
pub async fn consume(
    code: &str,
    conn: &mut SqliteConnection,
) -> Result<Option<ConsumedCode>, AppError> {
    let hash = hash_code(code);
    let now = now_epoch();

    let row = sqlx::query!(
        r#"SELECT application_id as "application_id: Uuid",
                  user_id as "user_id: Uuid",
                  redirect_uri, scope, nonce, code_challenge,
                  code_challenge_method, auth_time, expires_at, consumed_at
             FROM oidc_authorization_codes WHERE code_hash = ?"#,
        hash
    )
    .fetch_optional(&mut *conn)
    .await?;

    let Some(row) = row else { return Ok(None); };
    if row.consumed_at.is_some() || row.expires_at < now {
        return Ok(None);
    }

    let res = sqlx::query!(
        r#"UPDATE oidc_authorization_codes
              SET consumed_at = ?
            WHERE code_hash = ? AND consumed_at IS NULL AND expires_at >= ?"#,
        now,
        hash,
        now
    )
    .execute(conn)
    .await?;

    if res.rows_affected() != 1 {
        return Ok(None);
    }

    Ok(Some(ConsumedCode {
        application_id: row.application_id,
        user_id: row.user_id,
        redirect_uri: row.redirect_uri,
        scope: row.scope,
        nonce: row.nonce,
        code_challenge: row.code_challenge,
        code_challenge_method: row.code_challenge_method,
        auth_time: row.auth_time,
    }))
}

/// Delete rows older than one hour past their expiry. Called periodically from the
/// background sweep task.
pub async fn sweep_expired(conn: &mut SqliteConnection) -> Result<u64, AppError> {
    let cutoff = now_epoch() - 3600;
    let res = sqlx::query!(
        "DELETE FROM oidc_authorization_codes WHERE expires_at < ?",
        cutoff
    )
    .execute(conn)
    .await?;
    Ok(res.rows_affected())
}

/// Verify a PKCE `code_verifier` against a stored `code_challenge`. S256 only — `plain` is
/// rejected at authorize time, so verification never encounters it.
pub fn verify_pkce_s256(code_verifier: &str, code_challenge: &str) -> bool {
    if code_verifier.len() < 43 || code_verifier.len() > 128 {
        return false;
    }
    if !code_verifier
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return false;
    }
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let digest = hasher.finalize();
    let encoded = URL_SAFE_NO_PAD.encode(digest);
    encoded == code_challenge
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::{AppType, Application, CreateApplicationInput};
    use crate::db::DbEntity;
    use crate::user::User;
    use sqlx::SqlitePool;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("../migrations").run(&pool).await.unwrap();
        pool
    }

    async fn seed(conn: &mut SqliteConnection) -> (Uuid, Uuid) {
        let user = User::new("a".into(), "Alice".into(), None);
        user.save(conn).await.unwrap();

        let input = CreateApplicationInput {
            name: "RP".into(),
            slug: "rp".into(),
            app_type: Some(AppType::Oidc),
            host_pattern: None,
            path_prefix: None,
            required_roles: None,
            enabled: Some(true),
            oidc_redirect_uris: Some(vec!["https://app.example.com/cb".into()]),
            oidc_post_logout_redirect_uris: None,
            oidc_confidential: Some(true),
        };
        let (app, _) = Application::new_oidc(input);
        app.save(conn).await.unwrap();

        (user.id, app.id)
    }

    #[tokio::test]
    async fn issue_and_consume_roundtrip() {
        let pool = pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let (user_id, app_id) = seed(&mut conn).await;

        let issued = issue(
            app_id,
            user_id,
            "https://app.example.com/cb",
            "openid profile",
            Some("nonce-xyz"),
            "challenge-abc",
            "S256",
            1_700_000_000,
            &mut conn,
        )
        .await
        .unwrap();

        let consumed = consume(&issued.plaintext, &mut conn).await.unwrap().unwrap();
        assert_eq!(consumed.application_id, app_id);
        assert_eq!(consumed.user_id, user_id);
        assert_eq!(consumed.redirect_uri, "https://app.example.com/cb");
        assert_eq!(consumed.scope, "openid profile");
        assert_eq!(consumed.nonce.as_deref(), Some("nonce-xyz"));
    }

    #[tokio::test]
    async fn consume_rejects_replay() {
        let pool = pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let (user_id, app_id) = seed(&mut conn).await;

        let issued = issue(
            app_id, user_id, "https://app.example.com/cb", "openid",
            None, "c", "S256", 0, &mut conn,
        )
        .await
        .unwrap();

        assert!(consume(&issued.plaintext, &mut conn).await.unwrap().is_some());
        assert!(consume(&issued.plaintext, &mut conn).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn consume_rejects_unknown() {
        let pool = pool().await;
        let mut conn = pool.acquire().await.unwrap();
        assert!(consume("nope", &mut conn).await.unwrap().is_none());
    }

    #[test]
    fn pkce_s256_roundtrip() {
        // RFC 7636 §4.6 test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_pkce_s256(verifier, challenge));
    }

    #[test]
    fn pkce_s256_rejects_wrong_challenge() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert!(!verify_pkce_s256(verifier, "wrong"));
    }

    #[test]
    fn pkce_rejects_short_verifier() {
        assert!(!verify_pkce_s256("too-short", "anything"));
    }

    #[test]
    fn pkce_rejects_long_verifier() {
        let long = "a".repeat(129);
        assert!(!verify_pkce_s256(&long, "anything"));
    }

    #[test]
    fn pkce_rejects_invalid_chars() {
        let bad = "a".repeat(43) + "!";
        // The invalid char makes total length 44 which is in-range, but the non-URL-safe
        // character must be rejected.
        assert!(!verify_pkce_s256(&bad, "whatever"));
    }

    #[test]
    fn hash_code_deterministic() {
        assert_eq!(hash_code("abc"), hash_code("abc"));
        assert_ne!(hash_code("abc"), hash_code("abd"));
    }
}
