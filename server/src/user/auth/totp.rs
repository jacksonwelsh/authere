//! RFC 6238 TOTP with HMAC-SHA1, a 30-second period and 6-digit codes — the defaults
//! Google Authenticator, Authy, 1Password, etc. use when scanning `otpauth://totp/…` URIs.
//!
//! The secret is stored AES-GCM-encrypted under `AUTHERE_KEY_SECRET` (same KEK as the JWT
//! signing key), and the highest previously accepted step is persisted to block replay
//! within the ±1 step drift window.
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;
use uuid::Uuid;

use crate::errors::AppError;

pub const TOTP_DIGITS: u32 = 6;
pub const TOTP_PERIOD: u64 = 30;
pub const SECRET_BYTES: usize = 20;
pub const RECOVERY_CODE_COUNT: usize = 10;
/// 10 chars × 5 bits/char of base32 alphabet = 50 bits of entropy per code, grouped as
/// `XXXXX-XXXXX` for the user.
pub const RECOVERY_CODE_LEN: usize = 10;

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

type HmacSha1 = Hmac<Sha1>;

pub fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

pub fn generate_secret() -> [u8; SECRET_BYTES] {
    let mut out = [0u8; SECRET_BYTES];
    OsRng.fill_bytes(&mut out);
    out
}

/// Unpadded Base32 (RFC 4648). Authenticator apps reject padded or lowercased input.
pub fn encode_base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    out
}

/// Build the `otpauth://totp/...` URI that QR-code scanners parse. `issuer` appears both
/// in the path segment (as a prefix) and as a query parameter — older authenticator apps
/// only read one, newer ones read both.
pub fn build_otpauth_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    let secret_b32 = encode_base32(secret);
    let issuer_enc = urlencoding::encode(issuer);
    let account_enc = urlencoding::encode(account);
    format!(
        "otpauth://totp/{issuer_enc}:{account_enc}?secret={secret_b32}&issuer={issuer_enc}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"
    )
}

/// RFC 4226 HOTP, used by TOTP with `counter = floor(unix_time / period)`.
fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(secret)
        .expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let code = (u32::from(result[offset]) & 0x7f) << 24
        | u32::from(result[offset + 1]) << 16
        | u32::from(result[offset + 2]) << 8
        | u32::from(result[offset + 3]);
    code % 10u32.pow(TOTP_DIGITS)
}

/// Verify a TOTP code at `now`, allowing ±1 step drift. Returns the matched step number if
/// the code is valid AND strictly greater than `last_used_step` (replay protection).
pub fn verify_code(
    secret: &[u8],
    code_str: &str,
    now: i64,
    last_used_step: Option<i64>,
) -> Option<i64> {
    let trimmed = code_str.trim();
    if trimmed.len() != TOTP_DIGITS as usize {
        return None;
    }
    let code: u32 = trimmed.parse().ok()?;
    if code >= 10u32.pow(TOTP_DIGITS) {
        return None;
    }
    if now < 0 {
        return None;
    }

    let current_step = (now as u64) / TOTP_PERIOD;
    for delta in [-1i64, 0, 1] {
        let step = current_step as i64 + delta;
        if step < 0 {
            continue;
        }
        if let Some(last) = last_used_step
            && step <= last
        {
            continue;
        }
        if hotp(secret, step as u64) == code {
            return Some(step);
        }
    }
    None
}

// --------------------------------------------------------------------------
// Secret encryption (AES-GCM under AUTHERE_KEY_SECRET)
// --------------------------------------------------------------------------

fn get_kek() -> Result<[u8; 32], AppError> {
    let secret = std::env::var("AUTHERE_KEY_SECRET").map_err(|_| {
        AppError::InternalError(
            "AUTHERE_KEY_SECRET environment variable is required".to_string(),
        )
    })?;
    let bytes = hex::decode(secret.trim()).map_err(|_| {
        AppError::InternalError("AUTHERE_KEY_SECRET must be hex-encoded".to_string())
    })?;
    bytes
        .try_into()
        .map_err(|_| AppError::InternalError("AUTHERE_KEY_SECRET must be 32 bytes".to_string()))
}

pub fn encrypt_secret(secret: &[u8]) -> Result<String, AppError> {
    let kek = get_kek()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&kek));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), secret)
        .map_err(|e| AppError::InternalError(format!("TOTP secret encryption failed: {e}")))?;
    Ok(format!("{}:{}", hex::encode(nonce), hex::encode(ct)))
}

pub fn decrypt_secret(blob: &str) -> Result<Vec<u8>, AppError> {
    let (nonce_hex, ct_hex) = blob
        .split_once(':')
        .ok_or_else(|| AppError::InternalError("TOTP secret malformed".into()))?;
    let nonce = hex::decode(nonce_hex)
        .map_err(|_| AppError::InternalError("TOTP secret nonce not hex".into()))?;
    let ct = hex::decode(ct_hex)
        .map_err(|_| AppError::InternalError("TOTP secret ciphertext not hex".into()))?;
    if nonce.len() != 12 {
        return Err(AppError::InternalError("TOTP secret nonce wrong length".into()));
    }
    let kek = get_kek()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&kek));
    cipher
        .decrypt(Nonce::from_slice(&nonce), ct.as_slice())
        .map_err(|_| AppError::InternalError("TOTP secret decryption failed".into()))
}

// --------------------------------------------------------------------------
// Recovery codes
// --------------------------------------------------------------------------

/// Generate `RECOVERY_CODE_COUNT` human-friendly recovery codes formatted `XXXXX-XXXXX`.
pub fn generate_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            let mut bytes = [0u8; 7];
            OsRng.fill_bytes(&mut bytes);
            let s = encode_base32(&bytes);
            let trimmed: String = s.chars().take(RECOVERY_CODE_LEN).collect();
            format!("{}-{}", &trimmed[..5], &trimmed[5..])
        })
        .collect()
}

/// Canonicalise before hashing — users transcribe codes, so tolerate dashes and whitespace.
pub fn canonicalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(|c| c.to_uppercase())
        .collect()
}

pub fn hash_recovery_code(code: &str) -> String {
    let canonical = canonicalize_recovery_code(code);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

// --------------------------------------------------------------------------
// Database access
// --------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct UserTotp {
    pub user_id: Uuid,
    pub secret_encrypted: String,
    pub last_used_step: Option<i64>,
    pub activated_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl UserTotp {
    pub fn is_activated(&self) -> bool {
        self.activated_at.is_some()
    }

    pub async fn get(user_id: Uuid, conn: &mut SqliteConnection) -> Result<Option<Self>, AppError> {
        let row = sqlx::query!(
            r#"SELECT user_id as "user_id: uuid::Uuid",
                      secret_encrypted,
                      last_used_step,
                      activated_at,
                      created_at,
                      updated_at
               FROM user_totps WHERE user_id = ?"#,
            user_id
        )
        .fetch_optional(conn)
        .await?;
        Ok(row.map(|r| UserTotp {
            user_id: r.user_id,
            secret_encrypted: r.secret_encrypted,
            last_used_step: r.last_used_step,
            activated_at: r.activated_at,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    /// Upsert a pending (unactivated) enrollment, replacing any prior pending OR active state
    /// for this user. Callers should require re-authentication before overwriting an active
    /// enrollment — this function itself does not gate that.
    pub async fn upsert_pending(
        user_id: Uuid,
        secret_encrypted: &str,
        conn: &mut SqliteConnection,
    ) -> Result<(), AppError> {
        let now = now_epoch();
        sqlx::query!(
            r#"INSERT INTO user_totps
                   (user_id, secret_encrypted, last_used_step, activated_at, created_at, updated_at)
               VALUES (?, ?, NULL, NULL, ?, ?)
               ON CONFLICT(user_id) DO UPDATE SET
                   secret_encrypted = excluded.secret_encrypted,
                   last_used_step = NULL,
                   activated_at = NULL,
                   updated_at = excluded.updated_at"#,
            user_id,
            secret_encrypted,
            now,
            now
        )
        .execute(&mut *conn)
        .await?;
        // Wipe any stale recovery codes from a previous enrollment.
        sqlx::query!("DELETE FROM totp_recovery_codes WHERE user_id = ?", user_id)
            .execute(conn)
            .await?;
        Ok(())
    }

    /// Mark this enrollment active and record the step that activated it.
    pub async fn activate(
        user_id: Uuid,
        step: i64,
        conn: &mut SqliteConnection,
    ) -> Result<(), AppError> {
        let now = now_epoch();
        sqlx::query!(
            r#"UPDATE user_totps SET activated_at = ?, last_used_step = ?, updated_at = ?
               WHERE user_id = ? AND activated_at IS NULL"#,
            now,
            step,
            now,
            user_id
        )
        .execute(conn)
        .await?;
        Ok(())
    }

    pub async fn record_step(
        user_id: Uuid,
        step: i64,
        conn: &mut SqliteConnection,
    ) -> Result<(), AppError> {
        let now = now_epoch();
        sqlx::query!(
            "UPDATE user_totps SET last_used_step = ?, updated_at = ? WHERE user_id = ?",
            step,
            now,
            user_id
        )
        .execute(conn)
        .await?;
        Ok(())
    }

    pub async fn delete(user_id: Uuid, conn: &mut SqliteConnection) -> Result<bool, AppError> {
        let res = sqlx::query!("DELETE FROM user_totps WHERE user_id = ?", user_id)
            .execute(&mut *conn)
            .await?;
        sqlx::query!("DELETE FROM totp_recovery_codes WHERE user_id = ?", user_id)
            .execute(conn)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// True iff the user has an *active* TOTP — pending enrollments don't count.
    pub async fn is_activated_for(
        user_id: Uuid,
        conn: &mut SqliteConnection,
    ) -> Result<bool, AppError> {
        let row = sqlx::query!(
            "SELECT COUNT(*) as count FROM user_totps WHERE user_id = ? AND activated_at IS NOT NULL",
            user_id
        )
        .fetch_one(conn)
        .await?;
        Ok(row.count > 0)
    }
}

/// Persist freshly generated recovery codes. Accepts plaintext; stores only the hash.
pub async fn store_recovery_codes(
    user_id: Uuid,
    plaintext_codes: &[String],
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    sqlx::query!("DELETE FROM totp_recovery_codes WHERE user_id = ?", user_id)
        .execute(&mut *conn)
        .await?;
    let now = now_epoch();
    for code in plaintext_codes {
        let id = Uuid::now_v7();
        let hash = hash_recovery_code(code);
        sqlx::query!(
            r#"INSERT INTO totp_recovery_codes (id, user_id, code_hash, used_at, created_at)
               VALUES (?, ?, ?, NULL, ?)"#,
            id,
            user_id,
            hash,
            now
        )
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Consume a recovery code. Returns Ok(true) if the code was valid and unused (and marks it
/// used); Ok(false) otherwise. Does not leak which of "wrong code" vs. "already used".
pub async fn consume_recovery_code(
    user_id: Uuid,
    code: &str,
    conn: &mut SqliteConnection,
) -> Result<bool, AppError> {
    let hash = hash_recovery_code(code);
    let now = now_epoch();
    let res = sqlx::query!(
        r#"UPDATE totp_recovery_codes SET used_at = ?
           WHERE user_id = ? AND code_hash = ? AND used_at IS NULL"#,
        now,
        user_id,
        hash
    )
    .execute(conn)
    .await?;
    Ok(res.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_rfc4648_test_vectors() {
        // RFC 4648 §10.
        assert_eq!(encode_base32(b""), "");
        assert_eq!(encode_base32(b"f"), "MY");
        assert_eq!(encode_base32(b"fo"), "MZXQ");
        assert_eq!(encode_base32(b"foo"), "MZXW6");
        assert_eq!(encode_base32(b"foob"), "MZXW6YQ");
        assert_eq!(encode_base32(b"fooba"), "MZXW6YTB");
        assert_eq!(encode_base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn hotp_rfc4226_vectors() {
        // RFC 4226 Appendix D truncated HOTP values for the 20-byte ASCII secret "12345678901234567890".
        let secret = b"12345678901234567890";
        let expected = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(hotp(secret, counter as u64), *want as u32, "counter={counter}");
        }
    }

    #[test]
    fn totp_rfc6238_vector_sha1() {
        // RFC 6238 Appendix B first vector: time = 59 s, SHA1, 8 digits = 94287082.
        // We use 6 digits, so expected = 94287082 % 1_000_000 = 287082.
        let secret = b"12345678901234567890";
        // step = 59/30 = 1 => HOTP(secret, 1) truncated to 6 digits
        assert_eq!(hotp(secret, 1), 287082);
    }

    #[test]
    fn verify_accepts_current_step() {
        let secret = b"12345678901234567890";
        let now = 59;
        let step = 59 / TOTP_PERIOD as i64; // 1
        let code = format!("{:06}", hotp(secret, step as u64));
        let matched = verify_code(secret, &code, now, None).expect("code should verify");
        assert_eq!(matched, step);
    }

    #[test]
    fn verify_accepts_previous_step_drift() {
        let secret = b"12345678901234567890";
        let now = 90; // step 3
        let step_prev = 2;
        let code = format!("{:06}", hotp(secret, step_prev));
        let matched = verify_code(secret, &code, now, None).expect("drift -1 must verify");
        assert_eq!(matched, step_prev as i64);
    }

    #[test]
    fn verify_accepts_next_step_drift() {
        let secret = b"12345678901234567890";
        let now = 90; // step 3
        let step_next = 4;
        let code = format!("{:06}", hotp(secret, step_next));
        let matched = verify_code(secret, &code, now, None).expect("drift +1 must verify");
        assert_eq!(matched, step_next as i64);
    }

    #[test]
    fn verify_rejects_far_past_or_future() {
        let secret = b"12345678901234567890";
        let now = 30 * 100;
        let far_past = format!("{:06}", hotp(secret, 10));
        let far_future = format!("{:06}", hotp(secret, 200));
        assert!(verify_code(secret, &far_past, now, None).is_none());
        assert!(verify_code(secret, &far_future, now, None).is_none());
    }

    #[test]
    fn verify_blocks_replay_at_or_before_last_used_step() {
        let secret = b"12345678901234567890";
        let now = 90; // step 3
        let code_now = format!("{:06}", hotp(secret, 3));
        let first = verify_code(secret, &code_now, now, None).unwrap();
        assert_eq!(first, 3);
        // Submitting the same code again must fail once step 3 is marked used.
        let second = verify_code(secret, &code_now, now, Some(3));
        assert!(second.is_none());
        // A code from step 2 must also fail — no backwards replay.
        let past_code = format!("{:06}", hotp(secret, 2));
        assert!(verify_code(secret, &past_code, now, Some(3)).is_none());
    }

    #[test]
    fn verify_rejects_malformed_input() {
        let secret = b"12345678901234567890";
        assert!(verify_code(secret, "", 60, None).is_none());
        assert!(verify_code(secret, "abcdef", 60, None).is_none());
        assert!(verify_code(secret, "12345", 60, None).is_none()); // wrong length
        assert!(verify_code(secret, "1234567", 60, None).is_none()); // wrong length
        assert!(verify_code(secret, "-12345", 60, None).is_none());
    }

    #[test]
    fn secret_generation_has_expected_entropy() {
        let s1 = generate_secret();
        let s2 = generate_secret();
        assert_ne!(s1, s2, "two fresh secrets must not collide");
        assert_eq!(s1.len(), SECRET_BYTES);
    }

    #[test]
    fn otpauth_uri_has_required_parameters() {
        let secret = [0xab; SECRET_BYTES];
        let uri = build_otpauth_uri("Authere", "alice@example.com", &secret);
        assert!(uri.starts_with("otpauth://totp/Authere:"));
        assert!(uri.contains("secret="));
        assert!(uri.contains("issuer=Authere"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
        assert!(uri.contains("alice%40example.com"));
    }

    #[test]
    fn recovery_codes_are_unique_and_formatted() {
        let codes = generate_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        for c in &codes {
            assert_eq!(c.len(), RECOVERY_CODE_LEN + 1, "code {c} missing dash");
            assert!(c.contains('-'));
        }
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len(), "recovery codes must be unique");
    }

    #[test]
    fn recovery_code_canonicalization_is_consistent() {
        let code = "ABCDE-FGHIJ";
        assert_eq!(canonicalize_recovery_code(code), "ABCDEFGHIJ");
        assert_eq!(canonicalize_recovery_code("abcde-fghij"), "ABCDEFGHIJ");
        assert_eq!(canonicalize_recovery_code(" A B-CDE fghij "), "ABCDEFGHIJ");
        // Same hash regardless of format.
        assert_eq!(
            hash_recovery_code("ABCDE-FGHIJ"),
            hash_recovery_code("abcdefghij")
        );
    }

    // ------------------------------------------------------------------
    // DB-backed tests
    // ------------------------------------------------------------------
    use sqlx::SqlitePool;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn in_memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        sqlx::migrate!("../migrations")
            .run(&pool)
            .await
            .expect("run migrations");
        pool
    }

    async fn seed_user(conn: &mut SqliteConnection) -> Uuid {
        use crate::db::DbEntity;
        let user = crate::user::User::new("alice".into(), "Alice".into(), None);
        user.save(conn).await.unwrap();
        user.id
    }

    #[tokio::test]
    async fn upsert_pending_replaces_previous_state() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let user_id = seed_user(&mut conn).await;

        UserTotp::upsert_pending(user_id, "fake-ct-1", &mut conn).await.unwrap();
        UserTotp::upsert_pending(user_id, "fake-ct-2", &mut conn).await.unwrap();

        let loaded = UserTotp::get(user_id, &mut conn).await.unwrap().unwrap();
        assert_eq!(loaded.secret_encrypted, "fake-ct-2");
        assert!(!loaded.is_activated());
    }

    #[tokio::test]
    async fn activate_requires_pending_state() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let user_id = seed_user(&mut conn).await;

        UserTotp::upsert_pending(user_id, "fake-ct", &mut conn).await.unwrap();
        UserTotp::activate(user_id, 7, &mut conn).await.unwrap();

        let after = UserTotp::get(user_id, &mut conn).await.unwrap().unwrap();
        assert!(after.is_activated());
        assert_eq!(after.last_used_step, Some(7));

        // Re-activating is a no-op on already-activated rows.
        UserTotp::activate(user_id, 100, &mut conn).await.unwrap();
        let again = UserTotp::get(user_id, &mut conn).await.unwrap().unwrap();
        assert_eq!(again.last_used_step, Some(7));
    }

    #[tokio::test]
    async fn is_activated_for_ignores_pending() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let user_id = seed_user(&mut conn).await;

        assert!(!UserTotp::is_activated_for(user_id, &mut conn).await.unwrap());
        UserTotp::upsert_pending(user_id, "ct", &mut conn).await.unwrap();
        assert!(!UserTotp::is_activated_for(user_id, &mut conn).await.unwrap());
        UserTotp::activate(user_id, 1, &mut conn).await.unwrap();
        assert!(UserTotp::is_activated_for(user_id, &mut conn).await.unwrap());
    }

    #[tokio::test]
    async fn recovery_codes_single_use() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let user_id = seed_user(&mut conn).await;

        let codes = vec!["ABCDE-FGHIJ".to_string(), "KLMNO-PQRST".to_string()];
        store_recovery_codes(user_id, &codes, &mut conn).await.unwrap();

        assert!(consume_recovery_code(user_id, "ABCDE-FGHIJ", &mut conn).await.unwrap());
        // Second use of the same code fails.
        assert!(!consume_recovery_code(user_id, "ABCDE-FGHIJ", &mut conn).await.unwrap());
        // Whitespace and case variations still match the unused code.
        assert!(consume_recovery_code(user_id, "klmno pqrst", &mut conn).await.unwrap());
        // Unknown code fails.
        assert!(!consume_recovery_code(user_id, "ZZZZZ-ZZZZZ", &mut conn).await.unwrap());
    }

    #[tokio::test]
    async fn delete_removes_totp_and_codes() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let user_id = seed_user(&mut conn).await;

        UserTotp::upsert_pending(user_id, "ct", &mut conn).await.unwrap();
        UserTotp::activate(user_id, 1, &mut conn).await.unwrap();
        store_recovery_codes(user_id, &["ABCDE-FGHIJ".into()], &mut conn).await.unwrap();

        assert!(UserTotp::delete(user_id, &mut conn).await.unwrap());
        assert!(UserTotp::get(user_id, &mut conn).await.unwrap().is_none());
        assert!(!consume_recovery_code(user_id, "ABCDE-FGHIJ", &mut conn).await.unwrap());
    }

    #[tokio::test]
    async fn upsert_pending_wipes_old_recovery_codes() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let user_id = seed_user(&mut conn).await;

        UserTotp::upsert_pending(user_id, "ct1", &mut conn).await.unwrap();
        store_recovery_codes(user_id, &["ABCDE-FGHIJ".into()], &mut conn).await.unwrap();
        // Re-enrolling must invalidate the old codes so a stale reveal can't bypass the
        // new enrollment.
        UserTotp::upsert_pending(user_id, "ct2", &mut conn).await.unwrap();
        assert!(!consume_recovery_code(user_id, "ABCDE-FGHIJ", &mut conn).await.unwrap());
    }

    // Encryption roundtrip — requires AUTHERE_KEY_SECRET. Runs only when provided.
    #[test]
    fn encrypt_decrypt_roundtrip() {
        // Deterministically set a KEK for this test to avoid polluting other tests.
        unsafe {
            std::env::set_var(
                "AUTHERE_KEY_SECRET",
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            );
        }
        let plaintext = b"supersecretseed1234567890"; // 25 bytes
        let blob = encrypt_secret(plaintext).expect("encrypt ok");
        // Two encryptions of the same plaintext must differ (random nonce).
        let blob2 = encrypt_secret(plaintext).expect("encrypt ok");
        assert_ne!(blob, blob2);
        let out = decrypt_secret(&blob).expect("decrypt ok");
        assert_eq!(out, plaintext);
    }
}
