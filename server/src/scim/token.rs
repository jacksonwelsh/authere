//! SCIM bearer token lifecycle: minting, hashing, verifying, revoking.
//!
//! Tokens are 32 bytes of `OsRng` entropy, base64url-nopad encoded, and prefixed with
//! `authere_scim_` so leaked tokens are greppable (mirrors GitHub PAT conventions). Because
//! they already carry ~256 bits of uniformly random entropy, we hash them with plain SHA-256
//! rather than argon2 — same treatment as `refresh_tokens` in this codebase. Argon2 exists
//! to slow down dictionary attacks against human-chosen passwords; it would only add per-
//! request latency here.

use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;
use uuid::Uuid;

use crate::errors::AppError;

pub const TOKEN_PREFIX: &str = "authere_scim_";
/// Number of random bytes behind each token. 32 bytes = 256 bits.
pub const TOKEN_ENTROPY_BYTES: usize = 32;
/// How often we refresh `last_used_at` for a given token. One second granularity × debounce
/// of this many seconds keeps write amplification low even under aggressive polling.
pub const LAST_USED_DEBOUNCE_SECS: i64 = 60;

/// A freshly-minted SCIM token. Hand the plaintext to the caller *exactly once*; after that
/// only the hash survives in the database. The caller is expected to display it to the admin
/// and never again log it.
pub struct MintedToken {
    pub id: Uuid,
    pub name: String,
    pub plaintext: String,
    pub created_at: i64,
    pub created_by: Uuid,
}

/// Metadata row as returned from `list_tokens` / `get_token`. Never carries the hash or
/// plaintext to callers.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ScimTokenRecord {
    pub id: Uuid,
    pub name: String,
    pub created_at: i64,
    pub created_by: Uuid,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

/// SHA-256-then-hex the provided token string. `hash_token` is what we store in the DB.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a fresh token. The plaintext is returned alongside the DB row; the hash is
/// what persists.
pub fn generate_plaintext() -> String {
    // Hex rather than base64 to match the rest of the codebase (`hex` is already a dep) and
    // keep the token URL-safe without pulling in a new crate. 32 bytes → 64 hex chars: well
    // within the 128-ish char budget most IdPs accept.
    let mut bytes = [0u8; TOKEN_ENTROPY_BYTES];
    OsRng.fill_bytes(&mut bytes);
    format!("{TOKEN_PREFIX}{}", hex::encode(bytes))
}

/// Accept only strings that could plausibly be our tokens — cheap short-circuit before we hash.
pub fn looks_like_scim_token(candidate: &str) -> bool {
    candidate.starts_with(TOKEN_PREFIX)
        && candidate.len() > TOKEN_PREFIX.len()
        && candidate.len() < 256 // anything above that is adversarial
}

/// Create a new SCIM token for the given admin. Returns the plaintext (hand to the caller
/// immediately) plus the stored record.
pub async fn mint(
    name: &str,
    created_by: Uuid,
    conn: &mut SqliteConnection,
) -> Result<MintedToken, AppError> {
    let plaintext = generate_plaintext();
    let hash = hash_token(&plaintext);
    let id = Uuid::now_v7();
    let created_at = now_epoch();

    sqlx::query!(
        "INSERT INTO scim_tokens (id, name, token_hash, created_at, created_by) VALUES (?, ?, ?, ?, ?)",
        id, name, hash, created_at, created_by
    )
    .execute(conn)
    .await?;

    Ok(MintedToken {
        id,
        name: name.to_string(),
        plaintext,
        created_at,
        created_by,
    })
}

/// Resolve a bearer-presented token to the owning record. Returns `Ok(None)` for unknown or
/// revoked tokens — callers must treat both the same way (401). Always updates
/// `last_used_at` (debounced) so admins can see when tokens were last active.
pub async fn verify(
    token: &str,
    conn: &mut SqliteConnection,
) -> Result<Option<ScimTokenRecord>, AppError> {
    if !looks_like_scim_token(token) {
        return Ok(None);
    }
    let hash = hash_token(token);
    let row = sqlx::query!(
        r#"SELECT id as "id: Uuid", name, created_at, created_by as "created_by: Uuid",
                  last_used_at, revoked_at
             FROM scim_tokens WHERE token_hash = ?"#,
        hash
    )
    .fetch_optional(&mut *conn)
    .await?;

    let Some(row) = row else { return Ok(None); };
    if row.revoked_at.is_some() {
        return Ok(None);
    }

    let now = now_epoch();
    let debounce_cutoff = now - LAST_USED_DEBOUNCE_SECS;
    sqlx::query!(
        r#"UPDATE scim_tokens
              SET last_used_at = ?
            WHERE id = ?
              AND (last_used_at IS NULL OR last_used_at < ?)"#,
        now, row.id, debounce_cutoff
    )
    .execute(conn)
    .await?;

    Ok(Some(ScimTokenRecord {
        id: row.id,
        name: row.name,
        created_at: row.created_at,
        created_by: row.created_by,
        last_used_at: row.last_used_at,
        revoked_at: row.revoked_at,
    }))
}

/// List every token regardless of revocation state — consumed by the admin UI.
pub async fn list(conn: &mut SqliteConnection) -> Result<Vec<ScimTokenRecord>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT id as "id: Uuid", name, created_at, created_by as "created_by: Uuid",
                  last_used_at, revoked_at
             FROM scim_tokens
         ORDER BY created_at DESC"#
    )
    .fetch_all(conn)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| ScimTokenRecord {
            id: r.id,
            name: r.name,
            created_at: r.created_at,
            created_by: r.created_by,
            last_used_at: r.last_used_at,
            revoked_at: r.revoked_at,
        })
        .collect())
}

/// Mark a token revoked. Idempotent: returns Ok(true) if this call flipped the state,
/// Ok(false) if the row was already revoked or doesn't exist.
pub async fn revoke(id: Uuid, conn: &mut SqliteConnection) -> Result<bool, AppError> {
    let now = now_epoch();
    let res = sqlx::query!(
        "UPDATE scim_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        now, id
    )
    .execute(conn)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn get(id: Uuid, conn: &mut SqliteConnection) -> Result<Option<ScimTokenRecord>, AppError> {
    let row = sqlx::query!(
        r#"SELECT id as "id: Uuid", name, created_at, created_by as "created_by: Uuid",
                  last_used_at, revoked_at
             FROM scim_tokens WHERE id = ?"#,
        id
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|r| ScimTokenRecord {
        id: r.id,
        name: r.name,
        created_at: r.created_at,
        created_by: r.created_by,
        last_used_at: r.last_used_at,
        revoked_at: r.revoked_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
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

    async fn admin(conn: &mut SqliteConnection) -> Uuid {
        let u = User::new("admin".into(), "Admin".into(), None);
        u.save(conn).await.unwrap();
        u.id
    }

    #[test]
    fn hash_token_is_deterministic_and_hex() {
        let h1 = hash_token("authere_scim_abc");
        let h2 = hash_token("authere_scim_abc");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_token_different_inputs_differ() {
        assert_ne!(hash_token("a"), hash_token("b"));
    }

    #[test]
    fn generate_plaintext_has_prefix_and_is_unique() {
        let a = generate_plaintext();
        let b = generate_plaintext();
        assert!(a.starts_with(TOKEN_PREFIX));
        assert!(b.starts_with(TOKEN_PREFIX));
        assert_ne!(a, b);
        // 32 bytes hex-encoded = 64 chars.
        assert_eq!(a.len(), TOKEN_PREFIX.len() + 64);
    }

    #[test]
    fn looks_like_scim_token_filters_obvious_garbage() {
        assert!(looks_like_scim_token("authere_scim_x"));
        assert!(!looks_like_scim_token("authere_scim_")); // prefix only, no body
        assert!(!looks_like_scim_token(""));
        assert!(!looks_like_scim_token("Bearer abc"));
        assert!(!looks_like_scim_token("jwt.eyJhbGc"));
        // Something absurdly long should also be rejected.
        let huge = format!("authere_scim_{}", "x".repeat(300));
        assert!(!looks_like_scim_token(&huge));
    }

    #[tokio::test]
    async fn mint_returns_plaintext_and_record_roundtrips() {
        let pool = pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let admin_id = admin(&mut conn).await;

        let minted = mint("Okta prod", admin_id, &mut conn).await.unwrap();
        assert!(minted.plaintext.starts_with(TOKEN_PREFIX));

        let record = verify(&minted.plaintext, &mut conn).await.unwrap().unwrap();
        assert_eq!(record.id, minted.id);
        assert_eq!(record.name, "Okta prod");
        assert_eq!(record.created_by, admin_id);
        assert!(record.revoked_at.is_none());
    }

    #[tokio::test]
    async fn verify_rejects_unknown_token() {
        let pool = pool().await;
        let mut conn = pool.acquire().await.unwrap();
        // No tokens in DB.
        let res = verify("authere_scim_doesnotexist", &mut conn).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn verify_rejects_non_prefixed_token_without_db_hit() {
        let pool = pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let res = verify("just-some-random-string", &mut conn).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn revoked_tokens_no_longer_verify() {
        let pool = pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let admin_id = admin(&mut conn).await;
        let minted = mint("ephemeral", admin_id, &mut conn).await.unwrap();

        assert!(revoke(minted.id, &mut conn).await.unwrap());
        assert!(verify(&minted.plaintext, &mut conn).await.unwrap().is_none());

        // Idempotent.
        assert!(!revoke(minted.id, &mut conn).await.unwrap());
    }

    #[tokio::test]
    async fn revoking_unknown_id_is_false_not_error() {
        let pool = pool().await;
        let mut conn = pool.acquire().await.unwrap();
        assert!(!revoke(Uuid::now_v7(), &mut conn).await.unwrap());
    }

    #[tokio::test]
    async fn list_returns_most_recent_first() {
        let pool = pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let admin_id = admin(&mut conn).await;
        let first = mint("first", admin_id, &mut conn).await.unwrap();
        // Guarantee the second mint has a strictly-greater created_at, since we sort by it.
        std::thread::sleep(std::time::Duration::from_secs(1));
        let second = mint("second", admin_id, &mut conn).await.unwrap();

        let rows = list(&mut conn).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, second.id);
        assert_eq!(rows[1].id, first.id);
    }

    #[tokio::test]
    async fn verify_updates_last_used_at() {
        let pool = pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let admin_id = admin(&mut conn).await;
        let minted = mint("t", admin_id, &mut conn).await.unwrap();

        let before = get(minted.id, &mut conn).await.unwrap().unwrap();
        assert!(before.last_used_at.is_none());

        verify(&minted.plaintext, &mut conn).await.unwrap();
        let after = get(minted.id, &mut conn).await.unwrap().unwrap();
        assert!(after.last_used_at.is_some());
    }

    #[tokio::test]
    async fn get_returns_none_for_unknown_id() {
        let pool = pool().await;
        let mut conn = pool.acquire().await.unwrap();
        assert!(get(Uuid::now_v7(), &mut conn).await.unwrap().is_none());
    }
}
