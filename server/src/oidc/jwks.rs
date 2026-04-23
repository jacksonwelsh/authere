//! JWKS helpers — load the signing key's public-key ID + bytes from the database, then
//! build a static JWK document for `/.well-known/jwks.json`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sqlx::{SqliteConnection, query};
use uuid::Uuid;

use crate::errors::AppError;

/// A JSON Web Key for an Ed25519 public key. Per RFC 8037 §2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
    pub x: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// Load the signing key's UUID so it can be used as both the JWK `kid` and the JWT header
/// `kid`. The signing key itself lives in `user::auth::token` but we only need its id here.
pub async fn load_signing_kid(conn: &mut SqliteConnection) -> Result<String, AppError> {
    let row = query!(r#"SELECT id as "id: Uuid" FROM keys WHERE name = 'default'"#)
        .fetch_one(conn)
        .await?;
    Ok(row.id.to_string())
}

/// Build the single-key JWKS for the given signing key.
pub fn build_jwks(signing_key: &SigningKey, kid: &str) -> JwkSet {
    let public = signing_key.verifying_key().to_bytes();
    let x = URL_SAFE_NO_PAD.encode(public);
    JwkSet {
        keys: vec![Jwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            alg: "EdDSA".to_string(),
            use_: "sig".to_string(),
            kid: kid.to_string(),
            x,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn build_jwks_has_single_key_with_expected_fields() {
        let sk = SigningKey::generate(&mut OsRng);
        let set = build_jwks(&sk, "kid-42");
        assert_eq!(set.keys.len(), 1);
        let k = &set.keys[0];
        assert_eq!(k.kty, "OKP");
        assert_eq!(k.crv, "Ed25519");
        assert_eq!(k.alg, "EdDSA");
        assert_eq!(k.use_, "sig");
        assert_eq!(k.kid, "kid-42");
        // x should be 32 bytes → 43 base64url-no-pad chars.
        assert_eq!(k.x.len(), 43);
        assert!(!k.x.contains('='));
        assert!(!k.x.contains('+'));
        assert!(!k.x.contains('/'));
    }

    #[test]
    fn build_jwks_encodes_correct_public_key() {
        let sk = SigningKey::generate(&mut OsRng);
        let set = build_jwks(&sk, "kid");
        let decoded = URL_SAFE_NO_PAD.decode(&set.keys[0].x).unwrap();
        assert_eq!(decoded, sk.verifying_key().to_bytes().to_vec());
    }
}
