//! OIDC ID tokens + OIDC-scoped access tokens. Kept distinct from `user::auth::token` because
//! OIDC tokens have a different `aud` (the RP's client_id) and different claim shapes
//! governed by the OIDC Core §5 spec.

use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::application::Application;
use crate::errors::AppError;
use crate::user::User;

/// OIDC access token lifetime (1 hour). Shorter-lived than internal access tokens because RPs
/// hit /userinfo directly with them.
pub const OIDC_ACCESS_TOKEN_LIFETIME: i64 = 60 * 60;
/// ID token lifetime (1 hour). Matches the access token so both expire together.
pub const ID_TOKEN_LIFETIME: i64 = 60 * 60;
/// Authorization code lifetime — short because codes are single-use and exchanged
/// immediately after the redirect.
pub const AUTHORIZATION_CODE_LIFETIME: i64 = 10 * 60;

/// Supported OIDC scopes. `openid` is mandatory; the rest unlock claim families per §5.4.
pub const SCOPE_OPENID: &str = "openid";
pub const SCOPE_PROFILE: &str = "profile";
pub const SCOPE_EMAIL: &str = "email";
/// Non-standard but commonly implemented — exposes the user's Authere roles to the RP.
pub const SCOPE_ROLES: &str = "roles";

/// ID Token claims per OIDC Core §2. Optional claims are gated by scope.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub auth_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    // profile scope
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,

    // email scope
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    // roles scope (Authere-specific)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

/// Claims for OIDC access tokens. `typ=oidc_access` keeps them distinct from internal
/// Authere access tokens (`typ=access`) so a leaked /userinfo token can't be replayed as a
/// general-purpose Authere session.
#[derive(Debug, Serialize, Deserialize)]
pub struct OidcAccessClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub scope: String,
    pub typ: String,
}

/// Split a space-separated scope string into unique tokens. OIDC scope strings are whitespace-
/// delimited (RFC 6749 §3.3).
pub fn parse_scope(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in s.split_whitespace() {
        let token = token.to_string();
        if !out.contains(&token) {
            out.push(token);
        }
    }
    out
}

pub fn scope_contains(scope: &[String], needle: &str) -> bool {
    scope.iter().any(|s| s == needle)
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

fn encoding_key(signing_key: &SigningKey) -> Result<EncodingKey, AppError> {
    let pkcs8 = signing_key
        .to_pkcs8_der()
        .map_err(|e| AppError::InternalError(format!("Failed to encode signing key: {e}")))?;
    Ok(EncodingKey::from_ed_der(pkcs8.as_bytes()))
}

/// Project a `User` into ID token claims, gated by scope.
pub fn build_id_token_claims(
    issuer: &str,
    client_id: &str,
    user: &User,
    user_roles: &[String],
    scope: &[String],
    nonce: Option<String>,
    auth_time: i64,
    now: i64,
) -> IdTokenClaims {
    let mut claims = IdTokenClaims {
        iss: issuer.to_string(),
        sub: user.id.to_string(),
        aud: client_id.to_string(),
        exp: now + ID_TOKEN_LIFETIME,
        iat: now,
        auth_time,
        nonce,
        name: None,
        preferred_username: None,
        updated_at: None,
        email: None,
        email_verified: None,
        roles: None,
    };

    if scope_contains(scope, SCOPE_PROFILE) {
        claims.name = Some(user.name.clone());
        claims.preferred_username = Some(user.username.clone());
        claims.updated_at = Some(user.updated_at);
    }
    if scope_contains(scope, SCOPE_EMAIL)
        && let Some(email) = &user.email
    {
        claims.email = Some(email.clone());
        // Authere does not verify email addresses today. Rather than claim a verification
        // status we don't actually enforce, omit `email_verified` — RPs that require it will
        // treat this as `false` per §5.4.
        claims.email_verified = None;
    }
    if scope_contains(scope, SCOPE_ROLES) {
        claims.roles = Some(user_roles.to_vec());
    }

    claims
}

/// Encode an ID token. The JWT header includes `kid = <signing_key_id>` so RPs can match it
/// against the JWK they fetched from `/.well-known/jwks.json`.
pub fn encode_id_token(
    claims: &IdTokenClaims,
    signing_key: &SigningKey,
    kid: &str,
) -> Result<String, AppError> {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.to_string());
    let key = encoding_key(signing_key)?;
    encode(&header, claims, &key)
        .map_err(|e| AppError::InternalError(format!("Failed to encode id_token: {e}")))
}

/// Generate an OIDC access token suitable for `/oauth/userinfo`.
pub fn generate_oidc_access_token(
    issuer: &str,
    user_id: Uuid,
    client_id: &str,
    scope: &[String],
    signing_key: &SigningKey,
    kid: &str,
) -> Result<String, AppError> {
    let now = now_epoch();
    let claims = OidcAccessClaims {
        iss: issuer.to_string(),
        sub: user_id.to_string(),
        aud: client_id.to_string(),
        exp: now + OIDC_ACCESS_TOKEN_LIFETIME,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        scope: scope.join(" "),
        typ: "oidc_access".to_string(),
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.to_string());
    let key = encoding_key(signing_key)?;
    encode(&header, &claims, &key)
        .map_err(|e| AppError::InternalError(format!("Failed to encode access token: {e}")))
}

/// Verify an OIDC access token presented at `/oauth/userinfo`.
pub fn verify_oidc_access_token(
    token: &str,
    issuer: &str,
    signing_key: &SigningKey,
) -> Result<OidcAccessClaims, AppError> {
    let verifying_key = signing_key.verifying_key();
    let decoding_key = DecodingKey::from_ed_der(&verifying_key.to_bytes());

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_required_spec_claims(&["sub", "exp", "iat", "jti", "typ", "iss"]);
    validation.set_issuer(&[issuer]);
    // Don't bind to a specific aud — /userinfo accepts any OIDC access token minted by this
    // issuer. jsonwebtoken requires we explicitly disable the aud check.
    validation.validate_aud = false;

    let data = decode::<OidcAccessClaims>(token, &decoding_key, &validation)
        .map_err(|_| AppError::AuthenticationRequired)?;
    if data.claims.typ != "oidc_access" {
        return Err(AppError::AuthenticationRequired);
    }
    Ok(data.claims)
}

/// Verify an ID token (used only in tests — RPs verify externally).
#[cfg(test)]
pub fn verify_id_token_for_test(
    token: &str,
    issuer: &str,
    audience: &str,
    signing_key: &SigningKey,
) -> Result<IdTokenClaims, AppError> {
    let verifying_key = signing_key.verifying_key();
    let decoding_key = DecodingKey::from_ed_der(&verifying_key.to_bytes());
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_required_spec_claims(&["sub", "exp", "iat", "iss", "aud"]);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    let data = decode::<IdTokenClaims>(token, &decoding_key, &validation)
        .map_err(|_| AppError::AuthenticationRequired)?;
    Ok(data.claims)
}

/// Assemble the token endpoint response body (RFC 6749 §5.1 + OIDC Core §3.1.3.3).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub id_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
}

/// Convenience helper: mint an ID token + OIDC access token for a post-exchange response.
pub fn mint_token_pair(
    issuer: &str,
    app: &Application,
    user: &User,
    user_roles: &[String],
    scope: &[String],
    nonce: Option<String>,
    auth_time: i64,
    signing_key: &SigningKey,
    kid: &str,
) -> Result<TokenResponse, AppError> {
    let client_id = app
        .oidc_client_id
        .as_deref()
        .ok_or_else(|| AppError::InternalError("OIDC app has no client_id".into()))?;
    let now = now_epoch();
    let id_claims = build_id_token_claims(issuer, client_id, user, user_roles, scope, nonce, auth_time, now);
    let id_token = encode_id_token(&id_claims, signing_key, kid)?;
    let access_token = generate_oidc_access_token(issuer, user.id, client_id, scope, signing_key, kid)?;
    Ok(TokenResponse {
        access_token,
        id_token,
        token_type: "Bearer".to_string(),
        expires_in: OIDC_ACCESS_TOKEN_LIFETIME,
        scope: scope.join(" "),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn test_user() -> User {
        User {
            id: Uuid::now_v7(),
            username: "alice".into(),
            name: "Alice".into(),
            email: Some("alice@example.com".into()),
            active: true,
            external_id: None,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_100,
        }
    }

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn parse_scope_splits_and_dedups() {
        let s = parse_scope("openid profile openid   email");
        assert_eq!(s, vec!["openid", "profile", "email"]);
    }

    #[test]
    fn parse_scope_empty() {
        assert!(parse_scope("").is_empty());
        assert!(parse_scope("   ").is_empty());
    }

    #[test]
    fn scope_contains_works() {
        let scope = vec!["openid".to_string(), "profile".to_string()];
        assert!(scope_contains(&scope, "openid"));
        assert!(scope_contains(&scope, "profile"));
        assert!(!scope_contains(&scope, "email"));
    }

    #[test]
    fn id_token_claims_include_only_requested_scopes() {
        let u = test_user();
        let scope = vec!["openid".to_string()];
        let claims = build_id_token_claims(
            "https://authere",
            "client-123",
            &u,
            &["admin".to_string()],
            &scope,
            None,
            1_700_000_200,
            1_700_000_300,
        );
        assert_eq!(claims.sub, u.id.to_string());
        assert_eq!(claims.aud, "client-123");
        assert_eq!(claims.iss, "https://authere");
        assert!(claims.name.is_none());
        assert!(claims.email.is_none());
        assert!(claims.roles.is_none());
    }

    #[test]
    fn id_token_claims_populate_profile_scope() {
        let u = test_user();
        let scope = vec!["openid".to_string(), "profile".to_string()];
        let claims = build_id_token_claims("iss", "cli", &u, &[], &scope, None, 0, 0);
        assert_eq!(claims.name.as_deref(), Some("Alice"));
        assert_eq!(claims.preferred_username.as_deref(), Some("alice"));
        assert_eq!(claims.updated_at, Some(1_700_000_100));
    }

    #[test]
    fn id_token_claims_populate_email_scope() {
        let u = test_user();
        let scope = vec!["openid".to_string(), "email".to_string()];
        let claims = build_id_token_claims("iss", "cli", &u, &[], &scope, None, 0, 0);
        assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn id_token_claims_populate_roles_scope() {
        let u = test_user();
        let scope = vec!["openid".to_string(), "roles".to_string()];
        let roles = vec!["admin".to_string(), "user".to_string()];
        let claims = build_id_token_claims("iss", "cli", &u, &roles, &scope, None, 0, 0);
        assert_eq!(claims.roles.as_deref(), Some(roles.as_slice()));
    }

    #[test]
    fn id_token_claims_echo_nonce() {
        let u = test_user();
        let claims = build_id_token_claims(
            "iss",
            "cli",
            &u,
            &[],
            &["openid".to_string()],
            Some("n-0S6_WzA2Mj".into()),
            0,
            0,
        );
        assert_eq!(claims.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
    }

    #[test]
    fn encoded_id_token_has_kid_header() {
        let u = test_user();
        let claims = build_id_token_claims("iss", "cli", &u, &[], &["openid".to_string()], None, 0, 0);
        let sk = key();
        let jwt = encode_id_token(&claims, &sk, "kid-abc").unwrap();
        let header = jsonwebtoken::decode_header(&jwt).unwrap();
        assert_eq!(header.kid.as_deref(), Some("kid-abc"));
        assert_eq!(header.alg, Algorithm::EdDSA);
    }

    #[test]
    fn access_token_roundtrip() {
        let sk = key();
        let uid = Uuid::now_v7();
        let token = generate_oidc_access_token(
            "https://authere",
            uid,
            "client-abc",
            &["openid".to_string(), "profile".to_string()],
            &sk,
            "kid",
        )
        .unwrap();
        let claims = verify_oidc_access_token(&token, "https://authere", &sk).unwrap();
        assert_eq!(claims.sub, uid.to_string());
        assert_eq!(claims.aud, "client-abc");
        assert_eq!(claims.scope, "openid profile");
        assert_eq!(claims.typ, "oidc_access");
    }

    #[test]
    fn access_token_rejects_wrong_issuer() {
        let sk = key();
        let token = generate_oidc_access_token(
            "https://authere",
            Uuid::now_v7(),
            "cli",
            &["openid".to_string()],
            &sk,
            "kid",
        )
        .unwrap();
        let err = verify_oidc_access_token(&token, "https://other", &sk).unwrap_err();
        assert!(matches!(err, AppError::AuthenticationRequired));
    }

    #[test]
    fn access_token_rejects_wrong_key() {
        let sk = key();
        let token = generate_oidc_access_token(
            "iss",
            Uuid::now_v7(),
            "cli",
            &["openid".to_string()],
            &sk,
            "kid",
        )
        .unwrap();
        let other = key();
        let err = verify_oidc_access_token(&token, "iss", &other).unwrap_err();
        assert!(matches!(err, AppError::AuthenticationRequired));
    }

    #[test]
    fn access_token_typ_is_enforced() {
        // Forge a JWT with the same claims but `typ = access` — verify must reject it so a
        // forward-auth session cookie can't be replayed at /userinfo.
        let sk = key();
        let now = now_epoch();
        let claims = OidcAccessClaims {
            iss: "iss".into(),
            sub: Uuid::now_v7().to_string(),
            aud: "cli".into(),
            exp: now + 3600,
            iat: now,
            jti: Uuid::new_v4().to_string(),
            scope: "openid".into(),
            typ: "access".into(),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("kid".into());
        let key = encoding_key(&sk).unwrap();
        let token = encode(&header, &claims, &key).unwrap();
        let err = verify_oidc_access_token(&token, "iss", &sk).unwrap_err();
        assert!(matches!(err, AppError::AuthenticationRequired));
    }
}
