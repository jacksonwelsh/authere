//! OpenID Connect provider implementation.
//!
//! Layered on top of the existing Ed25519 signing key, the User model, and forward-auth
//! Applications (extended with an `app_type = 'oidc'` variant). Supports the Authorization
//! Code flow with PKCE and RP-initiated logout. No refresh tokens, no consent screen, no
//! hybrid/implicit flows — see the plan file for the deliberate MVP scope.

pub mod codes;
pub mod jwks;
pub mod token;
