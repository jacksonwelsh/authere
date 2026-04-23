//! SCIM 2.0 (RFC 7643 + 7644) provisioning surface for Authere.
//!
//! External IdPs (Okta, Azure AD, OneLogin, etc.) and custom integrations use this API to
//! create, update, deactivate, and query users. Authentication is via admin-issued long-lived
//! bearer tokens stored hashed in `scim_tokens`; every endpoint mounted here should require
//! the [`auth::ScimAuth`] extractor, never the JWT-based `AuthUser`.
//!
//! The public surface is intentionally narrow: a handful of types in [`schema`] describe wire
//! format, [`error`] maps internal errors to SCIM's error body shape, and the handler modules
//! ([`discovery`], [`users`], [`admin`]) register routes.

pub mod admin;
pub mod auth;
pub mod discovery;
pub mod error;
pub mod filter;
pub mod patch;
pub mod schema;
pub mod token;
pub mod users;

pub const SCIM_CONTENT_TYPE: &str = "application/scim+json; charset=utf-8";
pub const USER_SCHEMA_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const LIST_RESPONSE_URN: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const PATCH_OP_URN: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const ERROR_URN: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
