//! Minimal LDAP server for homelab directory-consumer clients (Jellyfin etc.).
//!
//! Only the BIND, SEARCH, UNBIND, and Whoami operations are implemented; anything else
//! responds with `unwillingToPerform`. The directory is read-only — Authere owns the
//! source of truth, LDAP is purely a view.

pub mod filter;
pub mod handler;
pub mod schema;
pub mod server;

pub use server::{handle_connection, run};
