//! Per-connection dispatch of LDAP operations against the Authere data model.
//!
//! The entry points are [`handle_bind`] and [`handle_search`]. They return ready-to-send
//! [`LdapMsg`] responses plus, in the bind case, the new [`BindState`]. The caller owns
//! the socket and the Framed codec; this module only touches state/db.

use std::net::IpAddr;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use ldap3_proto::proto::{LdapMsg, LdapOp, LdapResult, LdapResultCode, LdapSearchScope};
use ldap3_proto::simple::{SearchRequest, SimpleBindRequest};
use sqlx::SqliteConnection;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::AppState;
use crate::audit::{log_ldap_bind_failed, log_ldap_bind_rejected_mfa_required, log_ldap_bind_success};
use crate::app_passwords::AppPassword;
use crate::role::{Role, UserRole};
use crate::settings::{LdapConfig, LdapPasswordMode};
use crate::user::User;
use crate::user::auth::Authenticator;

use super::filter;
use super::schema::{
    Dn, Entry, build_group_entry, build_root_dse, build_user_entry, parse_dn,
};

/// Current authentication state of an LDAP connection.
#[derive(Debug, Clone)]
pub enum BindState {
    Anonymous,
    Service,
    User(Uuid),
}

/// Handle a simple bind. Returns the response message and the new bind state. On any
/// failure (invalid credentials, unknown DN, TOTP required, etc.) the new state is
/// [`BindState::Anonymous`].
pub async fn handle_bind(
    req: &SimpleBindRequest,
    cfg: &LdapConfig,
    state: &AppState,
    peer_ip: IpAddr,
) -> (LdapMsg, BindState) {
    let mode = cfg.password_mode;
    let ip_str = peer_ip.to_string();
    let mode_str = mode.as_str().to_string();

    // Anonymous bind — allowed, for Root DSE lookup only.
    if req.dn.is_empty() && req.pw.is_empty() {
        return (req.gen_success(), BindState::Anonymous);
    }

    let Ok(dn) = parse_dn(&req.dn) else {
        return bind_failed(req, &ip_str, &mode_str, "invalid_dn", None, &req.dn, state).await;
    };

    // Service account?
    if dn.equals(&service_dn(cfg)) {
        return handle_service_bind(req, cfg, state, &ip_str, &mode_str).await;
    }

    // User?
    let people_suffix = match parse_dn(&cfg.people_base_dn()) {
        Ok(d) => d,
        Err(_) => {
            return bind_failed(req, &ip_str, &mode_str, "bad_config", None, &req.dn, state).await
        }
    };
    if dn.depth_under(&people_suffix) == Some(1) {
        if let Some((attr, value)) = dn.leaf() {
            if attr == "uid" {
                return handle_user_bind(req, cfg, state, &ip_str, &mode_str, value).await;
            }
        }
    }

    // Unknown DN — run dummy verify to preserve timing, log, fail.
    Authenticator::dummy_password_check();
    bind_failed(
        req,
        &ip_str,
        &mode_str,
        "unknown_dn",
        None,
        &req.dn,
        state,
    )
    .await
}

async fn handle_service_bind(
    req: &SimpleBindRequest,
    cfg: &LdapConfig,
    state: &AppState,
    ip: &str,
    mode: &str,
) -> (LdapMsg, BindState) {
    let Some(ref hash) = cfg.service_password_hash else {
        // No password set — treat as invalid credentials.
        Authenticator::dummy_password_check();
        return bind_failed(req, ip, mode, "service_password_unset", None, &req.dn, state).await;
    };

    if verify_argon2(hash, &req.pw) {
        let mut conn = match state.db_pool.acquire().await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "ldap: db acquire failed during service bind");
                return (req.gen_operror("internal error"), BindState::Anonymous);
            }
        };
        let _ = log_ldap_bind_success(None, &req.dn, ip, mode, "service", &mut conn).await;
        (req.gen_success(), BindState::Service)
    } else {
        bind_failed(
            req,
            ip,
            mode,
            "invalid_credentials",
            None,
            &req.dn,
            state,
        )
        .await
    }
}

async fn handle_user_bind(
    req: &SimpleBindRequest,
    cfg: &LdapConfig,
    state: &AppState,
    ip: &str,
    mode: &str,
    username: &str,
) -> (LdapMsg, BindState) {
    let mut conn = match state.db_pool.acquire().await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "ldap: db acquire failed during user bind");
            return (req.gen_operror("internal error"), BindState::Anonymous);
        }
    };

    let user = match User::get_by_username(username, &mut conn).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            Authenticator::dummy_password_check();
            return bind_failed_with_conn(
                req,
                ip,
                mode,
                "unknown_user",
                None,
                &req.dn,
                &mut conn,
            )
            .await;
        }
        Err(e) => {
            warn!(error = ?e, "ldap: user lookup failed");
            return (req.gen_operror("internal error"), BindState::Anonymous);
        }
    };

    if !user.active {
        Authenticator::dummy_password_check();
        return bind_failed_with_conn(
            req,
            ip,
            mode,
            "user_inactive",
            Some(user.id),
            &req.dn,
            &mut conn,
        )
        .await;
    }

    let totp = match user_has_totp(user.id, &mut conn).await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = ?e, "ldap: totp lookup failed");
            return (req.gen_operror("internal error"), BindState::Anonymous);
        }
    };

    match cfg.password_mode {
        LdapPasswordMode::PrimaryOnly => {
            if totp {
                let _ = log_ldap_bind_rejected_mfa_required(user.id, &req.dn, ip, mode, &mut conn)
                    .await;
                Authenticator::dummy_password_check();
                return (req.gen_invalid_cred(), BindState::Anonymous);
            }
            try_primary(req, &user, ip, mode, &mut conn).await
        }
        LdapPasswordMode::AppOnly => try_app_password(req, &user, ip, mode, &mut conn).await,
        LdapPasswordMode::PrimaryAndApp => {
            match AppPassword::verify_for_user(user.id, &req.pw, &mut conn).await {
                Ok(Some(_)) => {
                    let _ = log_ldap_bind_success(
                        Some(user.id),
                        &req.dn,
                        ip,
                        mode,
                        "app_password",
                        &mut conn,
                    )
                    .await;
                    (req.gen_success(), BindState::User(user.id))
                }
                Ok(None) => {
                    if totp {
                        // MFA user: primary password is never tried.
                        Authenticator::dummy_password_check();
                        let _ = log_ldap_bind_failed(
                            Some(user.id),
                            &req.dn,
                            ip,
                            mode,
                            "invalid_credentials",
                            &mut conn,
                        )
                        .await;
                        (req.gen_invalid_cred(), BindState::Anonymous)
                    } else {
                        try_primary(req, &user, ip, mode, &mut conn).await
                    }
                }
                Err(e) => {
                    warn!(error = ?e, "ldap: app password verify failed");
                    (req.gen_operror("internal error"), BindState::Anonymous)
                }
            }
        }
    }
}

async fn try_primary(
    req: &SimpleBindRequest,
    user: &User,
    ip: &str,
    mode: &str,
    conn: &mut SqliteConnection,
) -> (LdapMsg, BindState) {
    match Authenticator::try_password_login(user, req.pw.clone(), conn).await {
        Ok(()) => {
            let _ = log_ldap_bind_success(
                Some(user.id),
                &req.dn,
                ip,
                mode,
                "primary",
                &mut *conn,
            )
            .await;
            (req.gen_success(), BindState::User(user.id))
        }
        Err(_) => {
            let _ = log_ldap_bind_failed(
                Some(user.id),
                &req.dn,
                ip,
                mode,
                "invalid_credentials",
                &mut *conn,
            )
            .await;
            (req.gen_invalid_cred(), BindState::Anonymous)
        }
    }
}

async fn try_app_password(
    req: &SimpleBindRequest,
    user: &User,
    ip: &str,
    mode: &str,
    conn: &mut SqliteConnection,
) -> (LdapMsg, BindState) {
    match AppPassword::verify_for_user(user.id, &req.pw, conn).await {
        Ok(Some(_)) => {
            let _ = log_ldap_bind_success(
                Some(user.id),
                &req.dn,
                ip,
                mode,
                "app_password",
                &mut *conn,
            )
            .await;
            (req.gen_success(), BindState::User(user.id))
        }
        Ok(None) => {
            Authenticator::dummy_password_check();
            let _ = log_ldap_bind_failed(
                Some(user.id),
                &req.dn,
                ip,
                mode,
                "invalid_credentials",
                &mut *conn,
            )
            .await;
            (req.gen_invalid_cred(), BindState::Anonymous)
        }
        Err(e) => {
            warn!(error = ?e, "ldap: app password verify failed");
            (req.gen_operror("internal error"), BindState::Anonymous)
        }
    }
}

async fn bind_failed(
    req: &SimpleBindRequest,
    ip: &str,
    mode: &str,
    reason: &str,
    user_id: Option<Uuid>,
    dn: &str,
    state: &AppState,
) -> (LdapMsg, BindState) {
    if let Ok(mut conn) = state.db_pool.acquire().await {
        let _ = log_ldap_bind_failed(user_id, dn, ip, mode, reason, &mut conn).await;
    }
    (req.gen_invalid_cred(), BindState::Anonymous)
}

async fn bind_failed_with_conn(
    req: &SimpleBindRequest,
    ip: &str,
    mode: &str,
    reason: &str,
    user_id: Option<Uuid>,
    dn: &str,
    conn: &mut SqliteConnection,
) -> (LdapMsg, BindState) {
    let _ = log_ldap_bind_failed(user_id, dn, ip, mode, reason, conn).await;
    (req.gen_invalid_cred(), BindState::Anonymous)
}

fn service_dn(cfg: &LdapConfig) -> Dn {
    parse_dn(&cfg.service_account_dn()).expect("service DN must parse")
}

async fn user_has_totp(user_id: Uuid, conn: &mut SqliteConnection) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT COUNT(*) as count FROM authenticators WHERE owner_id = ? AND type = 'totp'",
        user_id
    )
    .fetch_one(conn)
    .await?;
    Ok(row.count > 0)
}

fn verify_argon2(hash: &str, cleartext: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(cleartext.as_bytes(), &parsed)
        .is_ok()
}

/// Handle a search request. Returns the sequence of messages to send back to the client
/// (result entries, then a single SearchResultDone). Searches below the people OU return
/// users; below the groups OU return roles; base="" + Base scope returns the Root DSE.
pub async fn handle_search(
    req: &SearchRequest,
    cfg: &LdapConfig,
    state: &AppState,
    bind_state: &BindState,
) -> Vec<LdapMsg> {
    // Require a bind for anything but the Root DSE (empty base).
    if matches!(bind_state, BindState::Anonymous) && !req.base.is_empty() {
        return vec![done(req, LdapResultCode::InsufficentAccessRights, "bind required")];
    }

    // Root DSE: empty base + Base scope.
    if req.base.is_empty() && req.scope == LdapSearchScope::Base {
        let dse = build_root_dse(cfg);
        return finalize(req, vec![dse]);
    }

    let Ok(base) = parse_dn(&req.base) else {
        return vec![done(req, LdapResultCode::InvalidDNSyntax, "bad base DN")];
    };

    let Ok(people) = parse_dn(&cfg.people_base_dn()) else {
        return vec![done(req, LdapResultCode::OperationsError, "bad config")];
    };
    let Ok(groups) = parse_dn(&cfg.groups_base_dn()) else {
        return vec![done(req, LdapResultCode::OperationsError, "bad config")];
    };
    let Ok(root) = parse_dn(&cfg.base_dn) else {
        return vec![done(req, LdapResultCode::OperationsError, "bad config")];
    };

    // Decide which categories we need to scan, based on the base DN + scope.
    let include_users = match req.scope {
        LdapSearchScope::Base => base.equals(&people) || base.depth_under(&people) == Some(1),
        LdapSearchScope::OneLevel => base.equals(&people),
        LdapSearchScope::Subtree | LdapSearchScope::Children => {
            base.is_under(&people) || people.is_under(&base)
        }
    };
    let include_groups = match req.scope {
        LdapSearchScope::Base => base.equals(&groups) || base.depth_under(&groups) == Some(1),
        LdapSearchScope::OneLevel => base.equals(&groups),
        LdapSearchScope::Subtree | LdapSearchScope::Children => {
            base.is_under(&groups) || groups.is_under(&base)
        }
    };

    if !include_users && !include_groups {
        // Unknown subtree — return "no such object" rather than a bare empty result, which
        // some clients treat as a bug.
        if !base.equals(&root) && !base.is_under(&root) {
            return vec![done(req, LdapResultCode::NoSuchObject, "")];
        }
        return vec![done(req, LdapResultCode::Success, "")];
    }

    // Load the directory snapshot.
    let mut conn = match state.db_pool.acquire().await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "ldap: db acquire failed during search");
            return vec![done(req, LdapResultCode::OperationsError, "internal error")];
        }
    };

    let mut entries: Vec<Entry> = Vec::new();

    if include_users {
        let users = match User::list(&mut conn).await {
            Ok(u) => u,
            Err(e) => {
                warn!(error = ?e, "ldap: user list failed");
                return vec![done(req, LdapResultCode::OperationsError, "internal error")];
            }
        };
        for user in &users {
            let role_names = match user.get_roles(&mut conn).await {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = ?e, "ldap: user roles lookup failed");
                    Vec::new()
                }
            };
            let entry = build_user_entry(user, &role_names, cfg);
            let entry_dn = match parse_dn(&entry.dn) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if entry_in_scope(&entry_dn, &base, &req.scope)
                && filter::matches(&entry, &req.filter)
            {
                entries.push(entry);
            }
        }
    }

    if include_groups {
        let roles = match Role::list(&mut conn).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = ?e, "ldap: role list failed");
                return vec![done(req, LdapResultCode::OperationsError, "internal error")];
            }
        };
        // For each role, gather member usernames.
        let users = match User::list(&mut conn).await {
            Ok(u) => u,
            Err(e) => {
                warn!(error = ?e, "ldap: user list failed");
                return vec![done(req, LdapResultCode::OperationsError, "internal error")];
            }
        };
        for role in &roles {
            let mut member_usernames: Vec<String> = Vec::new();
            for user in &users {
                let user_roles = UserRole::get_for_user(user.id, &mut conn)
                    .await
                    .unwrap_or_default();
                if user_roles.iter().any(|r| r.role_name == role.name) {
                    member_usernames.push(user.username.clone());
                }
            }
            let entry = build_group_entry(role, &member_usernames, cfg);
            let entry_dn = match parse_dn(&entry.dn) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if entry_in_scope(&entry_dn, &base, &req.scope)
                && filter::matches(&entry, &req.filter)
            {
                entries.push(entry);
            }
        }
    }

    debug!(count = entries.len(), "ldap: search returning entries");
    finalize(req, entries)
}

fn entry_in_scope(entry: &Dn, base: &Dn, scope: &LdapSearchScope) -> bool {
    match scope {
        LdapSearchScope::Base => entry.equals(base),
        LdapSearchScope::OneLevel => entry.depth_under(base) == Some(1),
        LdapSearchScope::Subtree => entry.is_under(base),
        LdapSearchScope::Children => entry.is_under(base) && !entry.equals(base),
    }
}

fn finalize(req: &SearchRequest, entries: Vec<Entry>) -> Vec<LdapMsg> {
    let mut out = Vec::with_capacity(entries.len() + 1);
    for entry in entries {
        out.push(req.gen_result_entry(entry.to_ldap(&req.attrs)));
    }
    out.push(req.gen_success());
    out
}

fn done(req: &SearchRequest, code: LdapResultCode, msg: &str) -> LdapMsg {
    LdapMsg {
        msgid: req.msgid,
        op: LdapOp::SearchResultDone(LdapResult {
            code,
            matcheddn: String::new(),
            message: msg.to_string(),
            referral: Vec::new(),
        }),
        ctrl: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{DEFAULT_LDAP_BASE_DN, LdapPasswordMode};

    fn cfg() -> LdapConfig {
        LdapConfig {
            enabled: true,
            base_dn: DEFAULT_LDAP_BASE_DN.to_string(),
            bind_address: "0.0.0.0:3389".parse().unwrap(),
            service_password_hash: None,
            password_mode: LdapPasswordMode::default(),
        }
    }

    #[test]
    fn entry_in_scope_base_matches_self_only() {
        let base = parse_dn("ou=people,dc=authere,dc=local").unwrap();
        let people = parse_dn("ou=people,dc=authere,dc=local").unwrap();
        let alice = parse_dn("uid=alice,ou=people,dc=authere,dc=local").unwrap();
        assert!(entry_in_scope(&people, &base, &LdapSearchScope::Base));
        assert!(!entry_in_scope(&alice, &base, &LdapSearchScope::Base));
    }

    #[test]
    fn entry_in_scope_onelevel_matches_direct_children() {
        let base = parse_dn("ou=people,dc=authere,dc=local").unwrap();
        let alice = parse_dn("uid=alice,ou=people,dc=authere,dc=local").unwrap();
        let people = parse_dn("ou=people,dc=authere,dc=local").unwrap();
        assert!(entry_in_scope(&alice, &base, &LdapSearchScope::OneLevel));
        assert!(!entry_in_scope(&people, &base, &LdapSearchScope::OneLevel));
    }

    #[test]
    fn entry_in_scope_subtree_matches_self_and_descendants() {
        let base = parse_dn("dc=authere,dc=local").unwrap();
        let alice = parse_dn("uid=alice,ou=people,dc=authere,dc=local").unwrap();
        let root = parse_dn("dc=authere,dc=local").unwrap();
        assert!(entry_in_scope(&alice, &base, &LdapSearchScope::Subtree));
        assert!(entry_in_scope(&root, &base, &LdapSearchScope::Subtree));
    }

    #[test]
    fn service_dn_parses() {
        let cfg = cfg();
        let svc = service_dn(&cfg);
        assert_eq!(svc.leaf().unwrap().0, "cn");
        assert_eq!(svc.leaf().unwrap().1, "service");
    }
}
