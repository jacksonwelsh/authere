//! DN building, DN parsing, and projection of Authere users / roles into LDAP entries.
//!
//! The LDAP namespace Authere exposes is deliberately tiny:
//!
//! ```text
//! <base_dn>
//! ├── cn=service,<base_dn>
//! ├── ou=people,<base_dn>
//! │   └── uid=<username>,ou=people,<base_dn>
//! └── ou=groups,<base_dn>
//!     └── cn=<role_name>,ou=groups,<base_dn>
//! ```
//!
//! Usernames and role names are already validated to a safe character set (alphanumerics,
//! `.`, `-`, `_`), so no DN escaping is required when we *build* DNs. Parsing incoming DNs
//! needs to tolerate whitespace, case-insensitive attribute names, and the occasional
//! escaped comma, which we handle with [`parse_dn`].

use ldap3_proto::proto::{
    LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry,
};

use crate::role::Role;
use crate::settings::LdapConfig;
use crate::user::User;

/// A parsed DN, as an ordered list of (attribute, value) RDN pairs. Attribute names are
/// lowercased; values keep their original case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dn {
    pub rdns: Vec<(String, String)>,
}

impl Dn {
    /// Compare two DNs for equality, case-insensitively on both sides. Used for matching
    /// an incoming bind DN or search base against our known DNs.
    pub fn equals(&self, other: &Dn) -> bool {
        if self.rdns.len() != other.rdns.len() {
            return false;
        }
        self.rdns.iter().zip(&other.rdns).all(|(a, b)| {
            a.0.eq_ignore_ascii_case(&b.0) && a.1.eq_ignore_ascii_case(&b.1)
        })
    }

    /// Check whether `self` ends with `suffix` (e.g. is `uid=alice,ou=people,<base>` under
    /// `ou=people,<base>`?).
    pub fn is_under(&self, suffix: &Dn) -> bool {
        if self.rdns.len() < suffix.rdns.len() {
            return false;
        }
        let offset = self.rdns.len() - suffix.rdns.len();
        self.rdns[offset..]
            .iter()
            .zip(&suffix.rdns)
            .all(|(a, b)| a.0.eq_ignore_ascii_case(&b.0) && a.1.eq_ignore_ascii_case(&b.1))
    }

    /// Number of RDN components above the suffix, i.e. the "depth" of `self` below it.
    pub fn depth_under(&self, suffix: &Dn) -> Option<usize> {
        if self.is_under(suffix) {
            Some(self.rdns.len() - suffix.rdns.len())
        } else {
            None
        }
    }

    /// First RDN of the DN, if any (e.g. `("uid", "alice")`).
    pub fn leaf(&self) -> Option<&(String, String)> {
        self.rdns.first()
    }
}

/// Parse an LDAP DN string into its RDN components. Supports escaped commas (`\\,`) and
/// collapses whitespace around separators. Does not support the full RFC 4514 escape
/// syntax — intentionally minimal for our MVP.
pub fn parse_dn(input: &str) -> Result<Dn, LdapResultCode> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Dn { rdns: vec![] });
    }
    let mut rdns = Vec::new();
    let mut current = String::new();
    let mut chars = trimmed.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(&next) = chars.peek() {
                    current.push(next);
                    chars.next();
                }
            }
            ',' => {
                let piece = std::mem::take(&mut current);
                rdns.push(split_rdn(&piece)?);
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        rdns.push(split_rdn(&current)?);
    }
    Ok(Dn { rdns })
}

fn split_rdn(raw: &str) -> Result<(String, String), LdapResultCode> {
    let (attr, value) = raw.split_once('=').ok_or(LdapResultCode::InvalidDNSyntax)?;
    let attr = attr.trim();
    let value = value.trim();
    if attr.is_empty() || value.is_empty() {
        return Err(LdapResultCode::InvalidDNSyntax);
    }
    Ok((attr.to_ascii_lowercase(), value.to_string()))
}

/// Produce `uid=<username>,ou=people,<base_dn>`.
pub fn user_dn(username: &str, cfg: &LdapConfig) -> String {
    format!("uid={username},{}", cfg.people_base_dn())
}

/// Produce `cn=<role_name>,ou=groups,<base_dn>`.
pub fn group_dn(role_name: &str, cfg: &LdapConfig) -> String {
    format!("cn={role_name},{}", cfg.groups_base_dn())
}

/// A resolved entry: its DN and the flat attribute map we'll match filters against.
#[derive(Debug, Clone)]
pub struct Entry {
    pub dn: String,
    pub attrs: Vec<(String, Vec<String>)>,
}

impl Entry {
    pub fn attr_values(&self, name: &str) -> Option<&Vec<String>> {
        self.attrs
            .iter()
            .find(|(a, _)| a.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    pub fn has_attr(&self, name: &str) -> bool {
        self.attr_values(name).is_some()
    }

    /// Build an LDAP search result entry, filtering attributes if the client provided a
    /// non-empty attribute list.
    pub fn to_ldap(&self, requested: &[String]) -> LdapSearchResultEntry {
        let include_all = requested.is_empty()
            || requested.iter().any(|a| a == "*" || a.eq_ignore_ascii_case("all"));
        let attributes = self
            .attrs
            .iter()
            .filter(|(a, _)| {
                include_all || requested.iter().any(|req| req.eq_ignore_ascii_case(a))
            })
            .map(|(a, vals)| LdapPartialAttribute {
                atype: a.clone(),
                vals: vals.iter().map(|v| v.as_bytes().to_vec()).collect(),
            })
            .collect();
        LdapSearchResultEntry {
            dn: self.dn.clone(),
            attributes,
        }
    }
}

/// Build a user entry including its role memberships.
pub fn build_user_entry(user: &User, role_names: &[String], cfg: &LdapConfig) -> Entry {
    let dn = user_dn(&user.username, cfg);
    let mut attrs: Vec<(String, Vec<String>)> = vec![
        (
            "objectClass".into(),
            vec!["top".into(), "person".into(), "inetOrgPerson".into()],
        ),
        ("uid".into(), vec![user.username.clone()]),
        ("cn".into(), vec![user.name.clone()]),
        ("sn".into(), vec![user.name.clone()]),
        ("displayName".into(), vec![user.name.clone()]),
        ("entryUUID".into(), vec![user.id.to_string()]),
    ];
    if let Some(ref email) = user.email {
        attrs.push(("mail".into(), vec![email.clone()]));
    }
    if !role_names.is_empty() {
        let member_of: Vec<String> = role_names
            .iter()
            .map(|r| group_dn(r, cfg))
            .collect();
        attrs.push(("memberOf".into(), member_of));
    }
    Entry { dn, attrs }
}

/// Build a group entry listing its member DNs.
pub fn build_group_entry(role: &Role, member_usernames: &[String], cfg: &LdapConfig) -> Entry {
    let dn = group_dn(&role.name, cfg);
    let mut attrs: Vec<(String, Vec<String>)> = vec![
        (
            "objectClass".into(),
            vec!["top".into(), "groupOfNames".into()],
        ),
        ("cn".into(), vec![role.name.clone()]),
    ];
    if let Some(ref desc) = role.description {
        attrs.push(("description".into(), vec![desc.clone()]));
    }
    // groupOfNames technically requires at least one member. Empty groups are rare for us,
    // but we emit a placeholder that clients typically ignore.
    let members: Vec<String> = if member_usernames.is_empty() {
        vec![format!("cn=placeholder,{}", cfg.base_dn)]
    } else {
        member_usernames.iter().map(|u| user_dn(u, cfg)).collect()
    };
    attrs.push(("member".into(), members));
    Entry { dn, attrs }
}

/// Build the Root DSE, returned for SEARCH with base="" and scope=Base.
pub fn build_root_dse(cfg: &LdapConfig) -> Entry {
    Entry {
        dn: String::new(),
        attrs: vec![
            ("objectClass".into(), vec!["top".into()]),
            ("namingContexts".into(), vec![cfg.base_dn.clone()]),
            ("supportedLDAPVersion".into(), vec!["3".into()]),
            ("vendorName".into(), vec!["Authere".into()]),
            ("vendorVersion".into(), vec![env!("CARGO_PKG_VERSION").into()]),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{DEFAULT_LDAP_BASE_DN, LdapPasswordMode};
    use uuid::Uuid;

    fn test_cfg() -> LdapConfig {
        LdapConfig {
            enabled: true,
            base_dn: DEFAULT_LDAP_BASE_DN.to_string(),
            bind_address: "0.0.0.0:3389".parse().unwrap(),
            service_password_hash: None,
            password_mode: LdapPasswordMode::default(),
        }
    }

    #[test]
    fn parse_dn_empty_is_empty_vec() {
        assert!(parse_dn("").unwrap().rdns.is_empty());
        assert!(parse_dn("   ").unwrap().rdns.is_empty());
    }

    #[test]
    fn parse_dn_simple() {
        let dn = parse_dn("uid=alice,ou=people,dc=authere,dc=local").unwrap();
        assert_eq!(
            dn.rdns,
            vec![
                ("uid".into(), "alice".into()),
                ("ou".into(), "people".into()),
                ("dc".into(), "authere".into()),
                ("dc".into(), "local".into()),
            ]
        );
    }

    #[test]
    fn parse_dn_lowercases_attributes_only() {
        let dn = parse_dn("UID=Alice,OU=People,DC=Authere,DC=Local").unwrap();
        assert_eq!(dn.rdns[0], ("uid".into(), "Alice".into()));
        assert_eq!(dn.rdns[1], ("ou".into(), "People".into()));
    }

    #[test]
    fn parse_dn_tolerates_whitespace() {
        let dn = parse_dn(" uid = alice , ou = people , dc = authere , dc = local ").unwrap();
        assert_eq!(dn.rdns.len(), 4);
        assert_eq!(dn.rdns[0], ("uid".into(), "alice".into()));
    }

    #[test]
    fn parse_dn_rejects_bad_shapes() {
        assert!(parse_dn("noequals").is_err());
        assert!(parse_dn("=empty-attr").is_err());
        assert!(parse_dn("attr=").is_err());
    }

    #[test]
    fn parse_dn_handles_escaped_comma() {
        let dn = parse_dn(r"cn=Last\, First,ou=people,dc=authere,dc=local").unwrap();
        assert_eq!(dn.rdns[0].1, "Last, First");
        assert_eq!(dn.rdns.len(), 4);
    }

    #[test]
    fn dn_equals_is_case_insensitive() {
        let a = parse_dn("uid=alice,ou=people,dc=authere,dc=local").unwrap();
        let b = parse_dn("UID=ALICE,ou=People,dc=AUTHERE,dc=local").unwrap();
        assert!(a.equals(&b));
    }

    #[test]
    fn dn_is_under_suffix() {
        let leaf = parse_dn("uid=alice,ou=people,dc=authere,dc=local").unwrap();
        let suffix = parse_dn("ou=people,dc=authere,dc=local").unwrap();
        let other = parse_dn("ou=groups,dc=authere,dc=local").unwrap();
        assert!(leaf.is_under(&suffix));
        assert!(!leaf.is_under(&other));
        assert!(leaf.is_under(&leaf));
    }

    #[test]
    fn dn_depth_under_counts_components() {
        let leaf = parse_dn("uid=alice,ou=people,dc=authere,dc=local").unwrap();
        let base = parse_dn("dc=authere,dc=local").unwrap();
        let people = parse_dn("ou=people,dc=authere,dc=local").unwrap();
        assert_eq!(leaf.depth_under(&base), Some(2));
        assert_eq!(leaf.depth_under(&people), Some(1));
        assert_eq!(people.depth_under(&leaf), None);
    }

    #[test]
    fn user_dn_format() {
        let cfg = test_cfg();
        assert_eq!(
            user_dn("alice", &cfg),
            "uid=alice,ou=people,dc=authere,dc=local"
        );
    }

    #[test]
    fn group_dn_format() {
        let cfg = test_cfg();
        assert_eq!(
            group_dn("admin", &cfg),
            "cn=admin,ou=groups,dc=authere,dc=local"
        );
    }

    #[test]
    fn build_user_entry_has_expected_attributes() {
        let cfg = test_cfg();
        let user = User {
            id: Uuid::nil(),
            username: "alice".into(),
            name: "Alice".into(),
            email: Some("alice@example.com".into()),
            active: true,
            created_at: 0,
            updated_at: 0,
        };
        let entry = build_user_entry(&user, &["admin".into(), "user".into()], &cfg);
        assert_eq!(entry.dn, "uid=alice,ou=people,dc=authere,dc=local");
        assert_eq!(entry.attr_values("uid"), Some(&vec!["alice".into()]));
        assert_eq!(entry.attr_values("cn"), Some(&vec!["Alice".into()]));
        assert_eq!(
            entry.attr_values("mail"),
            Some(&vec!["alice@example.com".into()])
        );
        let member_of = entry.attr_values("memberOf").unwrap();
        assert!(member_of.contains(&"cn=admin,ou=groups,dc=authere,dc=local".to_string()));
        assert!(member_of.contains(&"cn=user,ou=groups,dc=authere,dc=local".to_string()));
    }

    #[test]
    fn build_user_entry_omits_email_when_absent() {
        let cfg = test_cfg();
        let user = User {
            id: Uuid::nil(),
            username: "bob".into(),
            name: "Bob".into(),
            email: None,
            active: true,
            created_at: 0,
            updated_at: 0,
        };
        let entry = build_user_entry(&user, &[], &cfg);
        assert!(entry.attr_values("mail").is_none());
        assert!(entry.attr_values("memberOf").is_none());
    }

    #[test]
    fn build_group_entry_lists_members() {
        let cfg = test_cfg();
        let role = Role {
            id: Uuid::nil(),
            name: "admin".into(),
            description: Some("Admins".into()),
        };
        let entry = build_group_entry(&role, &["alice".into(), "bob".into()], &cfg);
        assert_eq!(entry.dn, "cn=admin,ou=groups,dc=authere,dc=local");
        let members = entry.attr_values("member").unwrap();
        assert_eq!(members.len(), 2);
        assert!(members.contains(&"uid=alice,ou=people,dc=authere,dc=local".to_string()));
        assert_eq!(
            entry.attr_values("description"),
            Some(&vec!["Admins".into()])
        );
    }

    #[test]
    fn build_group_entry_uses_placeholder_when_empty() {
        let cfg = test_cfg();
        let role = Role {
            id: Uuid::nil(),
            name: "empty".into(),
            description: None,
        };
        let entry = build_group_entry(&role, &[], &cfg);
        let members = entry.attr_values("member").unwrap();
        assert_eq!(members.len(), 1);
        assert!(members[0].starts_with("cn=placeholder,"));
    }

    #[test]
    fn entry_to_ldap_respects_requested_attributes() {
        let cfg = test_cfg();
        let user = User {
            id: Uuid::nil(),
            username: "alice".into(),
            name: "Alice".into(),
            email: Some("a@b.co".into()),
            active: true,
            created_at: 0,
            updated_at: 0,
        };
        let entry = build_user_entry(&user, &[], &cfg);

        let all = entry.to_ldap(&[]);
        assert!(all.attributes.len() >= 5);

        let filtered = entry.to_ldap(&["uid".into(), "mail".into()]);
        assert_eq!(filtered.attributes.len(), 2);
        let names: Vec<_> = filtered.attributes.iter().map(|a| a.atype.clone()).collect();
        assert!(names.iter().any(|n| n == "uid"));
        assert!(names.iter().any(|n| n == "mail"));
    }

    #[test]
    fn root_dse_advertises_naming_context() {
        let cfg = test_cfg();
        let dse = build_root_dse(&cfg);
        assert_eq!(dse.dn, "");
        assert_eq!(
            dse.attr_values("namingContexts"),
            Some(&vec!["dc=authere,dc=local".into()])
        );
        assert_eq!(
            dse.attr_values("supportedLDAPVersion"),
            Some(&vec!["3".into()])
        );
    }
}
