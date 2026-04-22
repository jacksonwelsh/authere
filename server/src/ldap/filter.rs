//! LDAP filter evaluation against the flat attribute map inside [`Entry`].
//!
//! The MVP only handles the subset of filters that real LDAP clients actually send at us —
//! equality, presence, substring, and boolean combinators. Greater/less/approximate/
//! extensible filters resolve to `false`; the search still succeeds (returning no entries)
//! rather than erroring, which matches common server behaviour.

use ldap3_proto::proto::{LdapFilter, LdapSubstringFilter};

use super::schema::Entry;

/// Evaluate `filter` against `entry`. All comparisons are case-insensitive, which matches
/// the LDAP default for the attributes we expose (`uid`, `cn`, `mail`, `memberOf`,
/// `objectClass`). Substring matching is also case-insensitive.
pub fn matches(entry: &Entry, filter: &LdapFilter) -> bool {
    match filter {
        LdapFilter::And(children) => children.iter().all(|c| matches(entry, c)),
        LdapFilter::Or(children) => children.iter().any(|c| matches(entry, c)),
        LdapFilter::Not(inner) => !matches(entry, inner),
        LdapFilter::Present(attr) => entry.has_attr(attr),
        LdapFilter::Equality(attr, value) => equality(entry, attr, value),
        LdapFilter::Approx(attr, value) => equality(entry, attr, value),
        LdapFilter::Substring(attr, sub) => substring(entry, attr, sub),
        LdapFilter::GreaterOrEqual(_, _)
        | LdapFilter::LessOrEqual(_, _)
        | LdapFilter::Extensible(_) => false,
    }
}

fn equality(entry: &Entry, attr: &str, value: &str) -> bool {
    match entry.attr_values(attr) {
        Some(vals) => vals.iter().any(|v| v.eq_ignore_ascii_case(value)),
        None => false,
    }
}

fn substring(entry: &Entry, attr: &str, sub: &LdapSubstringFilter) -> bool {
    let Some(vals) = entry.attr_values(attr) else {
        return false;
    };
    vals.iter().any(|v| substring_matches(v, sub))
}

fn substring_matches(value: &str, sub: &LdapSubstringFilter) -> bool {
    let lower = value.to_ascii_lowercase();
    let mut cursor = 0usize;

    if let Some(ref initial) = sub.initial {
        let needle = initial.to_ascii_lowercase();
        if !lower.starts_with(&needle) {
            return false;
        }
        cursor = needle.len();
    }

    for any in &sub.any {
        let needle = any.to_ascii_lowercase();
        match lower[cursor..].find(&needle) {
            Some(found) => cursor += found + needle.len(),
            None => return false,
        }
    }

    if let Some(ref final_) = sub.final_ {
        let needle = final_.to_ascii_lowercase();
        if !lower[cursor..].ends_with(&needle) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_entry() -> Entry {
        Entry {
            dn: "uid=alice,ou=people,dc=authere,dc=local".into(),
            attrs: vec![
                ("uid".into(), vec!["alice".into()]),
                ("cn".into(), vec!["Alice Example".into()]),
                ("mail".into(), vec!["alice@example.com".into()]),
                (
                    "memberOf".into(),
                    vec![
                        "cn=admin,ou=groups,dc=authere,dc=local".into(),
                        "cn=user,ou=groups,dc=authere,dc=local".into(),
                    ],
                ),
                (
                    "objectClass".into(),
                    vec!["top".into(), "inetOrgPerson".into()],
                ),
            ],
        }
    }

    #[test]
    fn equality_matches_case_insensitive() {
        let e = user_entry();
        assert!(matches(&e, &LdapFilter::Equality("uid".into(), "alice".into())));
        assert!(matches(&e, &LdapFilter::Equality("UID".into(), "ALICE".into())));
    }

    #[test]
    fn equality_fails_on_wrong_value_or_missing_attr() {
        let e = user_entry();
        assert!(!matches(&e, &LdapFilter::Equality("uid".into(), "bob".into())));
        assert!(!matches(&e, &LdapFilter::Equality("missing".into(), "x".into())));
    }

    #[test]
    fn presence_filter_checks_for_attribute() {
        let e = user_entry();
        assert!(matches(&e, &LdapFilter::Present("mail".into())));
        assert!(!matches(&e, &LdapFilter::Present("foobar".into())));
    }

    #[test]
    fn member_of_equality_matches_any_value() {
        let e = user_entry();
        assert!(matches(
            &e,
            &LdapFilter::Equality(
                "memberOf".into(),
                "cn=admin,ou=groups,dc=authere,dc=local".into()
            )
        ));
        assert!(!matches(
            &e,
            &LdapFilter::Equality(
                "memberOf".into(),
                "cn=other,ou=groups,dc=authere,dc=local".into()
            )
        ));
    }

    #[test]
    fn and_or_not_combine() {
        let e = user_entry();
        let admin = LdapFilter::Equality(
            "memberOf".into(),
            "cn=admin,ou=groups,dc=authere,dc=local".into(),
        );
        let has_uid = LdapFilter::Present("uid".into());
        let missing = LdapFilter::Present("foobar".into());

        assert!(matches(&e, &LdapFilter::And(vec![admin.clone(), has_uid.clone()])));
        assert!(!matches(&e, &LdapFilter::And(vec![admin.clone(), missing.clone()])));
        assert!(matches(&e, &LdapFilter::Or(vec![missing.clone(), admin.clone()])));
        assert!(matches(&e, &LdapFilter::Not(Box::new(missing))));
    }

    #[test]
    fn substring_initial_middle_final() {
        let e = user_entry();
        let filter = LdapFilter::Substring(
            "mail".into(),
            LdapSubstringFilter {
                initial: Some("alice".into()),
                any: vec!["example".into()],
                final_: Some(".com".into()),
            },
        );
        assert!(matches(&e, &filter));
    }

    #[test]
    fn substring_only_initial() {
        let e = user_entry();
        assert!(matches(
            &e,
            &LdapFilter::Substring(
                "cn".into(),
                LdapSubstringFilter {
                    initial: Some("Alice".into()),
                    any: vec![],
                    final_: None,
                }
            )
        ));
    }

    #[test]
    fn substring_only_final() {
        let e = user_entry();
        assert!(matches(
            &e,
            &LdapFilter::Substring(
                "mail".into(),
                LdapSubstringFilter {
                    initial: None,
                    any: vec![],
                    final_: Some("example.com".into()),
                }
            )
        ));
    }

    #[test]
    fn substring_fails_when_order_wrong() {
        let e = user_entry();
        let filter = LdapFilter::Substring(
            "mail".into(),
            LdapSubstringFilter {
                initial: Some(".com".into()),
                any: vec![],
                final_: Some("alice".into()),
            },
        );
        assert!(!matches(&e, &filter));
    }

    #[test]
    fn substring_handles_any_sequence() {
        let e = Entry {
            dn: "uid=bob,...".into(),
            attrs: vec![("cn".into(), vec!["info-tech-test".into()])],
        };
        let filter = LdapFilter::Substring(
            "cn".into(),
            LdapSubstringFilter {
                initial: Some("info".into()),
                any: vec!["tech".into()],
                final_: Some("test".into()),
            },
        );
        assert!(matches(&e, &filter));
    }

    #[test]
    fn unsupported_filters_resolve_false() {
        let e = user_entry();
        assert!(!matches(
            &e,
            &LdapFilter::GreaterOrEqual("uid".into(), "aaa".into())
        ));
        assert!(!matches(
            &e,
            &LdapFilter::LessOrEqual("uid".into(), "zzz".into())
        ));
    }
}
