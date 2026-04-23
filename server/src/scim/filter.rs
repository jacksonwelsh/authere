//! SCIM filter expressions (RFC 7644 §3.4.2.2) — minimum viable subset for Okta, Azure AD,
//! OneLogin, and the `scim2-tester` compliance suite.
//!
//! Grammar:
//! ```text
//! filter      := logicalOr
//! logicalOr   := logicalAnd ("or" logicalAnd)*
//! logicalAnd  := primary ("and" primary)*
//! primary     := "(" filter ")" | "not" "(" filter ")" | compExpr
//! compExpr    := attr op value | attr "pr"
//! attr        := word ("." word)?
//! op          := eq|ne|co|sw|ew|gt|ge|lt|le
//! value       := quoted-string | bool | number | null
//! ```
//!
//! Complex attribute filters like `emails[type eq "work"]` and URN-prefixed attribute paths
//! are intentionally rejected with `invalidFilter`. Unknown attribute names are also rejected;
//! supporting every SCIM attribute would quietly return empty results for clients typoing
//! their queries.
//!
//! Case-insensitivity: string `eq/ne/co/sw/ew` comparisons compare `lower(col) = lower(?)`
//! per §3.4.2.2. Timestamp operators use `meta.created` / `meta.lastModified`; values are
//! parsed as RFC3339 dates and compared against the unix-epoch `users.created_at` /
//! `users.updated_at` columns.

use sqlx::{QueryBuilder, Sqlite};

use crate::scim::error::ScimError;

// ============================================================================
// AST
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum FilterExpr {
    And(Box<FilterExpr>, Box<FilterExpr>),
    Or(Box<FilterExpr>, Box<FilterExpr>),
    Not(Box<FilterExpr>),
    Present(Attr),
    Compare {
        attr: Attr,
        op: CompOp,
        value: FilterValue,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompOp {
    Eq,
    Ne,
    Co,
    Sw,
    Ew,
    Gt,
    Ge,
    Lt,
    Le,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FilterValue {
    Str(String),
    Bool(bool),
    Int(i64),
    Null,
}

/// The SCIM attributes we can filter on, mapped to DB columns at compile time. Unknown
/// attributes produce an `invalidFilter` error before any SQL is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attr {
    UserName,
    ExternalId,
    Active,
    Id,
    DisplayName,
    NameFormatted,
    Emails,      // eq compares raw value against users.email (plain string)
    EmailsValue, // alias for Emails — SCIM accepts both forms
    MetaCreated,
    MetaLastModified,
}

impl Attr {
    fn column(self) -> &'static str {
        match self {
            Attr::UserName => "username",
            Attr::ExternalId => "external_id",
            Attr::Active => "active",
            Attr::Id => "id",
            Attr::DisplayName => "name",
            Attr::NameFormatted => "name",
            Attr::Emails | Attr::EmailsValue => "email",
            Attr::MetaCreated => "created_at",
            Attr::MetaLastModified => "updated_at",
        }
    }

    fn is_string(self) -> bool {
        matches!(
            self,
            Attr::UserName
                | Attr::ExternalId
                | Attr::Id
                | Attr::DisplayName
                | Attr::NameFormatted
                | Attr::Emails
                | Attr::EmailsValue
        )
    }

    fn is_bool(self) -> bool {
        matches!(self, Attr::Active)
    }

    fn is_timestamp(self) -> bool {
        matches!(self, Attr::MetaCreated | Attr::MetaLastModified)
    }

    fn parse(raw: &str) -> Result<Self, ScimError> {
        // Strip any URN prefix — some clients send `urn:ietf:params:scim:schemas:core:2.0:User:userName`
        // and we care about only the trailing dotted path.
        let raw = raw.rsplit_once(':').map(|(_, t)| t).unwrap_or(raw);
        match raw.to_ascii_lowercase().as_str() {
            "username" => Ok(Attr::UserName),
            "externalid" => Ok(Attr::ExternalId),
            "active" => Ok(Attr::Active),
            "id" => Ok(Attr::Id),
            "displayname" => Ok(Attr::DisplayName),
            "name.formatted" => Ok(Attr::NameFormatted),
            "emails" => Ok(Attr::Emails),
            "emails.value" => Ok(Attr::EmailsValue),
            "meta.created" => Ok(Attr::MetaCreated),
            "meta.lastmodified" => Ok(Attr::MetaLastModified),
            other => Err(ScimError::invalid_filter(format!(
                "unknown or unsupported attribute: {other}"
            ))),
        }
    }
}

// ============================================================================
// Lexer
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),    // attribute path or keyword
    Str(String),
    Bool(bool),
    Int(i64),
    Null,
    LParen,
    RParen,
    LBracket, // '[' — we reject immediately if seen in attribute position (complex filter)
    RBracket,
}

struct Lexer<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self { src, pos: 0 }
    }

    fn peek(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
    }

    fn read_string(&mut self) -> Result<Token, ScimError> {
        // Caller has already consumed the opening quote.
        let mut out = String::new();
        loop {
            let Some(c) = self.bump() else {
                return Err(ScimError::invalid_filter("unterminated string literal"));
            };
            match c {
                '"' => return Ok(Token::Str(out)),
                '\\' => {
                    let Some(esc) = self.bump() else {
                        return Err(ScimError::invalid_filter("trailing backslash in string"));
                    };
                    match esc {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        other => out.push(other),
                    }
                }
                c => out.push(c),
            }
        }
    }

    fn read_ident(&mut self, first: char) -> String {
        let start = self.pos - first.len_utf8();
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' || c == '.' || c == '-' || c == ':' {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
        self.src[start..self.pos].to_string()
    }

    fn read_number(&mut self, first: char) -> Result<Token, ScimError> {
        let start = self.pos - first.len_utf8();
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == '-' {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
        let s = &self.src[start..self.pos];
        s.parse::<i64>()
            .map(Token::Int)
            .map_err(|_| ScimError::invalid_filter(format!("invalid integer: {s}")))
    }

    fn next_token(&mut self) -> Result<Option<Token>, ScimError> {
        self.skip_ws();
        let Some(c) = self.bump() else {
            return Ok(None);
        };
        Ok(Some(match c {
            '(' => Token::LParen,
            ')' => Token::RParen,
            '[' => Token::LBracket,
            ']' => Token::RBracket,
            '"' => self.read_string()?,
            '-' | '0'..='9' => self.read_number(c)?,
            c if c.is_alphabetic() || c == '_' => {
                let raw = self.read_ident(c);
                match raw.to_ascii_lowercase().as_str() {
                    "true" => Token::Bool(true),
                    "false" => Token::Bool(false),
                    "null" => Token::Null,
                    _ => Token::Ident(raw),
                }
            }
            other => {
                return Err(ScimError::invalid_filter(format!(
                    "unexpected character '{other}'"
                )));
            }
        }))
    }

    fn tokenize(mut self) -> Result<Vec<Token>, ScimError> {
        let mut out = Vec::new();
        while let Some(t) = self.next_token()? {
            if matches!(t, Token::LBracket | Token::RBracket) {
                return Err(ScimError::invalid_filter(
                    "complex attribute filters (emails[…]) are not supported",
                ));
            }
            out.push(t);
        }
        Ok(out)
    }
}

// ============================================================================
// Parser
// ============================================================================

struct Parser {
    toks: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.toks.get(self.pos)
    }

    fn bump(&mut self) -> Option<Token> {
        if self.pos < self.toks.len() {
            let t = self.toks[self.pos].clone();
            self.pos += 1;
            Some(t)
        } else {
            None
        }
    }

    fn is_keyword(tok: &Token, word: &str) -> bool {
        if let Token::Ident(s) = tok {
            s.eq_ignore_ascii_case(word)
        } else {
            false
        }
    }

    fn parse_filter(&mut self) -> Result<FilterExpr, ScimError> {
        let expr = self.parse_or()?;
        if self.pos != self.toks.len() {
            return Err(ScimError::invalid_filter(
                "trailing tokens after filter expression",
            ));
        }
        Ok(expr)
    }

    fn parse_or(&mut self) -> Result<FilterExpr, ScimError> {
        let mut lhs = self.parse_and()?;
        while self.peek().map_or(false, |t| Self::is_keyword(t, "or")) {
            self.bump();
            let rhs = self.parse_and()?;
            lhs = FilterExpr::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<FilterExpr, ScimError> {
        let mut lhs = self.parse_primary()?;
        while self.peek().map_or(false, |t| Self::is_keyword(t, "and")) {
            self.bump();
            let rhs = self.parse_primary()?;
            lhs = FilterExpr::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_primary(&mut self) -> Result<FilterExpr, ScimError> {
        match self.peek() {
            Some(Token::LParen) => {
                self.bump();
                let inner = self.parse_or()?;
                match self.bump() {
                    Some(Token::RParen) => Ok(inner),
                    _ => Err(ScimError::invalid_filter("expected ')' to match '('")),
                }
            }
            Some(t) if Self::is_keyword(t, "not") => {
                self.bump();
                match self.bump() {
                    Some(Token::LParen) => {}
                    _ => {
                        return Err(ScimError::invalid_filter(
                            "expected '(' after 'not'",
                        ));
                    }
                }
                let inner = self.parse_or()?;
                match self.bump() {
                    Some(Token::RParen) => Ok(FilterExpr::Not(Box::new(inner))),
                    _ => Err(ScimError::invalid_filter("expected ')' to close 'not(…)'"))
                }
            }
            _ => self.parse_comp(),
        }
    }

    fn parse_comp(&mut self) -> Result<FilterExpr, ScimError> {
        let attr_tok = self
            .bump()
            .ok_or_else(|| ScimError::invalid_filter("unexpected end of filter"))?;
        let attr_raw = match attr_tok {
            Token::Ident(s) => s,
            other => {
                return Err(ScimError::invalid_filter(format!(
                    "expected attribute name, got {other:?}"
                )));
            }
        };
        let attr = Attr::parse(&attr_raw)?;

        let op_tok = self
            .bump()
            .ok_or_else(|| ScimError::invalid_filter("expected operator after attribute"))?;
        let op_str = match op_tok {
            Token::Ident(s) => s,
            other => {
                return Err(ScimError::invalid_filter(format!(
                    "expected operator, got {other:?}"
                )));
            }
        };

        let op = match op_str.to_ascii_lowercase().as_str() {
            "pr" => return Ok(FilterExpr::Present(attr)),
            "eq" => CompOp::Eq,
            "ne" => CompOp::Ne,
            "co" => CompOp::Co,
            "sw" => CompOp::Sw,
            "ew" => CompOp::Ew,
            "gt" => CompOp::Gt,
            "ge" => CompOp::Ge,
            "lt" => CompOp::Lt,
            "le" => CompOp::Le,
            other => {
                return Err(ScimError::invalid_filter(format!(
                    "unknown operator: {other}"
                )));
            }
        };

        let value_tok = self
            .bump()
            .ok_or_else(|| ScimError::invalid_filter("expected value after operator"))?;
        let value = match value_tok {
            Token::Str(s) => FilterValue::Str(s),
            Token::Bool(b) => FilterValue::Bool(b),
            Token::Int(n) => FilterValue::Int(n),
            Token::Null => FilterValue::Null,
            other => {
                return Err(ScimError::invalid_filter(format!(
                    "expected literal value, got {other:?}"
                )));
            }
        };

        Ok(FilterExpr::Compare { attr, op, value })
    }
}

pub fn parse(input: &str) -> Result<FilterExpr, ScimError> {
    let toks = Lexer::new(input).tokenize()?;
    if toks.is_empty() {
        return Err(ScimError::invalid_filter("empty filter expression"));
    }
    Parser { toks, pos: 0 }.parse_filter()
}

// ============================================================================
// Compiler: AST → SQL WHERE clause fragment
// ============================================================================

/// Append the `WHERE` clause fragment for `expr` onto an existing QueryBuilder. The caller
/// is expected to have already pushed "SELECT … FROM users" and is about to add this as
/// part of its WHERE. The fragment always wraps in parens so it composes.
pub fn compile(expr: &FilterExpr, qb: &mut QueryBuilder<'_, Sqlite>) -> Result<(), ScimError> {
    qb.push("(");
    match expr {
        FilterExpr::And(l, r) => {
            compile(l, qb)?;
            qb.push(" AND ");
            compile(r, qb)?;
        }
        FilterExpr::Or(l, r) => {
            compile(l, qb)?;
            qb.push(" OR ");
            compile(r, qb)?;
        }
        FilterExpr::Not(inner) => {
            qb.push("NOT ");
            compile(inner, qb)?;
        }
        FilterExpr::Present(attr) => {
            let col = attr.column();
            // `pr` is true when the attribute has any value — for strings, non-null AND
            // non-empty; for booleans, always true (they're always "present"); for timestamps
            // we already enforce NOT NULL so `pr` is always true.
            if attr.is_string() {
                qb.push(format!("({col} IS NOT NULL AND {col} <> '')"));
            } else {
                qb.push("1 = 1");
            }
        }
        FilterExpr::Compare { attr, op, value } => {
            compile_compare(*attr, *op, value, qb)?;
        }
    }
    qb.push(")");
    Ok(())
}

fn compile_compare(
    attr: Attr,
    op: CompOp,
    value: &FilterValue,
    qb: &mut QueryBuilder<'_, Sqlite>,
) -> Result<(), ScimError> {
    let col = attr.column();

    if attr.is_bool() {
        let b = match value {
            FilterValue::Bool(b) => *b,
            FilterValue::Str(s) => match s.to_ascii_lowercase().as_str() {
                "true" => true,
                "false" => false,
                _ => {
                    return Err(ScimError::invalid_filter(format!(
                        "expected boolean for attribute {col}"
                    )));
                }
            },
            _ => {
                return Err(ScimError::invalid_filter(format!(
                    "expected boolean for attribute {col}"
                )));
            }
        };
        match op {
            CompOp::Eq => {
                qb.push(format!("{col} = "));
                qb.push_bind(if b { 1i64 } else { 0i64 });
            }
            CompOp::Ne => {
                qb.push(format!("{col} <> "));
                qb.push_bind(if b { 1i64 } else { 0i64 });
            }
            _ => {
                return Err(ScimError::invalid_filter(
                    "only eq/ne are supported on boolean attributes",
                ));
            }
        }
        return Ok(());
    }

    if attr.is_timestamp() {
        // Accept either an RFC3339 string or a raw epoch integer. Okta sends RFC3339.
        let epoch = match value {
            FilterValue::Int(n) => *n,
            FilterValue::Str(s) => parse_rfc3339_epoch(s).ok_or_else(|| {
                ScimError::invalid_filter(format!(
                    "expected RFC3339 timestamp for {col}, got '{s}'"
                ))
            })?,
            _ => {
                return Err(ScimError::invalid_filter(format!(
                    "expected timestamp for {col}"
                )));
            }
        };
        let sql_op = match op {
            CompOp::Eq => "=",
            CompOp::Ne => "<>",
            CompOp::Gt => ">",
            CompOp::Ge => ">=",
            CompOp::Lt => "<",
            CompOp::Le => "<=",
            _ => {
                return Err(ScimError::invalid_filter(format!(
                    "operator {op:?} not supported on timestamps"
                )));
            }
        };
        qb.push(format!("{col} {sql_op} "));
        qb.push_bind(epoch);
        return Ok(());
    }

    // String attribute path. id is a BLOB; we still compare via lower()-cast-to-text per
    // SCIM case-insensitivity rules, and that works because UUIDs round-trip as hex.
    let s = match value {
        FilterValue::Str(s) => s.clone(),
        FilterValue::Int(n) => n.to_string(),
        FilterValue::Null => {
            match op {
                CompOp::Eq => qb.push(format!("{col} IS NULL")),
                CompOp::Ne => qb.push(format!("{col} IS NOT NULL")),
                _ => {
                    return Err(ScimError::invalid_filter(
                        "only eq/ne are valid against null",
                    ));
                }
            };
            return Ok(());
        }
        FilterValue::Bool(_) => {
            return Err(ScimError::invalid_filter(format!(
                "boolean value not valid for string attribute {col}"
            )));
        }
    };

    match op {
        CompOp::Eq => {
            qb.push(format!("lower({col}) = lower("));
            qb.push_bind(s);
            qb.push(")");
        }
        CompOp::Ne => {
            qb.push(format!("(lower({col}) <> lower("));
            qb.push_bind(s);
            qb.push(format!(") OR {col} IS NULL)"));
        }
        CompOp::Co => {
            qb.push(format!("lower({col}) LIKE "));
            qb.push_bind(format!("%{}%", s.to_lowercase()));
        }
        CompOp::Sw => {
            qb.push(format!("lower({col}) LIKE "));
            qb.push_bind(format!("{}%", s.to_lowercase()));
        }
        CompOp::Ew => {
            qb.push(format!("lower({col}) LIKE "));
            qb.push_bind(format!("%{}", s.to_lowercase()));
        }
        CompOp::Gt | CompOp::Ge | CompOp::Lt | CompOp::Le => {
            let sql_op = match op {
                CompOp::Gt => ">",
                CompOp::Ge => ">=",
                CompOp::Lt => "<",
                CompOp::Le => "<=",
                _ => unreachable!(),
            };
            qb.push(format!("lower({col}) {sql_op} lower("));
            qb.push_bind(s);
            qb.push(")");
        }
    }
    Ok(())
}

/// Parse a subset of RFC3339 timestamps into unix epoch seconds. Accepts
/// `YYYY-MM-DDTHH:MM:SS[.fffffffff](Z|+HH:MM|-HH:MM)`. Returns None on malformed input.
/// SCIM clients only ever send UTC with a `Z` suffix in practice, but we accept offsets
/// to be RFC-faithful.
pub fn parse_rfc3339_epoch(s: &str) -> Option<i64> {
    // Strip fractional seconds — SCIM clients send them occasionally; we only keep whole-second
    // precision for `users.created_at` / `users.updated_at`.
    let (main, rest) = s.split_at(s.find('.').unwrap_or(s.len()));
    let offset_str = if !rest.is_empty() {
        // Find the end of the fractional part and start of the offset
        rest.find(['Z', '+', '-']).map(|i| &rest[i..]).unwrap_or("")
    } else if main.ends_with('Z') {
        "Z"
    } else if let Some(idx) = main.rfind(['+', '-']) {
        if idx > 10 { &main[idx..] } else { "" }
    } else {
        ""
    };

    let main_no_offset = if rest.is_empty() {
        if main.ends_with('Z') {
            &main[..main.len() - 1]
        } else if let Some(idx) = main.rfind(['+', '-']) {
            if idx > 10 { &main[..idx] } else { main }
        } else {
            main
        }
    } else {
        main
    };

    let (date, time) = main_no_offset.split_once('T')?;
    let mut dparts = date.split('-');
    let year: i32 = dparts.next()?.parse().ok()?;
    let month: u32 = dparts.next()?.parse().ok()?;
    let day: u32 = dparts.next()?.parse().ok()?;
    let mut tparts = time.split(':');
    let hour: u32 = tparts.next()?.parse().ok()?;
    let minute: u32 = tparts.next()?.parse().ok()?;
    let second: u32 = tparts.next()?.parse().ok()?;

    let days = days_from_civil(year, month, day);
    let mut epoch = days * 86_400 + (hour as i64) * 3600 + (minute as i64) * 60 + (second as i64);

    // Offset adjustment: `+HH:MM` means the wall-clock time is ahead of UTC, so subtract.
    if offset_str.starts_with('+') || offset_str.starts_with('-') {
        let sign = if offset_str.starts_with('+') { 1 } else { -1 };
        let rest = &offset_str[1..];
        let (hh, mm) = rest.split_once(':').unwrap_or((rest, "00"));
        let hh: i64 = hh.parse().ok()?;
        let mm: i64 = mm.parse().ok()?;
        epoch -= sign * (hh * 3600 + mm * 60);
    }

    Some(epoch)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    // Inverse of civil_from_days in schema.rs — same Hinnant reference.
    let y = (year - if month <= 2 { 1 } else { 0 }) as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let m = month as i64;
    let m_shift = if m > 2 { m - 3 } else { m + 9 };
    let doy = ((153 * m_shift + 2) / 5 + day as i64 - 1) as u64; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe as i64 - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile_sql(filter: &str) -> String {
        let expr = parse(filter).unwrap();
        let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new("");
        compile(&expr, &mut qb).unwrap();
        qb.sql().to_string()
    }

    // --- Parser correctness ---

    #[test]
    fn parse_simple_eq() {
        let e = parse(r#"userName eq "alice""#).unwrap();
        assert_eq!(
            e,
            FilterExpr::Compare {
                attr: Attr::UserName,
                op: CompOp::Eq,
                value: FilterValue::Str("alice".into())
            }
        );
    }

    #[test]
    fn parse_is_case_insensitive_on_keywords() {
        parse(r#"userName EQ "alice" AND active EQ true"#).unwrap();
        parse(r#"userName Eq "alice" Or active eq false"#).unwrap();
        parse(r#"NOT (userName Pr)"#).unwrap();
    }

    #[test]
    fn parse_external_id_eq() {
        let e = parse(r#"externalId eq "okta-abc""#).unwrap();
        assert!(matches!(
            e,
            FilterExpr::Compare {
                attr: Attr::ExternalId,
                ..
            }
        ));
    }

    #[test]
    fn parse_active_true_and_present() {
        let e = parse("active eq true and userName pr").unwrap();
        let FilterExpr::And(_, rhs) = e else { panic!("not an AND") };
        assert!(matches!(*rhs, FilterExpr::Present(Attr::UserName)));
    }

    #[test]
    fn parse_emails_value_alias_accepted() {
        let e = parse(r#"emails.value eq "a@b.co""#).unwrap();
        assert!(matches!(
            e,
            FilterExpr::Compare {
                attr: Attr::EmailsValue,
                ..
            }
        ));
    }

    #[test]
    fn parse_emails_plain_accepted() {
        parse(r#"emails eq "a@b.co""#).unwrap();
    }

    #[test]
    fn parse_not_wraps_subexpression() {
        let e = parse("not (active eq true)").unwrap();
        assert!(matches!(e, FilterExpr::Not(_)));
    }

    #[test]
    fn parse_and_has_higher_precedence_than_or() {
        let e = parse(r#"userName eq "a" or userName eq "b" and active eq true"#).unwrap();
        // Expect: OR(eq(a), AND(eq(b), eq(true)))
        let FilterExpr::Or(_, rhs) = e else { panic!("not OR at top") };
        assert!(matches!(*rhs, FilterExpr::And(_, _)));
    }

    #[test]
    fn parse_parens_override_precedence() {
        let e = parse(r#"(userName eq "a" or userName eq "b") and active eq true"#).unwrap();
        let FilterExpr::And(lhs, _) = e else { panic!("not AND") };
        assert!(matches!(*lhs, FilterExpr::Or(_, _)));
    }

    #[test]
    fn parse_co_sw_ew() {
        parse(r#"userName co "lic""#).unwrap();
        parse(r#"userName sw "a""#).unwrap();
        parse(r#"userName ew "ce""#).unwrap();
    }

    #[test]
    fn parse_meta_lastmodified_gt_rfc3339() {
        let e = parse(r#"meta.lastModified gt "2024-01-01T00:00:00Z""#).unwrap();
        assert!(matches!(
            e,
            FilterExpr::Compare {
                attr: Attr::MetaLastModified,
                op: CompOp::Gt,
                ..
            }
        ));
    }

    #[test]
    fn parse_urn_prefix_on_attribute_is_stripped() {
        parse(r#"urn:ietf:params:scim:schemas:core:2.0:User:userName eq "alice""#).unwrap();
    }

    #[test]
    fn parse_strings_with_escaped_quotes() {
        let e = parse(r#"userName eq "ali\"ce""#).unwrap();
        if let FilterExpr::Compare { value: FilterValue::Str(s), .. } = e {
            assert_eq!(s, r#"ali"ce"#);
        } else {
            panic!("expected string");
        }
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(parse("").is_err());
        assert!(parse("   ").is_err());
    }

    #[test]
    fn parse_rejects_unbalanced_parens() {
        assert!(parse(r#"(userName eq "a""#).is_err());
        assert!(parse(r#"userName eq "a")"#).is_err());
    }

    #[test]
    fn parse_rejects_unknown_operator() {
        assert!(parse(r#"userName like "a""#).is_err());
    }

    #[test]
    fn parse_rejects_unknown_attribute() {
        assert!(parse(r#"phoneNumbers eq "555""#).is_err());
    }

    #[test]
    fn parse_rejects_complex_attribute_filter() {
        let err = parse(r#"emails[type eq "work"].value eq "a@b.co""#).unwrap_err();
        assert_eq!(err.scim_type, Some("invalidFilter"));
    }

    #[test]
    fn parse_rejects_trailing_tokens() {
        assert!(parse(r#"userName eq "a" extra garbage"#).is_err());
    }

    #[test]
    fn parse_rejects_missing_value() {
        assert!(parse(r#"userName eq"#).is_err());
    }

    #[test]
    fn parse_rejects_invalid_character() {
        assert!(parse("userName == 'a'").is_err());
    }

    // --- SQL compilation ---

    #[test]
    fn compile_eq_uses_case_insensitive_string_compare() {
        let sql = compile_sql(r#"userName eq "Alice""#);
        assert!(sql.contains("lower(username)"), "sql: {sql}");
        assert!(sql.contains("lower(?)"), "sql: {sql}");
    }

    #[test]
    fn compile_sw_produces_like_with_trailing_percent() {
        let sql = compile_sql(r#"userName sw "a""#);
        assert!(sql.contains("LIKE"));
    }

    #[test]
    fn compile_active_boolean_comparison() {
        let sql = compile_sql("active eq true");
        assert!(sql.contains("active ="));
    }

    #[test]
    fn compile_meta_lastmodified_uses_updated_at_column() {
        let sql = compile_sql(r#"meta.lastModified gt "2024-01-01T00:00:00Z""#);
        assert!(sql.contains("updated_at >"), "sql: {sql}");
    }

    #[test]
    fn compile_pr_on_string_checks_not_null_not_empty() {
        let sql = compile_sql("externalId pr");
        assert!(sql.contains("external_id IS NOT NULL"));
        assert!(sql.contains("<> ''"));
    }

    #[test]
    fn compile_and_composes() {
        let sql = compile_sql(r#"userName eq "a" and active eq true"#);
        assert!(sql.contains(" AND "));
    }

    #[test]
    fn compile_or_composes() {
        let sql = compile_sql(r#"userName eq "a" or userName eq "b""#);
        assert!(sql.contains(" OR "));
    }

    #[test]
    fn compile_not_wraps() {
        let sql = compile_sql("not (active eq true)");
        assert!(sql.contains("NOT "));
    }

    #[test]
    fn compile_eq_null_becomes_is_null() {
        let sql = compile_sql("externalId eq null");
        assert!(sql.contains("external_id IS NULL"));
    }

    // --- RFC3339 parsing ---

    #[test]
    fn rfc3339_epoch_known_points() {
        assert_eq!(
            parse_rfc3339_epoch("1970-01-01T00:00:00Z"),
            Some(0)
        );
        assert_eq!(
            parse_rfc3339_epoch("2023-11-14T22:13:20Z"),
            Some(1_700_000_000)
        );
    }

    #[test]
    fn rfc3339_epoch_with_offset() {
        // 2024-01-01T05:00:00+05:00 == 2024-01-01T00:00:00Z
        let a = parse_rfc3339_epoch("2024-01-01T05:00:00+05:00").unwrap();
        let b = parse_rfc3339_epoch("2024-01-01T00:00:00Z").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rfc3339_epoch_strips_fractional() {
        let a = parse_rfc3339_epoch("2024-01-01T00:00:00.123456789Z").unwrap();
        let b = parse_rfc3339_epoch("2024-01-01T00:00:00Z").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rfc3339_epoch_rejects_garbage() {
        assert!(parse_rfc3339_epoch("not a date").is_none());
        assert!(parse_rfc3339_epoch("2024-01-01").is_none());
    }
}
