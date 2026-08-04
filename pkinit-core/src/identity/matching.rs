use crate::error::{PkinitError, asn1_err};
use crate::san;

#[derive(Debug)]
pub enum MatchRule {
    Subject(String),
    Issuer(String),
    San(String),
    Eku(Vec<u32>),
    Ku(u16),
    And(Vec<MatchRule>),
    Or(Vec<MatchRule>),
}

pub struct CertMatcher {
    rule: MatchRule,
}

impl CertMatcher {
    pub fn parse(rule_str: &str) -> Result<Self, PkinitError> {
        let rule = parse_or(rule_str.trim())?;
        Ok(CertMatcher { rule })
    }

    pub fn matches(&self, cert_der: &[u8]) -> Result<bool, PkinitError> {
        evaluate(&self.rule, cert_der)
    }
}

fn parse_or(input: &str) -> Result<MatchRule, PkinitError> {
    let parts = split_top_level(input, "||");
    if parts.len() == 1 {
        return parse_and(parts[0]);
    }
    let rules: Result<Vec<_>, _> = parts.iter().map(|p| parse_and(p)).collect();
    Ok(MatchRule::Or(rules?))
}

fn parse_and(input: &str) -> Result<MatchRule, PkinitError> {
    let parts = split_top_level(input, "&&");
    if parts.len() == 1 {
        return parse_leaf(parts[0]);
    }
    let rules: Result<Vec<_>, _> = parts.iter().map(|p| parse_leaf(p)).collect();
    Ok(MatchRule::And(rules?))
}

fn split_top_level<'a>(input: &'a str, sep: &str) -> Vec<&'a str> {
    let mut parts = Vec::new();
    let mut depth = 0u32;
    let mut last = 0;
    let sep_bytes = sep.as_bytes();
    let input_bytes = input.as_bytes();

    let mut i = 0;
    while i < input_bytes.len() {
        if input_bytes[i] == b'<' {
            depth += 1;
        } else if input_bytes[i] == b'>' {
            depth = depth.saturating_sub(1);
        }
        if depth == 0
            && i + sep_bytes.len() <= input_bytes.len()
            && &input_bytes[i..i + sep_bytes.len()] == sep_bytes
        {
            parts.push(&input[last..i]);
            last = i + sep_bytes.len();
            i = last;
            continue;
        }
        i += 1;
    }
    parts.push(&input[last..]);
    parts
}

fn parse_leaf(input: &str) -> Result<MatchRule, PkinitError> {
    let input = input.trim();
    if !input.starts_with('<') {
        return Err(PkinitError::Config(format!(
            "match rule must start with <TAG>: {input}"
        )));
    }
    let close = input
        .find('>')
        .ok_or_else(|| PkinitError::Config(format!("match rule missing closing >: {input}")))?;
    let tag = &input[1..close];
    let value = &input[close + 1..];

    match tag {
        "SUBJECT" => Ok(MatchRule::Subject(value.to_string())),
        "ISSUER" => Ok(MatchRule::Issuer(value.to_string())),
        "SAN" => Ok(MatchRule::San(value.to_string())),
        "EKU" => {
            let arcs: Result<Vec<u32>, _> = value.split('.').map(|s| s.parse::<u32>()).collect();
            let arcs =
                arcs.map_err(|e| PkinitError::Config(format!("invalid EKU OID {value}: {e}")))?;
            Ok(MatchRule::Eku(arcs))
        }
        "KU" => {
            let bits = u16::from_str_radix(value, 16)
                .map_err(|e| PkinitError::Config(format!("invalid KU hex {value}: {e}")))?;
            Ok(MatchRule::Ku(bits))
        }
        _ => Err(PkinitError::Config(format!(
            "unknown match rule tag: {tag}"
        ))),
    }
}

fn evaluate(rule: &MatchRule, cert_der: &[u8]) -> Result<bool, PkinitError> {
    match rule {
        MatchRule::Subject(pattern) => {
            let dn = extract_subject_dn(cert_der)?;
            Ok(simple_match(&dn, pattern))
        }
        MatchRule::Issuer(pattern) => {
            let dn = extract_issuer_dn(cert_der)?;
            Ok(simple_match(&dn, pattern))
        }
        MatchRule::San(pattern) => {
            let mut all_sans = san::extract_pkinit_sans(cert_der)?;
            all_sans.extend(san::extract_upn_sans(cert_der)?);
            all_sans.extend(san::extract_dns_names(cert_der)?);
            Ok(all_sans.iter().any(|s| simple_match(s, pattern)))
        }
        MatchRule::Eku(oid) => {
            let ekus = san::extract_eku_oids(cert_der)?;
            Ok(ekus.iter().any(|e| e.as_slice() == oid.as_slice()))
        }
        MatchRule::Ku(bits) => {
            let ku = san::extract_key_usage(cert_der)?;
            Ok(ku & bits == *bits)
        }
        MatchRule::And(rules) => {
            for r in rules {
                if !evaluate(r, cert_der)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        MatchRule::Or(rules) => {
            for r in rules {
                if evaluate(r, cert_der)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

fn extract_subject_dn(cert_der: &[u8]) -> Result<String, PkinitError> {
    let cert: synta_certificate::Certificate<'_> =
        synta::Decoder::new(cert_der, synta::Encoding::Der)
            .decode()
            .map_err(asn1_err("decoding cert"))?;
    Ok(synta_certificate::format_dn(
        cert.tbs_certificate.subject.as_bytes(),
    ))
}

fn extract_issuer_dn(cert_der: &[u8]) -> Result<String, PkinitError> {
    let cert: synta_certificate::Certificate<'_> =
        synta::Decoder::new(cert_der, synta::Encoding::Der)
            .decode()
            .map_err(asn1_err("decoding cert"))?;
    Ok(synta_certificate::format_dn(
        cert.tbs_certificate.issuer.as_bytes(),
    ))
}

/// Simple substring match. If the pattern contains `*`, treat it as a
/// glob where `*` matches any sequence of characters.
fn simple_match(haystack: &str, pattern: &str) -> bool {
    if !pattern.contains('*') {
        return haystack.contains(pattern);
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if let Some(found) = haystack[pos..].find(part) {
            if i == 0 && found != 0 {
                return false;
            }
            pos += found + part.len();
        } else {
            return false;
        }
    }
    if !parts.last().is_none_or(|p| p.is_empty()) {
        pos == haystack.len()
    } else {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synta::{Integer, UtcTime};
    use synta_certificate::{
        CertificateBuilder, ExtendedKeyUsageBuilder, NameBuilder, PrivateKeyBuilder,
        SubjectAlternativeNameBuilder, Time,
    };

    fn build_test_cert(cn: &str, o: &str, dns_sans: &[&str], eku_oids: &[&[u32]]) -> Vec<u8> {
        let key = PrivateKeyBuilder::ec("P-256")
            .generate()
            .expect("generate key");
        let spki = key.public_key_spki_der().expect("public key");
        let name = NameBuilder::new()
            .common_name(cn)
            .organization(o)
            .build()
            .expect("build name");

        let mut builder = CertificateBuilder::new()
            .subject_name(&name)
            .issuer_name(&name)
            .public_key_der(&spki)
            .serial_number(Integer::from_i64(1))
            .not_valid_before(Time::UtcTime(UtcTime::new(2025, 1, 1, 0, 0, 0).unwrap()))
            .not_valid_after(Time::UtcTime(UtcTime::new(2027, 1, 1, 0, 0, 0).unwrap()));

        if !dns_sans.is_empty() {
            let mut san_builder = SubjectAlternativeNameBuilder::new();
            for dns in dns_sans {
                san_builder = san_builder.dns_name(dns);
            }
            let san_der = san_builder.build().unwrap();
            builder = builder.add_extension_oid(
                synta_certificate::oids::SUBJECT_ALT_NAME,
                false,
                &san_der,
            );
        }

        if !eku_oids.is_empty() {
            let mut eku_builder = ExtendedKeyUsageBuilder::new();
            for oid in eku_oids {
                eku_builder = eku_builder.add_oid(oid);
            }
            let eku_der = eku_builder.build().unwrap();
            builder = builder.add_extension_oid(
                synta_certificate::oids::EXTENDED_KEY_USAGE,
                false,
                &eku_der,
            );
        }

        builder.sign(&key.as_signer("sha256")).expect("sign cert")
    }

    #[test]
    fn parse_simple_subject_rule() {
        let m = CertMatcher::parse("<SUBJECT>CN=test").unwrap();
        assert!(matches!(m.rule, MatchRule::Subject(_)));
    }

    #[test]
    fn parse_and_combinator() {
        let m = CertMatcher::parse("<SUBJECT>CN=test&&<ISSUER>O=CA").unwrap();
        assert!(matches!(m.rule, MatchRule::And(_)));
    }

    #[test]
    fn parse_or_combinator() {
        let m = CertMatcher::parse("<SUBJECT>CN=a||<SUBJECT>CN=b").unwrap();
        assert!(matches!(m.rule, MatchRule::Or(_)));
    }

    #[test]
    fn parse_eku_rule() {
        let m = CertMatcher::parse("<EKU>1.3.6.1.5.2.3.4").unwrap();
        match &m.rule {
            MatchRule::Eku(oid) => assert_eq!(oid, &[1, 3, 6, 1, 5, 2, 3, 4]),
            _ => panic!("expected Eku"),
        }
    }

    #[test]
    fn parse_ku_rule() {
        let m = CertMatcher::parse("<KU>80").unwrap();
        match &m.rule {
            MatchRule::Ku(bits) => assert_eq!(*bits, 0x80),
            _ => panic!("expected Ku"),
        }
    }

    #[test]
    fn parse_invalid_tag_fails() {
        assert!(CertMatcher::parse("<INVALID>foo").is_err());
    }

    #[test]
    fn parse_missing_tag_bracket_fails() {
        assert!(CertMatcher::parse("SUBJECT>foo").is_err());
    }

    #[test]
    fn match_subject_cn() {
        let cert = build_test_cert("TestUser", "TestOrg", &[], &[]);
        let m = CertMatcher::parse("<SUBJECT>CN=TestUser").unwrap();
        assert!(m.matches(&cert).unwrap());
    }

    #[test]
    fn match_subject_cn_no_match() {
        let cert = build_test_cert("TestUser", "TestOrg", &[], &[]);
        let m = CertMatcher::parse("<SUBJECT>CN=OtherUser").unwrap();
        assert!(!m.matches(&cert).unwrap());
    }

    #[test]
    fn match_issuer_org() {
        let cert = build_test_cert("TestUser", "TestOrg", &[], &[]);
        let m = CertMatcher::parse("<ISSUER>O=TestOrg").unwrap();
        assert!(m.matches(&cert).unwrap());
    }

    #[test]
    fn match_san_dns() {
        let cert = build_test_cert("TestUser", "TestOrg", &["host.example.com"], &[]);
        let m = CertMatcher::parse("<SAN>host.example.com").unwrap();
        assert!(m.matches(&cert).unwrap());
    }

    #[test]
    fn match_san_no_match() {
        let cert = build_test_cert("TestUser", "TestOrg", &["host.example.com"], &[]);
        let m = CertMatcher::parse("<SAN>other.example.com").unwrap();
        assert!(!m.matches(&cert).unwrap());
    }

    #[test]
    fn match_eku() {
        let cert = build_test_cert(
            "TestUser",
            "TestOrg",
            &[],
            &[crate::constants::ID_PKINIT_KPCLIENT_AUTH],
        );
        let m = CertMatcher::parse("<EKU>1.3.6.1.5.2.3.4").unwrap();
        assert!(m.matches(&cert).unwrap());
    }

    #[test]
    fn match_eku_no_match() {
        let cert = build_test_cert(
            "TestUser",
            "TestOrg",
            &[],
            &[crate::constants::ID_PKINIT_KPCLIENT_AUTH],
        );
        let m = CertMatcher::parse("<EKU>1.3.6.1.5.5.7.3.1").unwrap();
        assert!(!m.matches(&cert).unwrap());
    }

    #[test]
    fn match_and_both_true() {
        let cert = build_test_cert("TestUser", "TestOrg", &[], &[]);
        let m = CertMatcher::parse("<SUBJECT>CN=TestUser&&<ISSUER>O=TestOrg").unwrap();
        assert!(m.matches(&cert).unwrap());
    }

    #[test]
    fn match_and_one_false() {
        let cert = build_test_cert("TestUser", "TestOrg", &[], &[]);
        let m = CertMatcher::parse("<SUBJECT>CN=TestUser&&<ISSUER>O=OtherOrg").unwrap();
        assert!(!m.matches(&cert).unwrap());
    }

    #[test]
    fn match_or_one_true() {
        let cert = build_test_cert("TestUser", "TestOrg", &[], &[]);
        let m = CertMatcher::parse("<SUBJECT>CN=OtherUser||<SUBJECT>CN=TestUser").unwrap();
        assert!(m.matches(&cert).unwrap());
    }

    #[test]
    fn match_or_both_false() {
        let cert = build_test_cert("TestUser", "TestOrg", &[], &[]);
        let m = CertMatcher::parse("<SUBJECT>CN=A||<SUBJECT>CN=B").unwrap();
        assert!(!m.matches(&cert).unwrap());
    }

    #[test]
    fn match_wildcard_pattern() {
        let cert = build_test_cert("TestUser", "TestOrg", &[], &[]);
        let m = CertMatcher::parse("<SUBJECT>CN=Test*").unwrap();
        assert!(m.matches(&cert).unwrap());
    }

    #[test]
    fn simple_match_no_glob() {
        assert!(simple_match("hello world", "world"));
        assert!(!simple_match("hello world", "mars"));
    }

    #[test]
    fn simple_match_glob_prefix() {
        assert!(simple_match("hello world", "hello*"));
        assert!(simple_match("hello world", "*world"));
    }

    #[test]
    fn simple_match_glob_middle() {
        assert!(simple_match("hello world", "he*ld"));
        assert!(!simple_match("hello world", "he*mars"));
    }
}
