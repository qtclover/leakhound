//! The core matcher: text in, hits out.

use crate::entropy::shannon;
use crate::rules::{RULES, Rule, is_placeholder};
use regex::bytes::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};

/// Put this anywhere on a line to silence findings on that line.
pub const ALLOW_MARKER: &str = "leakhound:allow";

#[derive(Debug, Clone)]
pub struct Hit {
    pub rule: &'static Rule,
    /// 1-based line of the secret.
    pub line: usize,
    /// 1-based column (in characters) of the secret.
    pub column: usize,
    pub secret: String,
    pub entropy: f64,
}

pub struct Scanner {
    /// One pass over the text tells us which rules can match at all, so the
    /// common case (a file with no secrets) costs a single scan.
    set: RegexSet,
    regexes: Vec<Regex>,
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    pub fn new() -> Self {
        // Byte-oriented, ASCII-only matching: secrets are ASCII, and without
        // Unicode tables the regex engine can stay in its fast DFA throughout.
        let set = RegexSetBuilder::new(RULES.iter().map(|r| r.pattern))
            .unicode(false)
            .build()
            .expect("built-in rules compile");
        let regexes = RULES
            .iter()
            .map(|r| {
                RegexBuilder::new(r.pattern)
                    .unicode(false)
                    .build()
                    .expect("built-in rules compile")
            })
            .collect();
        Scanner { set, regexes }
    }

    pub fn scan(&self, text: &str) -> Vec<Hit> {
        let text = text.as_bytes();
        let matched = self.set.matches(text);
        if !matched.matched_any() {
            return Vec::new();
        }

        struct Raw {
            rule: &'static Rule,
            start: usize,
            end: usize,
            entropy: f64,
        }

        let mut raw = Vec::new();
        for idx in matched.iter() {
            let rule = &RULES[idx];
            for caps in self.regexes[idx].captures_iter(text) {
                let Some(m) = caps.get(rule.group) else {
                    continue;
                };
                let entropy = shannon(m.as_bytes());
                if rule.min_entropy.is_some_and(|min| entropy < min) {
                    continue;
                }
                if rule.generic && is_placeholder(&String::from_utf8_lossy(m.as_bytes())) {
                    continue;
                }
                raw.push(Raw {
                    rule,
                    start: m.start(),
                    end: m.end(),
                    entropy,
                });
            }
        }
        if raw.is_empty() {
            return Vec::new();
        }

        // A generic rule adds nothing when a specific rule already claimed the
        // same bytes, or when another generic rule reported the same span.
        let specific: Vec<(usize, usize)> = raw
            .iter()
            .filter(|r| !r.rule.generic)
            .map(|r| (r.start, r.end))
            .collect();
        let mut seen_generic: Vec<(usize, usize)> = Vec::new();
        raw.retain(|r| {
            if !r.rule.generic {
                return true;
            }
            if specific.iter().any(|&(s, e)| r.start < e && s < r.end) {
                return false;
            }
            if seen_generic.contains(&(r.start, r.end)) {
                return false;
            }
            seen_generic.push((r.start, r.end));
            true
        });
        raw.sort_by_key(|r| r.start);

        let newlines: Vec<usize> = memchr::memchr_iter(b'\n', text).collect();
        let mut hits = Vec::with_capacity(raw.len());
        for r in raw {
            let line = newlines.partition_point(|&nl| nl < r.start) + 1;
            let line_start = if line == 1 { 0 } else { newlines[line - 2] + 1 };
            let line_end = newlines.get(line - 1).copied().unwrap_or(text.len());
            if memchr::memmem::find(&text[line_start..line_end], ALLOW_MARKER.as_bytes()).is_some()
            {
                continue;
            }
            hits.push(Hit {
                rule: r.rule,
                line,
                column: String::from_utf8_lossy(&text[line_start..r.start])
                    .chars()
                    .count()
                    + 1,
                secret: String::from_utf8_lossy(&text[r.start..r.end]).into_owned(),
                entropy: r.entropy,
            });
        }
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test secrets are assembled at runtime so this file never contains a
    // string that looks like a live credential to other scanners.
    fn github_token() -> String {
        format!("ghp_{}", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6")
    }

    fn ids(hits: &[Hit]) -> Vec<&'static str> {
        hits.iter().map(|h| h.rule.id).collect()
    }

    #[test]
    fn clean_text_has_no_hits() {
        let s = Scanner::new();
        assert!(
            s.scan("fn main() {\n    println!(\"hello\");\n}\n")
                .is_empty()
        );
    }

    #[test]
    fn finds_github_token_with_position() {
        let s = Scanner::new();
        let text = format!("line one\n  let t = \"{}\";\n", github_token());
        let hits = s.scan(&text);
        assert_eq!(ids(&hits), ["github-token"]);
        assert_eq!(hits[0].line, 2);
        assert_eq!(hits[0].column, 12);
        assert_eq!(hits[0].secret, github_token());
    }

    #[test]
    fn specific_rule_suppresses_generic_on_same_secret() {
        let s = Scanner::new();
        let text = format!("api_token = \"{}\"", github_token());
        assert_eq!(ids(&s.scan(&text)), ["github-token"]);
    }

    #[test]
    fn finds_aws_access_key_id() {
        let s = Scanner::new();
        let text = format!("key = {}{}", "AKIA", "Q7ZP2MX4LD9TR5VB");
        assert_eq!(ids(&s.scan(&text)), ["aws-access-key-id"]);
    }

    #[test]
    fn finds_private_key_header() {
        let s = Scanner::new();
        let text = format!("-----BEGIN {} KEY-----\nMIIE...\n", "RSA PRIVATE");
        assert_eq!(ids(&s.scan(&text)), ["private-key"]);
    }

    #[test]
    fn generic_assignment_needs_entropy() {
        let s = Scanner::new();
        assert!(s.scan("password = \"passwordpassword\"").is_empty());
        let hits = s.scan("password = \"q8Zr2LmX0vTa7KdP\"");
        assert_eq!(ids(&hits), ["generic-secret-assignment"]);
        assert_eq!(hits[0].secret, "q8Zr2LmX0vTa7KdP");
    }

    #[test]
    fn generic_assignment_skips_placeholders() {
        let s = Scanner::new();
        assert!(
            s.scan("api_key = \"your_api_key_goes_here_123\"")
                .is_empty()
        );
        assert!(s.scan("secret: \"${SECRET_FROM_VAULT_9x}\"").is_empty());
    }

    #[test]
    fn finds_unquoted_env_secret() {
        let s = Scanner::new();
        let hits = s.scan("DEBUG=1\nSESSION_SECRET=q8Zr2LmX0vTa7KdP4w\n");
        assert_eq!(ids(&hits), ["generic-env-secret"]);
        assert_eq!(hits[0].line, 2);
    }

    #[test]
    fn finds_database_password_but_not_local_defaults() {
        let s = Scanner::new();
        let hits = s.scan("url = postgres://app:x9Kq2mVz7Lp@db.internal:5432/prod"); // leakhound:allow
        assert_eq!(ids(&hits), ["database-url-password"]);
        assert_eq!(hits[0].secret, "x9Kq2mVz7Lp");
        assert!(
            s.scan("postgres://postgres:postgres@localhost/dev")
                .is_empty()
        );
    }

    #[test]
    fn allow_marker_silences_the_line() {
        let s = Scanner::new();
        let text = format!("t = \"{}\" # leakhound:allow\n", github_token());
        assert!(s.scan(&text).is_empty());
    }

    #[test]
    fn every_rule_id_is_unique() {
        let mut seen = std::collections::HashSet::new();
        for rule in RULES {
            assert!(seen.insert(rule.id), "duplicate rule id {}", rule.id);
        }
    }
}
