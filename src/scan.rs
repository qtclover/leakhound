//! The core matcher: text in, hits out.

use crate::config::Config;
use crate::entropy::shannon;
use crate::rules::{self, Rule, is_placeholder};
use anyhow::{Context, Result, bail};
use regex::bytes::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use std::sync::Arc;

/// Put this anywhere on a line to silence findings on that line.
pub const ALLOW_MARKER: &str = "leakhound:allow";

#[derive(Debug, Clone)]
pub struct Hit {
    pub rule: Arc<Rule>,
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
    rules: Vec<Arc<Rule>>,
    /// Secrets matching any of these are never reported.
    allow: Vec<Regex>,
    seam: Regex,
}

/// Byte-oriented, ASCII-only matching: secrets are ASCII, and without Unicode
/// tables the regex engine can stay in its fast DFA throughout.
fn compile(pattern: &str) -> Result<Regex> {
    Ok(RegexBuilder::new(pattern).unicode(false).build()?)
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    /// A scanner with only the built-in rules.
    pub fn new() -> Self {
        Self::from_rules(rules::builtin(), Vec::new()).expect("built-in rules compile")
    }

    /// Built-in rules minus the ones the config disables, plus its custom
    /// rules and allowlist.
    pub fn with_config(config: &Config) -> Result<Self> {
        let mut all = rules::builtin();
        for id in &config.disabled_rules {
            if !all.iter().any(|r| &r.id == id) {
                bail!("allowlist.rules names {id:?}, which is not a built-in rule");
            }
        }
        all.retain(|r| !config.disabled_rules.contains(&r.id));
        for rule in &config.custom_rules {
            if all.iter().any(|r| r.id == rule.id) {
                bail!("rule id {:?} is already in use", rule.id);
            }
            all.push(rule.clone());
        }
        let allow = config
            .allow_regexes
            .iter()
            .map(|p| compile(p).with_context(|| format!("invalid allowlist regex {p:?}")))
            .collect::<Result<_>>()?;
        Self::from_rules(all, allow)
    }

    fn from_rules(rules: Vec<Rule>, allow: Vec<Regex>) -> Result<Self> {
        let mut regexes = Vec::with_capacity(rules.len());
        for rule in &rules {
            let regex = compile(&rule.pattern)
                .with_context(|| format!("rule {:?} has an invalid regex", rule.id))?;
            if rule.group >= regex.captures_len() {
                bail!(
                    "rule {:?} asks for capture group {} but its regex has {}",
                    rule.id,
                    rule.group,
                    regex.captures_len() - 1
                );
            }
            regexes.push(regex);
        }
        let set = RegexSetBuilder::new(rules.iter().map(|r| &r.pattern))
            .unicode(false)
            .build()?;
        Ok(Scanner {
            set,
            regexes,
            rules: rules.into_iter().map(Arc::new).collect(),
            allow,
            seam: compile(SEAM)?,
        })
    }

    pub fn rules(&self) -> &[Arc<Rule>] {
        &self.rules
    }

    pub fn scan(&self, text: &str) -> Vec<Hit> {
        let text = text.as_bytes();
        let mut found = self.matches(text);

        // Second pass for secrets broken across lines as adjacent string
        // literals. Only matches that actually cross a join are new.
        if let Some((joined, seams)) = self.join_split_literals(text) {
            for mut m in self.matches(&joined) {
                if !seams.iter().any(|s| m.start < s.at && s.at < m.end) {
                    continue;
                }
                // Translate the start back into the original text.
                m.start += seams
                    .iter()
                    .take_while(|s| s.at <= m.start)
                    .map(|s| s.removed)
                    .sum::<usize>();
                // The first pass may have matched just the first fragment.
                found.retain(|f| !(f.rule == m.rule && f.start == m.start));
                found.push(m);
            }
            found.sort_by_key(|m| m.start);
        }
        if found.is_empty() {
            return Vec::new();
        }

        let newlines: Vec<usize> = memchr::memchr_iter(b'\n', text).collect();
        let mut hits = Vec::with_capacity(found.len());
        for m in found {
            let line = newlines.partition_point(|&nl| nl < m.start) + 1;
            let line_start = if line == 1 { 0 } else { newlines[line - 2] + 1 };
            let line_end = newlines.get(line - 1).copied().unwrap_or(text.len());
            if memchr::memmem::find(&text[line_start..line_end], ALLOW_MARKER.as_bytes()).is_some()
            {
                continue;
            }
            hits.push(Hit {
                rule: self.rules[m.rule].clone(),
                line,
                column: String::from_utf8_lossy(&text[line_start..m.start])
                    .chars()
                    .count()
                    + 1,
                secret: m.secret,
                entropy: m.entropy,
            });
        }
        hits
    }

    /// Every rule match in `text`, filtered and sorted by position.
    fn matches(&self, text: &[u8]) -> Vec<Match> {
        let matched = self.set.matches(text);
        if !matched.matched_any() {
            return Vec::new();
        }

        let mut found = Vec::new();
        for idx in matched.iter() {
            let rule = &self.rules[idx];
            for caps in self.regexes[idx].captures_iter(text) {
                let Some(m) = caps.get(rule.group) else {
                    continue;
                };
                let entropy = shannon(m.as_bytes());
                if rule.min_entropy.is_some_and(|min| entropy < min) {
                    continue;
                }
                let secret = String::from_utf8_lossy(m.as_bytes());
                if rule.generic && is_placeholder(&secret) {
                    continue;
                }
                if self.allow.iter().any(|a| a.is_match(m.as_bytes())) {
                    continue;
                }
                found.push(Match {
                    rule: idx,
                    start: m.start(),
                    end: m.end(),
                    entropy,
                    secret: secret.into_owned(),
                });
            }
        }

        // A generic rule adds nothing when a specific rule already claimed the
        // same bytes, or when another generic rule reported the same span.
        let specific: Vec<(usize, usize)> = found
            .iter()
            .filter(|m| !self.rules[m.rule].generic)
            .map(|m| (m.start, m.end))
            .collect();
        let mut seen_generic: Vec<(usize, usize)> = Vec::new();
        found.retain(|m| {
            if !self.rules[m.rule].generic {
                return true;
            }
            if specific.iter().any(|&(s, e)| m.start < e && s < m.end) {
                return false;
            }
            if seen_generic.contains(&(m.start, m.end)) {
                return false;
            }
            seen_generic.push((m.start, m.end));
            true
        });
        found.sort_by_key(|m| m.start);
        found
    }

    /// Glue together string literals that continue on the next line, as in
    ///
    /// ```text
    /// key = "ghp_aB3dE6gH9jK2" +
    ///       "mN5pQ8sT1vW4yZ7b"
    /// ```
    ///
    /// by cutting out everything from the closing quote to the next opening
    /// quote. Returns the glued text and where each cut was made, or `None`
    /// when the text has no such continuation (the usual case).
    fn join_split_literals(&self, text: &[u8]) -> Option<(Vec<u8>, Vec<Seam>)> {
        let mut cuts = self.seam.find_iter(text).peekable();
        cuts.peek()?;

        let mut joined = Vec::with_capacity(text.len());
        let mut seams = Vec::new();
        let mut copied = 0;
        for cut in cuts {
            joined.extend_from_slice(&text[copied..cut.start()]);
            seams.push(Seam {
                at: joined.len(),
                removed: cut.len(),
            });
            copied = cut.end();
        }
        joined.extend_from_slice(&text[copied..]);
        Some((joined, seams))
    }
}

struct Match {
    rule: usize,
    start: usize,
    end: usize,
    entropy: f64,
    secret: String,
}

/// A place where two string literals were glued together.
struct Seam {
    /// Offset in the glued text where the second literal now begins.
    at: usize,
    /// How many bytes of the original text were cut out here.
    removed: usize,
}

/// A closing quote, an optional `+`, `.` or `\` continuation, a line break,
/// and the matching opening quote. A comma is deliberately not accepted:
/// that separates list items, it does not continue a string.
const SEAM: &str = concat!(
    r#""[ \t]*[+.\\]?[ \t]*\r?\n[ \t]*[+.]?[ \t]*""#,
    "|",
    r#"'[ \t]*[+.\\]?[ \t]*\r?\n[ \t]*[+.]?[ \t]*'"#,
);

#[cfg(test)]
mod tests {
    use super::*;

    // Test secrets are assembled at runtime so this file never contains a
    // string that looks like a live credential to other scanners.
    fn github_token() -> String {
        format!("ghp_{}", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6")
    }

    fn ids(hits: &[Hit]) -> Vec<&str> {
        hits.iter().map(|h| h.rule.id.as_str()).collect()
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
        for rule in rules::builtin() {
            assert!(
                seen.insert(rule.id.clone()),
                "duplicate rule id {}",
                rule.id
            );
        }
    }

    fn split_token(glue: &str) -> (String, String) {
        let token = github_token();
        let text = format!("key = \"{}\"{glue}\"{}\"\n", &token[..20], &token[20..]);
        (text, token)
    }

    #[test]
    fn joins_literals_continued_on_the_next_line() {
        let s = Scanner::new();
        for glue in [" +\n      ", "\n      ", " \\\n  ", "\r\n\t+ ", "\n    . "] {
            let (text, token) = split_token(glue);
            let hits = s.scan(&text);
            assert_eq!(ids(&hits), ["github-token"], "glue {glue:?}");
            assert_eq!(hits[0].secret, token, "glue {glue:?}");
            assert_eq!((hits[0].line, hits[0].column), (1, 8), "glue {glue:?}");
        }
    }

    #[test]
    fn does_not_join_separate_list_items_or_other_lines() {
        let s = Scanner::new();
        for glue in [",\n      ", "\nother = ", ";\n"] {
            let (text, _) = split_token(glue);
            assert!(s.scan(&text).is_empty(), "glue {glue:?}");
        }
    }

    #[test]
    fn joined_pass_does_not_duplicate_ordinary_hits() {
        let s = Scanner::new();
        let (split, token) = split_token(" +\n  ");
        let text = format!("a = \"{token}\"\n\n{split}b = \"{token}\"\n");
        let hits = s.scan(&text);
        assert_eq!(hits.len(), 3);
        assert_eq!(
            hits.iter().map(|h| h.line).collect::<Vec<_>>(),
            [1, 3, 5],
            "positions after a join must map back to the original lines"
        );
    }

    #[test]
    fn single_quoted_literals_join_only_with_the_same_quote() {
        let s = Scanner::new();
        let token = github_token();
        let same = format!("k = '{}' +\n  '{}'\n", &token[..20], &token[20..]);
        assert_eq!(s.scan(&same).len(), 1);
        let mixed = format!("k = '{}' +\n  \"{}\"\n", &token[..20], &token[20..]);
        assert!(s.scan(&mixed).is_empty());
    }
}
