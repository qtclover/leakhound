//! The optional `leakhound.toml` file: custom rules and allowlists.
//!
//! ```toml
//! [[rules]]
//! id = "acme-token"
//! description = "Acme internal API token"
//! regex = 'acme_[a-z0-9]{32}'
//!
//! [allowlist]
//! paths = ["tests/fixtures/"]     # gitignore-style globs to skip
//! regexes = ['^EXAMPLE']          # secrets matching these are ignored
//! rules = ["jwt"]                 # built-in rules to switch off
//! ```

use crate::rules::Rule;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// File names looked for in the scanned directory, in order.
pub const FILE_NAMES: &[&str] = &["leakhound.toml", ".leakhound.toml"];

#[derive(Debug, Default)]
pub struct Config {
    pub custom_rules: Vec<Rule>,
    pub disabled_rules: Vec<String>,
    pub allow_paths: Vec<String>,
    pub allow_regexes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    rules: Vec<RawRule>,
    #[serde(default)]
    allowlist: RawAllowlist,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    description: Option<String>,
    regex: String,
    /// Capture group holding the secret; 0 (the default) is the whole match.
    #[serde(default)]
    group: usize,
    /// Only report matches with at least this much Shannon entropy.
    min_entropy: Option<f64>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawAllowlist {
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    regexes: Vec<String>,
    #[serde(default)]
    rules: Vec<String>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Config> {
        let raw: RawConfig = toml::from_str(text)?;
        Ok(Config {
            custom_rules: raw
                .rules
                .into_iter()
                .map(|r| Rule {
                    description: r.description.unwrap_or_else(|| r.id.clone()),
                    id: r.id,
                    pattern: r.regex,
                    group: r.group,
                    min_entropy: r.min_entropy,
                    generic: false,
                })
                .collect(),
            disabled_rules: raw.allowlist.rules,
            allow_paths: raw.allowlist.paths,
            allow_regexes: raw.allowlist.regexes,
        })
    }

    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        Config::parse(&text).with_context(|| format!("invalid config {}", path.display()))
    }

    /// The config file sitting in `dir`, if there is one.
    pub fn find(dir: &Path) -> Option<PathBuf> {
        FILE_NAMES
            .iter()
            .map(|name| dir.join(name))
            .find(|p| p.is_file())
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use crate::scan::Scanner;

    #[test]
    fn empty_config_is_valid() {
        let config = Config::parse("").unwrap();
        assert!(config.custom_rules.is_empty());
        assert_eq!(Scanner::with_config(&config).unwrap().rules().len(), 22);
    }

    #[test]
    fn custom_rule_is_loaded_and_matches() {
        let config = Config::parse(
            r#"
            [[rules]]
            id = "acme-token"
            description = "Acme internal API token"
            regex = 'acme_[a-z0-9]{16}'
            "#,
        )
        .unwrap();
        let scanner = Scanner::with_config(&config).unwrap();
        let hits = scanner.scan("key: acme_0123456789abcdef");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule.id, "acme-token");
        assert_eq!(hits[0].secret, "acme_0123456789abcdef");
    }

    #[test]
    fn custom_rule_can_pick_a_capture_group() {
        let config = Config::parse(
            r#"
            [[rules]]
            id = "acme-pin"
            regex = 'acme-pin=(\d{6})'
            group = 1
            "#,
        )
        .unwrap();
        let hits = Scanner::with_config(&config)
            .unwrap()
            .scan("acme-pin=482915");
        assert_eq!(hits[0].secret, "482915");
        assert_eq!(hits[0].rule.description, "acme-pin");
    }

    #[test]
    fn allowlist_disables_rules_and_ignores_secrets() {
        let config = Config::parse(
            r#"
            [allowlist]
            rules = ["private-key"]
            regexes = ['^AKIAEXAMPLE']
            "#,
        )
        .unwrap();
        let scanner = Scanner::with_config(&config).unwrap();
        assert_eq!(scanner.rules().len(), 21);
        let key_header = format!("-----BEGIN {} KEY-----", "RSA PRIVATE");
        assert!(scanner.scan(&key_header).is_empty());
        // Assembled at runtime, like every other test credential here.
        let allowed = format!("id = {}{}", "AKIA", "EXAMPLE7Q2ZP4MX9");
        let reported = format!("id = {}{}", "AKIA", "Q7ZP2MX4LD9TR5VB");
        assert!(scanner.scan(&allowed).is_empty());
        assert_eq!(scanner.scan(&reported).len(), 1);
    }

    #[test]
    fn mistakes_are_reported_not_ignored() {
        assert!(
            Config::parse("[[rules]]\nid = 'x'").is_err(),
            "missing regex"
        );
        assert!(Config::parse("typo = 1").is_err(), "unknown key");

        let bad_regex = Config::parse("[[rules]]\nid = 'x'\nregex = '('").unwrap();
        assert!(Scanner::with_config(&bad_regex).is_err());

        let bad_group = Config::parse("[[rules]]\nid = 'x'\nregex = 'a'\ngroup = 1").unwrap();
        assert!(Scanner::with_config(&bad_group).is_err());

        let clash = Config::parse("[[rules]]\nid = 'jwt'\nregex = 'a'").unwrap();
        assert!(Scanner::with_config(&clash).is_err());

        let unknown = Config::parse("[allowlist]\nrules = ['no-such-rule']").unwrap();
        assert!(Scanner::with_config(&unknown).is_err());
    }
}
