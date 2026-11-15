//! A baseline is a list of findings that are already known and accepted, so a
//! scan can fail only on new ones.
//!
//! It is simply a saved JSON report: `leakhound -f json -o baseline.json`
//! writes one, `leakhound --baseline baseline.json` reads it back. Findings are
//! matched by fingerprint, which covers the rule, file and secret but not the
//! line, so a known secret that moves within its file stays known.

use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::HashSet;
use std::path::Path;

pub fn parse(text: &str) -> Result<HashSet<String>> {
    let Value::Array(items) = serde_json::from_str(text)? else {
        bail!("expected a JSON array");
    };
    items
        .into_iter()
        .map(|item| match item {
            // A bare list of fingerprints is accepted too, for hand-written files.
            Value::String(fingerprint) => Ok(fingerprint),
            Value::Object(mut finding) => match finding.remove("fingerprint") {
                Some(Value::String(fingerprint)) => Ok(fingerprint),
                _ => bail!("an entry has no \"fingerprint\""),
            },
            _ => bail!("entries must be findings or fingerprint strings"),
        })
        .collect()
}

pub fn load(path: &Path) -> Result<HashSet<String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("could not read baseline {}", path.display()))?;
    parse(&text).with_context(|| format!("invalid baseline {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn reads_a_saved_report() {
        let known = parse(r#"[{"rule":"jwt","fingerprint":"00aa"},{"fingerprint":"11bb"}]"#);
        let known = known.unwrap();
        assert!(known.contains("00aa") && known.contains("11bb"));
        assert_eq!(known.len(), 2);
    }

    #[test]
    fn reads_a_plain_list_and_an_empty_one() {
        assert!(parse(r#"["00aa"]"#).unwrap().contains("00aa"));
        assert!(parse("[]").unwrap().is_empty());
    }

    #[test]
    fn rejects_anything_else() {
        assert!(parse("{}").is_err());
        assert!(parse(r#"[{"rule":"jwt"}]"#).is_err());
        assert!(parse("[1]").is_err());
        assert!(parse("not json").is_err());
    }
}
