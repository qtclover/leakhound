//! Output formats: human-readable text, JSON, and SARIF.

use crate::rules::Rule;
use crate::{Finding, Source};
use serde_json::{Value, json};
use std::io::{self, Write};
use std::sync::Arc;

pub fn text(out: &mut impl Write, findings: &[Finding], color: bool) -> io::Result<()> {
    let (red, bold, dim, reset) = if color {
        ("\x1b[31m", "\x1b[1m", "\x1b[2m", "\x1b[0m")
    } else {
        ("", "", "", "")
    };
    for f in findings {
        writeln!(out, "{red}{bold}{}{reset}  {}", f.rule, f.description)?;
        writeln!(out, "  {bold}{}:{}:{}{reset}", f.path, f.line, f.column)?;
        writeln!(
            out,
            "  secret   {}  {dim}(entropy {:.2}){reset}",
            f.secret, f.entropy
        )?;
        if let Some(c) = &f.commit {
            let label = match f.source {
                Source::History => "history ",
                _ => "added in",
            };
            let short = &c.hash[..c.hash.len().min(10)];
            writeln!(out, "  {label} {short} {dim}{} {}{reset}", c.date, c.author)?;
        }
        writeln!(out)?;
    }
    Ok(())
}

pub fn json(out: &mut impl Write, findings: &[Finding]) -> serde_json::Result<()> {
    serde_json::to_writer_pretty(out, findings)
}

/// SARIF 2.1.0, the format GitHub code scanning ingests.
pub fn sarif(findings: &[Finding], rules: &[Arc<Rule>]) -> Value {
    let rules: Vec<Value> = rules
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.id,
                "shortDescription": { "text": r.description },
                "defaultConfiguration": { "level": "error" },
            })
        })
        .collect();

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let mut message = format!("{}: {}", f.description, f.secret);
            if f.source == Source::History
                && let Some(c) = &f.commit
            {
                message.push_str(&format!(
                    ". No longer in the current files, but still in git history (commit {}).",
                    &c.hash[..c.hash.len().min(10)]
                ));
            }
            json!({
                "ruleId": f.rule,
                "level": "error",
                "message": { "text": message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.path.replace('\\', "/") },
                        "region": { "startLine": f.line, "startColumn": f.column },
                    }
                }],
                "partialFingerprints": { "leakhound/v1": f.fingerprint },
            })
        })
        .collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "leakhound",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/qtclover/leakhound",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    })
}
