pub mod entropy;
pub mod rules;
pub mod scan;
pub mod walk;

use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize)]
pub struct Commit {
    pub hash: String,
    pub author: String,
    pub date: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Present in the files on disk right now.
    Worktree,
    /// Only reachable through git history; the current files no longer have it.
    History,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub description: &'static str,
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub secret: String,
    pub entropy: f64,
    pub source: Source,
    /// The oldest commit that added this secret, when history was scanned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<Arc<Commit>>,
}

impl Finding {
    pub fn from_hit(hit: scan::Hit, path: &str, source: Source) -> Self {
        Finding {
            rule: hit.rule.id,
            description: hit.rule.description,
            path: path.to_string(),
            line: hit.line,
            column: hit.column,
            secret: hit.secret,
            entropy: hit.entropy,
            source,
            commit: None,
        }
    }
}

/// Keep enough of a secret to recognise it, hide the rest.
pub fn redact(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 2..].iter().collect();
    format!("{head}{}{tail}", "*".repeat((chars.len() - 6).min(12)))
}

#[cfg(test)]
mod tests {
    use super::redact;

    #[test]
    fn redact_hides_short_secrets_entirely() {
        assert_eq!(redact("hunter2"), "*******");
    }

    #[test]
    fn redact_keeps_prefix_and_suffix() {
        assert_eq!(redact("abcd1234567890yz"), "abcd**********yz");
    }
}
