pub mod baseline;
pub mod config;
pub mod entropy;
pub mod filter;
pub mod git;
pub mod hook;
pub mod report;
pub mod rules;
pub mod scan;
pub mod verify;
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
    /// Added to the index and about to be committed.
    Staged,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule: String,
    pub description: String,
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub secret: String,
    pub entropy: f64,
    /// Stable across runs for the same secret in the same file, whatever line
    /// it moves to. Lets other tools track or baseline a finding.
    pub fingerprint: String,
    pub source: Source,
    /// The oldest commit that added this secret, when history was scanned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<Arc<Commit>>,
    /// Whether the issuing service still accepts the secret, when --verify
    /// was given and this kind of secret can be checked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<verify::Status>,
}

impl Finding {
    pub fn from_hit(hit: scan::Hit, path: &str, source: Source) -> Self {
        Finding {
            rule: hit.rule.id.clone(),
            description: hit.rule.description.clone(),
            path: path.to_string(),
            line: hit.line,
            column: hit.column,
            fingerprint: fingerprint(&hit.rule.id, path, &hit.secret),
            secret: hit.secret,
            entropy: hit.entropy,
            source,
            commit: None,
            verification: None,
        }
    }
}

/// FNV-1a over rule, path and secret. Written out by hand because the standard
/// library's hasher is not guaranteed to give the same value across releases.
fn fingerprint(rule: &str, path: &str, secret: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for part in [rule, path, secret] {
        for &byte in part.as_bytes().iter().chain(&[0]) {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    format!("{hash:016x}")
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
    use super::{fingerprint, redact};

    #[test]
    fn fingerprint_is_stable_and_sensitive_to_each_part() {
        let base = fingerprint("rule", "a.txt", "s3cret");
        assert_eq!(base, fingerprint("rule", "a.txt", "s3cret"));
        assert_eq!(base.len(), 16);
        assert_ne!(base, fingerprint("rule", "b.txt", "s3cret"));
        assert_ne!(base, fingerprint("rule", "a.txt", "s3cret2"));
        assert_ne!(base, fingerprint("rulea", ".txt", "s3cret"));
    }

    #[test]
    fn redact_hides_short_secrets_entirely() {
        assert_eq!(redact("hunter2"), "*******");
    }

    #[test]
    fn redact_keeps_prefix_and_suffix() {
        assert_eq!(redact("abcd1234567890yz"), "abcd**********yz");
    }
}
