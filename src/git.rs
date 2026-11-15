//! Scan every line ever added in a repository's history, or just the lines
//! staged for the next commit.
//!
//! Rather than linking a git library, this streams `git log -p -U0` and parses
//! the diff: with zero context lines each hunk is exactly one block of added
//! text, which is all a secret scanner needs to look at.

use crate::filter::PathFilter;
use crate::scan::Scanner;
use crate::{Commit, Finding, Source};
use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

/// Hunks are scanned in parallel once this much added text has piled up.
const BATCH_BYTES: usize = 16 << 20;

struct Hunk {
    commit: Option<Arc<Commit>>,
    path: Arc<str>,
    start_line: usize,
    text: String,
}

#[derive(Debug, Default)]
pub struct HistoryStats {
    pub commits: u64,
    pub bytes: u64,
}

/// Pull the new-file start line out of `@@ -a,b +c,d @@`.
fn hunk_start(header: &str) -> Option<usize> {
    let plus = header.find(" +")? + 2;
    let digits: String = header[plus..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

fn scan_batch(batch: &mut Vec<Hunk>, scanner: &Scanner, source: Source, out: &mut Vec<Finding>) {
    let found: Vec<Finding> = batch
        .par_iter()
        .flat_map_iter(|hunk| {
            scanner.scan(&hunk.text).into_iter().map(|hit| {
                let mut f = Finding::from_hit(hit, &hunk.path, source);
                f.line += hunk.start_line - 1;
                f.commit = hunk.commit.clone();
                f
            })
        })
        .collect();
    out.extend(found);
    batch.clear();
}

/// Run a git command that prints a `-U0` diff and scan every added hunk.
fn scan_diff(
    dir: &Path,
    args: &[&str],
    scanner: &Scanner,
    filter: &PathFilter,
    source: Source,
) -> Result<(Vec<Finding>, HistoryStats, Output)> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "core.quotepath=off"])
        .args(args)
        .args([
            "-U0",
            "--relative",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("could not run git; is it installed?")?;

    let mut reader = BufReader::with_capacity(1 << 20, child.stdout.take().unwrap());
    let mut stats = HistoryStats::default();
    let mut findings = Vec::new();
    let mut batch: Vec<Hunk> = Vec::new();
    let mut batch_bytes = 0usize;

    let mut commit: Option<Arc<Commit>> = None;
    let mut path: Arc<str> = Arc::from("");
    // True between a `diff --git` line and its first hunk. Only there can a
    // line starting with `+++ ` be a file header instead of added content.
    let mut in_header = false;
    let mut current: Option<Hunk> = None;

    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }

        let starts_hunk = line.starts_with(b"@@ ");
        let ends_hunk = starts_hunk || line.first() == Some(&1) || line.starts_with(b"diff --git ");
        if ends_hunk && let Some(hunk) = current.take() {
            batch_bytes += hunk.text.len();
            stats.bytes += hunk.text.len() as u64;
            batch.push(hunk);
            if batch_bytes >= BATCH_BYTES {
                scan_batch(&mut batch, scanner, source, &mut findings);
                batch_bytes = 0;
            }
        }

        if line.first() == Some(&1) {
            let text = String::from_utf8_lossy(&line[1..]);
            let mut parts = text.splitn(3, '\u{1}');
            commit = Some(Arc::new(Commit {
                hash: parts.next().unwrap_or_default().to_string(),
                author: parts.next().unwrap_or_default().to_string(),
                date: parts.next().unwrap_or_default().to_string(),
            }));
            stats.commits += 1;
        } else if line.starts_with(b"diff --git ") {
            in_header = true;
        } else if in_header && line.starts_with(b"+++ ") {
            let name = String::from_utf8_lossy(&line[4..]);
            if name != "/dev/null" {
                path = Arc::from(name.strip_prefix("b/").unwrap_or(&name));
            }
        } else if starts_hunk {
            in_header = false;
            if !filter.is_excluded(&path) {
                let header = String::from_utf8_lossy(&line);
                current = Some(Hunk {
                    commit: commit.clone(),
                    path: path.clone(),
                    start_line: hunk_start(&header).unwrap_or(1).max(1),
                    text: String::new(),
                });
            }
        } else if !in_header
            && line.first() == Some(&b'+')
            && let Some(hunk) = current.as_mut()
        {
            hunk.text.push_str(&String::from_utf8_lossy(&line[1..]));
            hunk.text.push('\n');
        }
    }
    if let Some(hunk) = current.take() {
        stats.bytes += hunk.text.len() as u64;
        batch.push(hunk);
    }
    scan_batch(&mut batch, scanner, source, &mut findings);

    let output = child.wait_with_output()?;
    Ok((findings, stats, output))
}

pub fn scan_history(
    dir: &Path,
    scanner: &Scanner,
    filter: &PathFilter,
) -> Result<(Vec<Finding>, HistoryStats)> {
    let args = ["log", "--all", "-p", "--format=%x01%H%x01%an%x01%as"];
    let (findings, stats, output) = scan_diff(dir, &args, scanner, filter, Source::History)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // A repository with no commits yet has nothing to scan; that is fine.
        if !stderr.contains("does not have any commits yet") {
            bail!("git log failed: {}", stderr.trim());
        }
    }

    // The log runs newest first, so letting later entries overwrite earlier
    // ones leaves each secret attributed to the oldest commit that added it.
    let mut oldest: HashMap<(String, String, String), Finding> = HashMap::new();
    for f in findings {
        oldest.insert((f.rule.clone(), f.path.clone(), f.secret.clone()), f);
    }
    Ok((oldest.into_values().collect(), stats))
}

/// Scan only what `git add` has staged, which is what the next commit will
/// contain. This is the pre-commit hook's entry point.
pub fn scan_staged(
    dir: &Path,
    scanner: &Scanner,
    filter: &PathFilter,
) -> Result<(Vec<Finding>, HistoryStats)> {
    let args = ["diff", "--cached"];
    let (findings, stats, output) = scan_diff(dir, &args, scanner, filter, Source::Staged)?;
    if !output.status.success() {
        bail!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok((findings, stats))
}

#[cfg(test)]
mod tests {
    use super::hunk_start;

    #[test]
    fn parses_hunk_headers() {
        assert_eq!(hunk_start("@@ -0,0 +1,3 @@"), Some(1));
        assert_eq!(hunk_start("@@ -10 +42 @@ fn main() {"), Some(42));
        assert_eq!(hunk_start("@@ -3,2 +7,0 @@"), Some(7));
    }
}
