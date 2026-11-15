//! Scan the files on disk, in parallel.

use crate::scan::Scanner;
use crate::{Finding, Source};
use anyhow::{Context, Result};
use ignore::overrides::OverrideBuilder;
use ignore::{WalkBuilder, WalkState};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct WalkOptions {
    /// Also scan files that .gitignore and friends would hide.
    pub no_ignore: bool,
    /// Glob patterns to leave out, gitignore syntax.
    pub exclude: Vec<String>,
    /// Files larger than this many bytes are skipped.
    pub max_size: u64,
    pub threads: usize,
}

#[derive(Debug, Default)]
pub struct WalkStats {
    pub files: u64,
    pub bytes: u64,
}

/// A NUL byte near the start is the same cheap binary test git uses.
fn looks_binary(data: &[u8]) -> bool {
    memchr::memchr(0, &data[..data.len().min(8000)]).is_some()
}

pub fn scan_tree(
    root: &Path,
    scanner: &Scanner,
    opts: &WalkOptions,
) -> Result<(Vec<Finding>, WalkStats)> {
    let mut overrides = OverrideBuilder::new(root);
    for glob in &opts.exclude {
        overrides
            .add(&format!("!{glob}"))
            .with_context(|| format!("invalid --exclude pattern {glob:?}"))?;
    }

    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false) // dotfiles such as .env are exactly where secrets live
        .git_ignore(!opts.no_ignore)
        .git_global(!opts.no_ignore)
        .git_exclude(!opts.no_ignore)
        .ignore(!opts.no_ignore)
        .parents(!opts.no_ignore)
        .overrides(overrides.build()?)
        .threads(opts.threads)
        .filter_entry(|e| e.file_name() != ".git");

    let findings = Mutex::new(Vec::new());
    let files = AtomicU64::new(0);
    let bytes = AtomicU64::new(0);

    builder.build_parallel().run(|| {
        Box::new(|entry| {
            let Ok(entry) = entry else {
                return WalkState::Continue;
            };
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                return WalkState::Continue;
            }
            if entry.metadata().is_ok_and(|m| m.len() > opts.max_size) {
                return WalkState::Continue;
            }
            let Ok(data) = std::fs::read(entry.path()) else {
                return WalkState::Continue;
            };
            if looks_binary(&data) {
                return WalkState::Continue;
            }
            files.fetch_add(1, Ordering::Relaxed);
            bytes.fetch_add(data.len() as u64, Ordering::Relaxed);

            let hits = scanner.scan(&String::from_utf8_lossy(&data));
            if hits.is_empty() {
                return WalkState::Continue;
            }
            let rel = entry.path().strip_prefix(root).unwrap_or(entry.path());
            let shown = if rel.as_os_str().is_empty() {
                entry.path()
            } else {
                rel
            };
            let path = shown.to_string_lossy();
            let found = hits
                .into_iter()
                .map(|h| Finding::from_hit(h, &path, Source::Worktree));
            findings.lock().unwrap().extend(found);
            WalkState::Continue
        })
    });

    let stats = WalkStats {
        files: files.into_inner(),
        bytes: bytes.into_inner(),
    };
    Ok((findings.into_inner().unwrap(), stats))
}
