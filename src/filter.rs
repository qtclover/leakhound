//! Path exclusion shared by the file walk and the git history scan.

use anyhow::{Context, Result};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::overrides::{Override, OverrideBuilder};
use std::path::Path;

/// A set of gitignore-style globs naming paths that must not be scanned.
pub struct PathFilter {
    globs: Vec<String>,
    matcher: Gitignore,
}

impl PathFilter {
    pub fn new(root: &Path, globs: Vec<String>) -> Result<Self> {
        let mut builder = GitignoreBuilder::new(root);
        for glob in &globs {
            builder
                .add_line(None, glob)
                .with_context(|| format!("invalid exclude pattern {glob:?}"))?;
        }
        Ok(PathFilter {
            matcher: builder.build()?,
            globs,
        })
    }

    /// Whether a path relative to the scan root is excluded, either directly
    /// or because one of its parent directories is.
    pub fn is_excluded(&self, relative: &str) -> bool {
        !self.globs.is_empty()
            && self
                .matcher
                .matched_path_or_any_parents(relative, false)
                .is_ignore()
    }

    /// The same globs in the form the directory walker wants, so excluded
    /// directories are never descended into.
    pub fn overrides(&self, root: &Path) -> Result<Override> {
        let mut builder = OverrideBuilder::new(root);
        for glob in &self.globs {
            builder.add(&format!("!{glob}"))?;
        }
        Ok(builder.build()?)
    }
}

#[cfg(test)]
mod tests {
    use super::PathFilter;
    use std::path::Path;

    #[test]
    fn matches_files_and_everything_under_directories() {
        let filter = PathFilter::new(
            Path::new("."),
            vec!["fixtures/".to_string(), "*.lock".to_string()],
        )
        .unwrap();
        assert!(filter.is_excluded("fixtures/creds.txt"));
        assert!(filter.is_excluded("tests/fixtures/deep/creds.txt"));
        assert!(filter.is_excluded("Cargo.lock"));
        assert!(!filter.is_excluded("src/main.rs"));
    }

    #[test]
    fn empty_filter_excludes_nothing() {
        let filter = PathFilter::new(Path::new("."), Vec::new()).unwrap();
        assert!(!filter.is_excluded("anything"));
    }
}
