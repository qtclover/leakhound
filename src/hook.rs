//! Install a git pre-commit hook that runs `leakhound --staged`.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Lets a later install recognise, and safely replace, a hook we wrote.
const MARKER: &str = "# Installed by leakhound";

const SCRIPT: &str = r#"#!/bin/sh
# Installed by leakhound. Blocks commits that add secrets.
# Skip it for a single commit with: git commit --no-verify
if ! command -v leakhound >/dev/null 2>&1; then
    echo "leakhound: not found on PATH, skipping secret scan" >&2
    exit 0
fi
exec leakhound --staged
"#;

/// Writes the hook and returns where it went.
pub fn install(dir: &Path, force: bool) -> Result<PathBuf> {
    // Ask git rather than assuming .git/hooks: worktrees and core.hooksPath
    // both put hooks somewhere else.
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--git-path", "hooks"])
        .output()
        .context("could not run git; is it installed?")?;
    if !output.status.success() {
        bail!("{} is not inside a git repository", dir.display());
    }
    let hooks = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    let hooks = if hooks.is_relative() {
        dir.join(hooks)
    } else {
        hooks
    };

    let path = hooks.join("pre-commit");
    if !force
        && let Ok(existing) = std::fs::read_to_string(&path)
        && !existing.contains(MARKER)
    {
        bail!(
            "a pre-commit hook already exists at {}; rerun with --force to replace it",
            path.display()
        );
    }

    std::fs::create_dir_all(&hooks)?;
    std::fs::write(&path, SCRIPT).with_context(|| format!("could not write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(path)
}
