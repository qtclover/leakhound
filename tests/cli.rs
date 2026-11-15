//! End-to-end tests that run the real binary against throwaway directories.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn leakhound(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_leakhound"))
        .arg(dir)
        .args(args)
        .output()
        .expect("binary runs")
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=Test", "-c", "user.email=test@example.invalid"])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .output()
        .expect("git runs");
    assert!(status.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&status.stderr));
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("valid JSON on stdout")
}

// Assembled at runtime so the repository holds nothing that looks live.
fn token() -> String {
    format!("ghp_{}", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6")
}

#[test]
fn clean_directory_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();
    let out = leakhound(dir.path(), &[]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
}

#[test]
fn secret_on_disk_exits_one_and_is_redacted() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("config.py"), format!("a = 1\nTOKEN = '{}'\n", token())).unwrap();

    let out = leakhound(dir.path(), &["--format", "json"]);
    assert_eq!(out.status.code(), Some(1));
    let findings = json(&out);
    assert_eq!(findings.as_array().unwrap().len(), 1);
    assert_eq!(findings[0]["rule"], "github-token");
    assert_eq!(findings[0]["path"], "config.py");
    assert_eq!(findings[0]["line"], 2);
    assert_eq!(findings[0]["source"], "worktree");
    assert!(!String::from_utf8_lossy(&out.stdout).contains(&token()));

    let shown = leakhound(dir.path(), &["--format", "json", "--show-secrets"]);
    assert_eq!(json(&shown)[0]["secret"], token());
}

#[test]
fn exclude_glob_skips_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("fixtures")).unwrap();
    fs::write(dir.path().join("fixtures/creds.txt"), token()).unwrap();
    assert_eq!(leakhound(dir.path(), &[]).status.code(), Some(1));
    assert_eq!(leakhound(dir.path(), &["--exclude", "fixtures/"]).status.code(), Some(0));
}

#[test]
fn gitignored_files_are_skipped_unless_asked() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
    fs::write(dir.path().join(".env"), format!("GITHUB_TOKEN={}\n", token())).unwrap();
    assert_eq!(leakhound(dir.path(), &[]).status.code(), Some(0));
    assert_eq!(leakhound(dir.path(), &["--no-ignore"]).status.code(), Some(1));
}

#[test]
fn deleted_secret_is_still_found_in_history() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("deploy.sh");
    git(dir.path(), &["init", "-q"]);

    fs::write(&file, format!("#!/bin/sh\necho start\nexport GH={}\n", token())).unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "add deploy script"]);

    fs::write(&file, "#!/bin/sh\necho start\nexport GH=$GH_FROM_ENV\n").unwrap();
    git(dir.path(), &["commit", "-qam", "remove token"]);

    // Gone from the files on disk...
    assert_eq!(leakhound(dir.path(), &[]).status.code(), Some(0));

    // ...but one `git log -p` away for anyone who clones the repository.
    let out = leakhound(dir.path(), &["--history", "--format", "json"]);
    assert_eq!(out.status.code(), Some(1));
    let findings = json(&out);
    assert_eq!(findings.as_array().unwrap().len(), 1);
    assert_eq!(findings[0]["rule"], "github-token");
    assert_eq!(findings[0]["path"], "deploy.sh");
    assert_eq!(findings[0]["line"], 3);
    assert_eq!(findings[0]["source"], "history");
    assert_eq!(findings[0]["commit"]["author"], "Test");
}

#[test]
fn secret_on_disk_and_in_history_is_reported_once() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    fs::write(dir.path().join("a.txt"), format!("{}\n", token())).unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "one"]);
    fs::write(dir.path().join("b.txt"), "unrelated\n").unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "two"]);

    let findings = json(&leakhound(dir.path(), &["--history", "--format", "json"]));
    assert_eq!(findings.as_array().unwrap().len(), 1);
    assert_eq!(findings[0]["source"], "worktree");
    assert!(findings[0]["commit"]["hash"].is_string());
}

#[test]
fn missing_path_exits_two() {
    let out = leakhound(Path::new("/definitely/not/a/real/path"), &[]);
    assert_eq!(out.status.code(), Some(2));
}
