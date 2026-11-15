# leakhound

[![CI](https://github.com/qtclover/leakhound/actions/workflows/ci.yml/badge.svg)](https://github.com/qtclover/leakhound/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/qtclover/leakhound)](https://github.com/qtclover/leakhound/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A fast secret scanner for source trees and git history, written in Rust.

![leakhound's pre-commit hook rejecting a commit that contains a GitHub token](https://raw.githubusercontent.com/qtclover/leakhound/main/assets/demo.svg)

It finds API keys, tokens, private keys and passwords that were committed by
mistake, including ones that were later deleted but are still sitting in the
repository's history. It can block them at commit time, check whether they
still work, and report them to GitHub code scanning.

```console
$ leakhound . --history
database-url-password  Password embedded in a database connection URL
  compose.yml:3:25
  secret   x9Kq******p4  (entropy 3.58)
  added in f20ed393e4 2026-11-15 Sam

stripe-live-key  Stripe live secret key
  src/settings.py:3:11
  secret   sk_l************dc  (entropy 4.75)
  history  73b84c3b5f 2026-11-15 Sam

scanned 2 files (0.0 MB) and 2 commits (0.0 MB of added lines) in 0.01s, 2 findings
```

The second finding is the interesting one: the key was removed from
`settings.py` in a later commit, so the files on disk are clean, but anyone who
clones the repository can still read it.

## Install

Download a static Linux binary from the
[releases page](https://github.com/qtclover/leakhound/releases), or build from
source with a recent stable Rust toolchain:

```sh
cargo install --git https://github.com/qtclover/leakhound
```

`--history`, `--staged` and `install-hook` need `git` on your `PATH`.

## Usage

```sh
leakhound                      # scan the current directory
leakhound path/to/repo         # scan somewhere else
leakhound --history            # also scan every commit on every branch
leakhound --staged             # scan only what is staged for the next commit
leakhound --verify             # ask each service whether the secret still works
leakhound --format json        # machine-readable output (also: sarif)
leakhound -o report.json -f json  # write the report to a file
leakhound -x 'tests/fixtures/' # skip paths matching a glob (repeatable)
leakhound --no-ignore          # include files hidden by .gitignore
leakhound --show-secrets       # print secrets in full instead of redacted
leakhound --list-rules         # show the active rules
leakhound install-hook         # block commits that contain secrets
```

Exit codes make it easy to use in scripts:

| Code | Meaning          |
| ---- | ---------------- |
| 0    | Nothing found    |
| 1    | Secrets found    |
| 2    | Something failed |

To silence a known false positive, put `leakhound:allow` in a comment on the
same line.

## Stop secrets before they are committed

```sh
leakhound install-hook
```

This writes a git pre-commit hook that runs `leakhound --staged`. A commit that
adds a secret is rejected before it exists, which is far cheaper than cleaning
it out of history afterwards. An existing hook from another tool is left alone
unless you pass `--force`, and `git commit --no-verify` skips the check for one
commit.

## Use it in GitHub Actions

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0 # full history
- uses: qtclover/leakhound@v0.2.0
```

The action downloads the release binary, verifies its checksum and scans the
checkout including history. The job fails if anything is found. It runs on
Linux x86_64 runners.

To show findings in the repository's Security tab instead, write SARIF and
upload it:

```yaml
- uses: qtclover/leakhound@v0.2.0
  continue-on-error: true
  with:
    args: --history --format sarif --output leakhound.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: leakhound.sarif
```

`--format sarif` writes SARIF 2.1.0. Each result carries a fingerprint that
stays the same when a secret moves to a different line, so GitHub tracks it as
one alert. The upload step needs the `security-events: write` permission.

## Check whether a secret is still live

```console
$ leakhound --verify
github-token  GitHub token
  deploy.sh:3:11
  secret   ghp_************J6  (entropy 5.07)
  verified inactive
```

With `--verify`, each finding is sent once to the service that issued it, using
a read-only "who am I" request, and labelled:

- **active**: the service accepted it. Revoke it now.
- **inactive**: the service rejected it.
- **unknown**: no clear answer, for example a rate limit or a network error.

Supported: GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, Discord bot tokens
and webhooks, Telegram, SendGrid and npm. Other findings are left unlabelled.

Verification is off by default because it makes network requests with the
secrets it found. A token for a self-hosted service such as a private GitLab
instance shows as inactive, because only the public service is asked.

## Configuration

Put a `leakhound.toml` (or `.leakhound.toml`) in the directory you scan, or
point at one with `--config`:

```toml
# Your own rules, alongside the built-in ones
[[rules]]
id = "acme-token"
description = "Acme internal API token"
regex = 'acme_[a-z0-9]{32}'

[[rules]]
id = "acme-pin"
regex = 'acme-pin=(\d{6})'
group = 1          # which capture group is the secret (default 0, the whole match)
min_entropy = 2.0  # optional: ignore matches less random than this

[allowlist]
paths = ["tests/fixtures/", "*.lock"]  # gitignore-style globs to skip
regexes = ['^AKIAIOSFODNN7']           # secrets matching these are ignored
rules = ["jwt"]                        # built-in rules to switch off
```

Path exclusions apply to files on disk, staged changes and history alike. A
mistake in the file (an unknown key, a regex that does not compile, a rule id
that is already taken) stops the scan with an error instead of being silently
ignored.

## What it detects

22 built-in rules, in two groups.

**Specific formats** are recognised by their shape alone: AWS access keys,
GitHub and GitLab tokens, Slack tokens and webhooks, Discord bot tokens and
webhooks, Stripe live keys, Google, Anthropic and OpenAI API keys, npm,
SendGrid, Twilio and Telegram tokens, JSON Web Tokens, and private key blocks.

**Generic rules** catch secrets with no recognisable format by looking at
context: a quoted string assigned to a name like `password` or `api_key`, an
upper-case environment variable such as `SESSION_SECRET=...`, or a password
embedded in a database URL. These would be noisy on their own, so a match only
counts if it:

- has high enough [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory))
  to look random rather than like a word or an identifier,
- is not an obvious placeholder (`your_api_key`, `${VAR}`, `changeme`, ...),
- was not already claimed by a specific rule.

## How it works

- **One pass per file.** All rules are compiled into a single `RegexSet`, so a
  file with no secrets (nearly all of them) is read once and dismissed. Only
  rules that the set says can match are then run individually to extract
  positions.
- **Bytes, not Unicode.** Matching is byte-oriented and ASCII-only, which lets
  the regex engine stay in its DFA. This one change made scanning about 22
  times faster than the first Unicode-aware version.
- **Parallel everywhere.** The directory walk and the scanning both run across
  all cores. `.gitignore` is respected by default, binary files and anything
  over 10 MB are skipped.
- **History without a git library.** `--history` streams
  `git log --all -p -U0` and parses the diff. With zero lines of context, each
  hunk is exactly one block of added text, so every line ever added is scanned
  once. Hunks are batched and scanned in parallel. A secret that appears in
  many commits is reported once, attributed to the oldest commit that added it.
  `--staged` reuses the same parser on `git diff --cached`.

## Performance

Measured on a 24-thread desktop with a warm file cache:

| Input                                                  | Time   |
| ------------------------------------------------------ | ------ |
| 461 MB of source in 41,556 files, 24 threads           | 0.17 s |
| The same, single thread (`-j1`)                        | 1.51 s |
| ripgrep: 218 files plus the history of 2,344 commits   | 0.41 s |

## Limitations

- Every rule matches within a single line, so a secret split across lines is
  missed.
- Without `--verify`, findings are pattern matches only, so expect the
  occasional false positive: mostly test keys and constants that happen to sit
  next to the word "secret".
- Merge commits are not diffed, so a secret introduced only by a merge
  resolution is not seen in history.
- Release binaries and the GitHub Action cover Linux x86_64 only. Other
  platforms build from source.

## Development

```sh
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

Test credentials are assembled at runtime so the repository never contains a
string that another scanner would flag. CI enforces this by scanning the
repository and its history with the binary it just built.

Pushing a `v*` tag builds the static binary and publishes a release.

## License

MIT
