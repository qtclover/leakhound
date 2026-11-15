# leakhound

A fast secret scanner for source trees and git history, written in Rust.

It finds API keys, tokens, private keys and passwords that were committed by
mistake, including ones that were later deleted but are still sitting in the
repository's history.

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

```sh
cargo install --path .
```

Requires a recent stable Rust toolchain. `--history` also needs `git` on your
`PATH`.

## Usage

```sh
leakhound                      # scan the current directory
leakhound path/to/repo         # scan somewhere else
leakhound --history            # also scan every commit on every branch
leakhound --format json        # machine-readable output
leakhound -x 'tests/fixtures/' # skip paths matching a glob (repeatable)
leakhound --no-ignore          # include files hidden by .gitignore
leakhound --show-secrets       # print secrets in full instead of redacted
leakhound --list-rules         # show the built-in rules
```

Exit codes make it easy to use in CI or a pre-commit hook:

| Code | Meaning          |
| ---- | ---------------- |
| 0    | Nothing found    |
| 1    | Secrets found    |
| 2    | Something failed |

To silence a known false positive, put `leakhound:allow` in a comment on the
same line.

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

## Performance

Measured on a 24-thread desktop with a warm file cache:

| Input                                                  | Time   |
| ------------------------------------------------------ | ------ |
| 445 MB of source in 40,275 files, 24 threads           | 0.14 s |
| The same, single thread (`-j1`)                        | 1.46 s |
| ripgrep: 218 files plus the history of 2,344 commits   | 0.81 s |

## Limitations

- Rules are compiled in; there is no config file for custom rules yet.
- Every rule matches within a single line, so a secret split across lines is
  missed.
- Findings are pattern matches. Nothing is verified against the issuing
  service, so expect the occasional false positive, mostly test keys and
  constants that happen to sit next to the word "secret".
- Merge commits are not diffed, so a secret introduced only by a merge
  resolution is not seen in history.

## Development

```sh
cargo test
```

Test credentials are assembled at runtime so the repository never contains a
string that another scanner would flag.

## License

MIT
