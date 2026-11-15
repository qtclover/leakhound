use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use leakhound::config::Config;
use leakhound::filter::PathFilter;
use leakhound::scan::Scanner;
use leakhound::walk::{WalkOptions, scan_tree};
use leakhound::{git, redact, report};
use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    /// For GitHub code scanning and other SARIF consumers
    Sarif,
}

/// Find leaked credentials in a directory and, optionally, its git history.
///
/// Exits with 0 when nothing is found, 1 when secrets are found, and 2 on error.
#[derive(Parser)]
#[command(name = "leakhound", version)]
struct Cli {
    /// File or directory to scan
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Also scan every commit in the git history
    #[arg(long)]
    history: bool,

    /// Output format
    #[arg(long, short, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Print secrets in full instead of redacting them
    #[arg(long)]
    show_secrets: bool,

    /// Scan files that .gitignore would normally hide
    #[arg(long)]
    no_ignore: bool,

    /// Skip paths matching this glob (repeatable)
    #[arg(long, short = 'x', value_name = "GLOB")]
    exclude: Vec<String>,

    /// Skip files larger than this many megabytes
    #[arg(long, value_name = "MB", default_value_t = 10)]
    max_size: u64,

    /// Worker threads (default: one per CPU core)
    #[arg(long, short = 'j', value_name = "N")]
    threads: Option<usize>,

    /// Rules and allowlists file (default: leakhound.toml in the scanned directory)
    #[arg(long, short, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Print the active rules and exit
    #[arg(long)]
    list_rules: bool,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::from(1),
        Ok(false) => ExitCode::SUCCESS,
        // Output was piped into something like `head` that stopped reading.
        Err(err) if is_broken_pipe(&err) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("leakhound: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        let io = cause
            .downcast_ref::<std::io::Error>()
            .map(|e| e.kind())
            .or_else(|| {
                cause
                    .downcast_ref::<serde_json::Error>()
                    .and_then(|e| e.io_error_kind())
            });
        io == Some(std::io::ErrorKind::BrokenPipe)
    })
}

/// Returns whether any secrets were found.
fn run(cli: Cli) -> Result<bool> {
    if !cli.path.exists() {
        bail!("{} does not exist", cli.path.display());
    }
    let config = match cli.config.clone().or_else(|| Config::find(&cli.path)) {
        Some(file) => Config::load(&file)?,
        None => Config::default(),
    };
    let scanner = Scanner::with_config(&config)?;
    if cli.list_rules {
        let rules = scanner.rules();
        let width = rules.iter().map(|r| r.id.len()).max().unwrap_or(0);
        let mut out = std::io::stdout().lock();
        for rule in rules {
            writeln!(out, "{:width$}  {}", rule.id, rule.description)?;
        }
        return Ok(false);
    }
    if cli.history && !cli.path.is_dir() {
        bail!("--history needs a directory inside a git repository");
    }

    let threads = cli
        .threads
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
        .max(1);
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;

    let started = Instant::now();
    let mut excluded = cli.exclude;
    excluded.extend(config.allow_paths);
    let filter = PathFilter::new(&cli.path, excluded)?;
    let opts = WalkOptions {
        no_ignore: cli.no_ignore,
        max_size: cli.max_size.saturating_mul(1 << 20),
        threads,
    };
    let (mut findings, walk_stats) = scan_tree(&cli.path, &scanner, &filter, &opts)?;
    let mut summary = format!(
        "scanned {} files ({:.1} MB)",
        walk_stats.files,
        walk_stats.bytes as f64 / 1e6
    );

    if cli.history {
        let (history, stats) = git::scan_history(&cli.path, &scanner, &filter)?;
        summary.push_str(&format!(
            " and {} commits ({:.1} MB of added lines)",
            stats.commits,
            stats.bytes as f64 / 1e6
        ));

        // A secret still on disk is reported once, as a worktree finding that
        // remembers which commit introduced it. Anything left over exists only
        // in history.
        let mut on_disk: HashMap<(String, String, String), Vec<usize>> = HashMap::new();
        for (i, f) in findings.iter().enumerate() {
            on_disk
                .entry((f.rule.clone(), f.path.clone(), f.secret.clone()))
                .or_default()
                .push(i);
        }
        let mut history_only = Vec::new();
        for f in history {
            match on_disk.get(&(f.rule.clone(), f.path.clone(), f.secret.clone())) {
                Some(indexes) => {
                    for &i in indexes {
                        findings[i].commit = f.commit.clone();
                    }
                }
                None => history_only.push(f),
            }
        }
        findings.extend(history_only);
    }

    findings.sort_by(|a, b| {
        (&a.path, a.line, a.column, &a.rule).cmp(&(&b.path, b.line, b.column, &b.rule))
    });
    if !cli.show_secrets {
        for f in &mut findings {
            f.secret = redact(&f.secret);
        }
    }

    let mut out = std::io::stdout().lock();
    match cli.format {
        Format::Text => report::text(&mut out, &findings, std::io::stdout().is_terminal())?,
        Format::Json => {
            report::json(&mut out, &findings)?;
            writeln!(out)?;
        }
        Format::Sarif => {
            serde_json::to_writer_pretty(&mut out, &report::sarif(&findings, scanner.rules()))?;
            writeln!(out)?;
        }
    }

    eprintln!(
        "{summary} in {:.2}s, {} finding{}",
        started.elapsed().as_secs_f64(),
        findings.len(),
        if findings.len() == 1 { "" } else { "s" }
    );
    Ok(!findings.is_empty())
}
