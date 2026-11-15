use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use leakhound::config::Config;
use leakhound::filter::PathFilter;
use leakhound::scan::Scanner;
use leakhound::walk::{WalkOptions, scan_tree};
use leakhound::{baseline, git, hook, redact, report, verify};
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
#[command(name = "leakhound", version, args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    scan: ScanArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Install a git pre-commit hook that blocks commits containing secrets
    InstallHook {
        /// Repository to install the hook into
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Replace an existing pre-commit hook
        #[arg(long)]
        force: bool,
    },
}

#[derive(Args)]
struct ScanArgs {
    /// File or directory to scan
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Also scan every commit in the git history
    #[arg(long)]
    history: bool,

    /// Scan only the changes staged for the next commit
    #[arg(long, conflicts_with_all = ["history", "no_ignore"])]
    staged: bool,

    /// Output format
    #[arg(long, short, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Hide findings already listed in this saved JSON report
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Write the report to a file instead of standard output
    #[arg(long, short, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Ask the issuing service whether each secret still works (makes network requests)
    #[arg(long)]
    verify: bool,

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
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::InstallHook { path, force }) => install_hook(&path, force),
        None => run(cli.scan),
    };
    match result {
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

fn install_hook(path: &std::path::Path, force: bool) -> Result<bool> {
    let hook = hook::install(path, force)?;
    println!("installed pre-commit hook at {}", hook.display());
    Ok(false)
}

/// Returns whether any secrets were found.
fn run(cli: ScanArgs) -> Result<bool> {
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
    if (cli.history || cli.staged) && !cli.path.is_dir() {
        bail!("--history and --staged need a directory inside a git repository");
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
    let (mut findings, mut summary) = if cli.staged {
        let (findings, stats) = git::scan_staged(&cli.path, &scanner, &filter)?;
        let summary = format!(
            "scanned staged changes ({:.1} MB of added lines)",
            stats.bytes as f64 / 1e6
        );
        (findings, summary)
    } else {
        let opts = WalkOptions {
            no_ignore: cli.no_ignore,
            max_size: cli.max_size.saturating_mul(1 << 20),
            threads,
        };
        let (findings, stats) = scan_tree(&cli.path, &scanner, &filter, &opts)?;
        let summary = format!(
            "scanned {} files ({:.1} MB)",
            stats.files,
            stats.bytes as f64 / 1e6
        );
        (findings, summary)
    };

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
    if let Some(file) = &cli.baseline {
        let known = baseline::load(file)?;
        let before = findings.len();
        findings.retain(|f| !known.contains(&f.fingerprint));
        summary.push_str(&format!(
            ", {} known hidden by baseline",
            before - findings.len()
        ));
    }
    if cli.verify {
        let active = verify::verify_findings(&mut findings);
        summary.push_str(&format!(", {active} verified active"));
    }
    if !cli.show_secrets {
        for f in &mut findings {
            f.secret = redact(&f.secret);
        }
    }

    let color = cli.output.is_none() && std::io::stdout().is_terminal();
    let mut out: Box<dyn Write> = match &cli.output {
        Some(file) => Box::new(std::io::BufWriter::new(
            std::fs::File::create(file)
                .with_context(|| format!("could not write {}", file.display()))?,
        )),
        None => Box::new(std::io::stdout().lock()),
    };
    match cli.format {
        Format::Text => report::text(&mut out, &findings, color)?,
        Format::Json => {
            report::json(&mut out, &findings)?;
            writeln!(out)?;
        }
        Format::Sarif => {
            serde_json::to_writer_pretty(&mut out, &report::sarif(&findings, scanner.rules()))?;
            writeln!(out)?;
        }
    }

    out.flush()?;
    drop(out);

    eprintln!(
        "{summary} in {:.2}s, {} finding{}",
        started.elapsed().as_secs_f64(),
        findings.len(),
        if findings.len() == 1 { "" } else { "s" }
    );
    Ok(!findings.is_empty())
}
