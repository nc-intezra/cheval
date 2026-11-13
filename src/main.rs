use anyhow::{Context, Result, bail};
use cheval::config::{Config, Recheck, Repo};
use cheval::logo::{self, LogoMode};
use cheval::progress::{Level, Progress, format_line};
use cheval::status::{Hub, Reporter};
use cheval::sync::{self, SyncOptions};
use cheval::{bundle, daemon, headless, import, listen, probe, snapshot, status, tui, verify};
use clap::{Parser, Subcommand};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(name = "cheval", version, about = "Consistent, verified APT repository mirroring with a TUI")]
struct Cli {
    /// Configuration file [default: $CHEVAL_CONFIG, ./cheval.toml, /etc/cheval/cheval.toml]
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,
    /// Logo: auto (UTF-8 locale -> Unicode, else ASCII), unicode, ascii or off [env: CHEVAL_LOGO]
    #[arg(long, global = true, value_enum, value_name = "MODE")]
    logo: Option<LogoMode>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Mirror the configured repositories
    Sync {
        /// Plain log output instead of the TUI (automatic when not on a terminal)
        #[arg(long)]
        no_tui: bool,
        /// Fetch indices and report what would be downloaded; publish nothing
        #[arg(long)]
        dry_run: bool,
        /// How to treat files already present: size (default) or hash
        #[arg(long, value_enum)]
        recheck: Option<Recheck>,
        /// Only these repositories (repeatable)
        #[arg(long = "only", value_name = "NAME")]
        only: Vec<String>,
        /// Do not remove obsolete files this run
        #[arg(long)]
        no_clean: bool,
        /// Clean even above clean_max_percent
        #[arg(long)]
        force_clean: bool,
        /// Leave the TUI as soon as the run finishes
        #[arg(long)]
        exit_when_done: bool,
        /// Log retries and per-index details
        #[arg(short, long)]
        verbose: bool,
    },
    /// Check the local mirror offline against its signed indices
    Verify {
        /// Re-hash every package file (default: presence and size)
        #[arg(long)]
        full: bool,
        #[arg(long = "only", value_name = "NAME")]
        only: Vec<String>,
    },
    /// Inspect an unknown repository URL and print a suggested configuration
    Probe {
        url: String,
        /// Suites to look for (default: auto-discover)
        suites: Vec<String>,
        /// User agent to send ("apt" impersonates apt)
        #[arg(long)]
        user_agent: Option<String>,
        #[arg(long)]
        username: Option<String>,
        /// Environment variable holding the password or token
        #[arg(long)]
        password_env: Option<String>,
        /// Send the secret as a Bearer token
        #[arg(long)]
        bearer: bool,
    },
    /// Convert sources.list / *.sources / apt-mirror mirror.list / Refrapt config to cheval TOML
    Import {
        files: Vec<PathBuf>,
        #[arg(long)]
        base_path: Option<String>,
        #[arg(long, default_value = "amd64")]
        arch: String,
    },
    /// Print apt sources for clients of this mirror
    Sources {
        /// URL under which mirror_path is served, e.g. http://mirror.lan
        #[arg(long)]
        base_url: String,
        /// Emit deb822 (.sources) instead of one-line format
        #[arg(long)]
        deb822: bool,
    },
    /// Hard-linked point-in-time snapshots of the mirror
    Snapshot {
        #[command(subcommand)]
        cmd: SnapCmd,
    },
    /// Carry the mirror across an air gap as (incremental) tar bundles
    Bundle {
        #[command(subcommand)]
        cmd: BundleCmd,
    },
    /// Validate the configuration and show what would be mirrored where
    Check,
    /// Print an annotated example configuration
    Example,
    /// Run syncs on the configured schedule; keep the status streams and HTTP API up between runs
    Daemon {
        /// Start a run immediately, then follow the schedule
        #[arg(long)]
        run_on_start: bool,
    },
    /// Receive the status stream on the far side of a data diode
    Status {
        #[command(subcommand)]
        cmd: StatusCmd,
    },
    /// Show the logo, version and build target
    #[command(alias = "about")]
    Version,
}

#[derive(Subcommand)]
enum StatusCmd {
    /// Listen for status messages, show progress and serve the read-only HTTP API.
    /// Needs no configuration file
    Listen {
        /// Where to receive: udp://ADDRESS:PORT, or tcp://ADDRESS:PORT behind a diode TCP proxy
        #[arg(default_value = "udp://0.0.0.0:5515")]
        url: String,
        /// Serve the HTTP API here, e.g. 127.0.0.1:8611
        #[arg(long, value_name = "ADDRESS:PORT")]
        http: Option<std::net::SocketAddr>,
        /// File with the Bearer token HTTP clients must send (required for non-loopback --http)
        #[arg(long, value_name = "FILE")]
        token_file: Option<PathBuf>,
        /// Pass every accepted message on to this udp://HOST:PORT (repeatable)
        #[arg(long, value_name = "URL")]
        forward: Vec<String>,
        /// Shared secret: accept only messages signed with it (the sink's hmac_key_file)
        #[arg(long, value_name = "FILE")]
        hmac_key_file: Option<PathBuf>,
        /// Report the sender as stale after this many seconds of silence
        #[arg(long, default_value_t = 180, value_name = "SECONDS")]
        stale_after: u64,
        /// Print status lines instead of the TUI (automatic when not on a terminal)
        #[arg(long)]
        no_tui: bool,
    },
}

#[derive(Subcommand)]
enum BundleCmd {
    /// Pack everything that changed since the previous bundle into a tar file
    Create {
        out: PathBuf,
        /// Ignore the manifest and pack the complete mirror
        #[arg(long)]
        full: bool,
        /// Manifest file to diff against and update [default: <state>/bundle-manifest.tsv].
        /// Use one manifest per destination site.
        #[arg(long)]
        manifest: Option<PathBuf>,
    },
    /// Unpack a bundle into the mirror directory of this (offline) side
    Apply {
        bundle: PathBuf,
        /// Target directory [default: mirror_path from the configuration]
        #[arg(long)]
        to: Option<PathBuf>,
        /// Do not remove files that were deleted on the sending side
        #[arg(long)]
        keep_deleted: bool,
    },
}

#[derive(Subcommand)]
enum SnapCmd {
    /// Create a snapshot (default name: timestamp)
    Create {
        name: Option<String>,
    },
    List,
    Delete {
        name: String,
    },
}

fn load_config(path: &Option<PathBuf>) -> Result<Config> {
    let candidates: Vec<PathBuf> = match path {
        Some(p) => vec![p.clone()],
        None => std::env::var_os("CHEVAL_CONFIG")
            .map(PathBuf::from)
            .into_iter()
            .chain(["cheval.toml".into(), "/etc/cheval/cheval.toml".into()])
            .collect(),
    };
    for c in &candidates {
        if c.exists() {
            return Config::load(c);
        }
    }
    bail!(
        "no configuration file found (looked for {}). Create one with `cheval example > cheval.toml`.",
        candidates.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
    )
}

fn main() {
    let cli = Cli::parse();
    let code = match real_main(cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cheval: error: {e:#}");
            2
        }
    };
    std::process::exit(code);
}

fn real_main(cli: Cli) -> Result<i32> {
    match cli.cmd {
        Cmd::Example => {
            print!("{}", cheval::config::EXAMPLE);
            Ok(0)
        }
        Cmd::Daemon { run_on_start } => {
            let cfg = load_config(&cli.config)?;
            let run_on_start = run_on_start || cfg.daemon.run_on_start;
            let path = cli.config.clone();
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            rt.block_on(daemon::run(cfg, move || load_config(&path), run_on_start, CancellationToken::new()))?;
            rt.shutdown_timeout(Duration::from_secs(2));
            Ok(0)
        }
        Cmd::Status {
            cmd: StatusCmd::Listen { url, http, token_file, forward, hmac_key_file, stale_after, no_tui },
        } => {
            if stale_after == 0 {
                bail!("--stale-after must be at least 1 second");
            }
            let use_tui = !no_tui && std::io::stdout().is_terminal() && std::io::stdin().is_terminal();
            let opts = listen::Options {
                listen: url.clone(),
                http,
                token: cheval::config::read_secret(None, token_file.as_deref(), "--token-file")?,
                forward,
                hmac_key: hmac_key_file.as_deref().map(status::read_key).transpose()?,
                stale_after: Duration::from_secs(stale_after),
                print: !use_tui,
            };
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            let listener = rt.block_on(listen::bind(opts))?;
            let store = listener.store.clone();
            let signed = if hmac_key_file.is_some() { "signed messages only" } else { "unsigned messages accepted" };
            eprintln!("cheval status: listening on {url} ({signed})");
            if let Some(a) = listener.http_local {
                eprintln!("cheval status: HTTP API on http://{a}");
            }
            let stop = CancellationToken::new();
            let task = rt.spawn(listener.run(stop.clone()));
            if use_tui {
                listen::tui(store, &url, logo::resolve(cli.logo)).context("terminal UI")?;
            } else {
                rt.block_on(async {
                    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {}
                        _ = async { match term.as_mut() { Some(t) => { t.recv().await; } None => std::future::pending().await } } => {}
                    }
                });
            }
            stop.cancel();
            let _ = rt.block_on(task);
            rt.shutdown_timeout(Duration::from_secs(1));
            Ok(0)
        }
        Cmd::Version => {
            for l in logo::about(logo::resolve(cli.logo)) {
                println!("{l}");
            }
            println!("cheval {} ({}-{})", logo::VERSION, std::env::consts::ARCH, std::env::consts::OS);
            println!("{}", logo::TAGLINE);
            println!("{}", env!("CARGO_PKG_REPOSITORY"));
            Ok(0)
        }
        Cmd::Import { files, base_path, arch } => {
            if files.is_empty() {
                bail!(
                    "give at least one file, e.g. /etc/apt/sources.list /etc/apt/sources.list.d/* or /etc/apt/mirror.list"
                );
            }
            let mut imp = import::Imported::default();
            for f in &files {
                if f.is_file() {
                    imp.parse_file(f)?;
                }
            }
            if imp.is_empty() {
                bail!("no repository definitions found in the given files");
            }
            print!("{}", imp.to_toml(base_path.as_deref(), &arch));
            Ok(0)
        }
        Cmd::Probe { url, suites, user_agent, username, password_env, bearer } => {
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            let ok =
                rt.block_on(probe::run(probe::ProbeArgs { url, suites, user_agent, username, password_env, bearer }))?;
            Ok(if ok { 0 } else { 1 })
        }
        Cmd::Check => {
            let cfg = load_config(&cli.config)?;
            let g = &cfg.global;
            println!("configuration OK: {} repositories, mirror at {}", cfg.repos.len(), g.mirror_path().display());
            for r in &cfg.repos {
                println!(
                    "  {:<24} {}{}\n      -> {}\n      suites [{}] components [{}] architectures [{}]{} verify={} clean={:?}",
                    r.name,
                    r.base_url()?,
                    if r.enabled { "" } else { "  (disabled)" },
                    r.root(g)?.display(),
                    r.suites.join(" "),
                    r.components.join(" "),
                    r.architectures(g).join(" "),
                    if r.source(g) { " +source" } else { "" },
                    match (r.verify(g), &r.keyring) {
                        (cheval::config::VerifyMode::Off, _) => "off",
                        (_, Some(_)) => "signature",
                        (_, None) => "NONE (no keyring)",
                    },
                    r.clean(g),
                );
            }
            if let Some(s) = &cfg.daemon.schedule {
                println!("daemon schedule: {s}{}", if cfg.daemon.run_on_start { " (and at start)" } else { "" });
            }
            for k in &cfg.status.sinks {
                println!(
                    "status sink: {} ({}{}{})",
                    k.url,
                    if k.format == cheval::config::SinkFormat::Json { "json" } else { "syslog" },
                    if k.repeat > 1 { format!(", sent {} times", k.repeat) } else { String::new() },
                    if k.hmac_key_file.is_some() { ", signed" } else { "" },
                );
                if let Some(f) = &k.hmac_key_file {
                    status::read_key(f)?;
                }
            }
            if let Some(h) = &cfg.status.http {
                println!(
                    "status HTTP API (daemon): http://{}{}",
                    h.addr()?,
                    if h.token()?.is_some() { " (bearer token required)" } else { "" }
                );
            }
            Ok(0)
        }
        Cmd::Sources { base_url, deb822 } => {
            let cfg = load_config(&cli.config)?;
            let g = &cfg.global;
            let base = base_url.trim_end_matches('/');
            for r in cfg.repos.iter().filter(|r| r.enabled) {
                let root = r.root(g)?;
                let rel = root.strip_prefix(g.mirror_path()).unwrap_or(&root).to_string_lossy().into_owned();
                let url = format!("{base}/{rel}");
                let archs = r.architectures(g).join(",");
                let comps = r.components.join(" ");
                if deb822 {
                    let flat = r.suites.iter().all(|s| Repo::is_flat(s));
                    println!(
                        "# {}\nTypes: deb{}\nURIs: {url}\nSuites: {}",
                        r.name,
                        if r.source(g) { " deb-src" } else { "" },
                        r.suites.join(" ")
                    );
                    if !flat {
                        println!("Components: {comps}");
                    }
                    if !archs.is_empty() {
                        println!("Architectures: {}", r.architectures(g).join(" "));
                    }
                    println!("# Signed-By: /usr/share/keyrings/<key>.gpg\n");
                } else {
                    println!("# {}", r.name);
                    for s in &r.suites {
                        let c = if Repo::is_flat(s) { "" } else { comps.as_str() };
                        if !archs.is_empty() {
                            println!("deb [arch={archs}] {url} {s} {c}");
                        }
                        if r.source(g) {
                            println!("deb-src {url} {s} {c}");
                        }
                    }
                }
            }
            Ok(0)
        }
        Cmd::Snapshot { cmd } => {
            let cfg = load_config(&cli.config)?;
            match cmd {
                SnapCmd::Create { name } => {
                    snapshot::create(&cfg.global, name)?;
                }
                SnapCmd::List => snapshot::list(&cfg.global)?,
                SnapCmd::Delete { name } => snapshot::delete(&cfg.global, &name)?,
            }
            Ok(0)
        }
        Cmd::Bundle { cmd } => {
            match cmd {
                BundleCmd::Create { out, full, manifest } => {
                    let cfg = load_config(&cli.config)?;
                    bundle::create(&cfg.global, &out, full, manifest)?;
                }
                BundleCmd::Apply { bundle: file, to, keep_deleted } => {
                    let dest = match to {
                        Some(d) => d,
                        None => {
                            let cfg = load_config(&cli.config)?;
                            let _lock = sync::lock(&cfg.global)?;
                            cfg.global.mirror_path()
                        }
                    };
                    bundle::apply(&file, &dest, keep_deleted)?;
                }
            }
            Ok(0)
        }
        Cmd::Verify { full, only } => {
            let cfg = load_config(&cli.config)?;
            Ok(if verify::run(&cfg, &only, full)? { 0 } else { 1 })
        }
        Cmd::Sync { no_tui, dry_run, recheck, only, no_clean, force_clean, exit_when_done, verbose } => {
            let cfg = Arc::new(load_config(&cli.config)?);
            if cfg.repos.is_empty() {
                bail!("the configuration defines no [[repo]] entries");
            }
            let opts = SyncOptions { dry_run, recheck, only, no_clean, force_clean };
            run_sync(cfg, opts, no_tui, exit_when_done, verbose, logo::resolve(cli.logo))
        }
    }
}

fn run_sync(
    cfg: Arc<Config>,
    opts: SyncOptions,
    no_tui: bool,
    exit_when_done: bool,
    verbose: bool,
    logo: logo::Charset,
) -> Result<i32> {
    let names: Vec<String> = cfg.repos.iter().map(|r| r.name.clone()).collect();
    let progress = Progress::new(&names);
    progress.verbose.store(verbose, Ordering::Relaxed);
    let log_dir = cfg.global.base_path.join("log");
    std::fs::create_dir_all(&log_dir).with_context(|| format!("creating {}", log_dir.display()))?;
    if let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(log_dir.join("cheval.log")) {
        progress.set_logfile(f);
    }
    let use_tui = !no_tui && std::io::stdout().is_terminal() && std::io::stdin().is_terminal();
    progress.echo.store(!use_tui, Ordering::Relaxed);

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let cancel = CancellationToken::new();
    {
        let (cancel, progress) = (cancel.clone(), progress.clone());
        rt.spawn(async move {
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = async { match term.as_mut() { Some(t) => { t.recv().await; } None => std::future::pending().await } } => {}
            }
            progress.warn(None, "signal received — stopping cleanly");
            cancel.cancel();
        });
    }
    progress.info(
        None,
        format!("cheval {} starting{}", env!("CARGO_PKG_VERSION"), if opts.dry_run { " (dry run)" } else { "" }),
    );
    // Status streams (if configured) report this run too; they never slow it down.
    let reporting = if cfg.status.sinks.is_empty() {
        None
    } else {
        let _in_runtime = rt.enter();
        let hub = Hub::new(&cfg.status)?;
        Some((hub.clone(), Reporter::spawn(hub, progress.clone(), opts.dry_run)))
    };
    let engine = {
        let (cfg, progress, cancel) = (cfg.clone(), progress.clone(), cancel.clone());
        rt.spawn(async move {
            let r = sync::run(cfg, opts, progress.clone(), cancel).await;
            if let Err(e) = &r {
                progress.error(None, format!("{e:#}"));
            }
            progress.finished.store(true, Ordering::Relaxed);
            r
        })
    };
    if use_tui {
        let title = format!("{} → {}", cfg.global.base_path.display(), cfg.global.mirror_path().display());
        tui::run(progress.clone(), cancel.clone(), &title, exit_when_done, logo).context("terminal UI")?;
        if !progress.finished.load(Ordering::Relaxed) {
            cancel.cancel();
        }
    } else {
        rt.spawn(headless::report(progress.clone(), Duration::from_secs(10)));
    }
    let result = rt.block_on(engine)?;
    if let Some((hub, reporter)) = reporting {
        let error = result.as_ref().err().map(|e| format!("{e:#}"));
        rt.block_on(async {
            reporter.finish_with(result.as_ref().ok(), error).await;
            hub.close(Duration::from_secs(2)).await;
        });
    }
    rt.shutdown_timeout(Duration::from_secs(2));
    if use_tui {
        // Leave the important lines in the terminal scrollback.
        for l in progress.logs_snapshot(Level::Warn).iter().rev().take(40).rev() {
            eprintln!("{}", format_line(l));
        }
    }
    let summary = result?;
    print!("{}", summary.render());
    println!("  log: {}", log_dir.join("cheval.log").display());
    Ok(if summary.cancelled {
        130
    } else if summary.success() {
        0
    } else {
        1
    })
}
