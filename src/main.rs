use anyhow::{Context, Result, bail};
use cheval::config::{Config, Recheck, Repo};
use cheval::logo::{self, LogoMode};
use cheval::progress::{Level, Progress, format_line};
use cheval::status::{Hub, Reporter};
use cheval::sync::{self, SyncOptions};
use cheval::{bundle, daemon, headless, import, ingest, listen, probe, snapshot, status, tui, verify};
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
        /// No progress bar (on a terminal) or progress lines (in a log) on stderr
        #[arg(long)]
        no_progress: bool,
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
    /// Receiving end of a data diode: apply bundles from a drop folder as they arrive, in order
    Ingest {
        /// Folder the diode writes bundles into
        drop: PathBuf,
        /// Mirror directory to apply to [default: mirror_path from the configuration]
        #[arg(long)]
        to: Option<PathBuf>,
        /// Record and lock [default: <state>/ingest from the configuration, else /var/lib/cheval/ingest]
        #[arg(long)]
        state: Option<PathBuf>,
        /// Where applied bundles go [default: DROP/done]
        #[arg(long)]
        done: Option<PathBuf>,
        /// Where bundles that cannot be applied go, with a .reason file [default: DROP/failed]
        #[arg(long)]
        failed: Option<PathBuf>,
        /// Applied bundles kept in the done folder (0: delete once applied)
        #[arg(long, default_value_t = 3)]
        keep: usize,
        /// Seconds a bundle without a .sha256 file must stay unchanged before it is taken
        #[arg(long, value_name = "DURATION", default_value = "2m", value_parser = parse_duration)]
        settle: std::time::Duration,
        /// Only take bundles that have a .sha256 file
        #[arg(long)]
        require_checksum: bool,
        /// How long a bundle waits for a missing earlier one before it is applied anyway
        #[arg(long, value_name = "DURATION", default_value = "1h", value_parser = parse_duration)]
        gap_wait: std::time::Duration,
        /// After applying: off, quick (files present, right size) or full (hash everything)
        /// [default: quick with a configuration, off without]
        #[arg(long, value_enum)]
        verify: Option<ingest::VerifyAfter>,
        /// Do not remove files the sending side deleted
        #[arg(long)]
        keep_deleted: bool,
        /// One pass over the drop folder, then exit (for timers and scripts)
        #[arg(long)]
        once: bool,
        /// Seconds between looks at the drop folder
        #[arg(long, value_name = "DURATION", default_value = "30s", value_parser = parse_duration)]
        interval: std::time::Duration,
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
        /// Bundle only this repository (repeatable) [default: the whole mirror].
        /// Repositories that share a directory must be named together
        #[arg(long = "only", value_name = "NAME")]
        only: Vec<String>,
        /// Compress with zstd on all cores; LEVEL 1 (fastest) to 19 (smallest). Mirrors are mostly
        /// already-compressed packages, so expect only a few percent
        #[arg(long, value_name = "LEVEL", num_args = 0..=1, default_missing_value = "3")]
        compress: Option<i32>,
        /// Write hard-linked files as separate copies, for receivers older than cheval 0.6.2
        #[arg(long)]
        no_hard_links: bool,
        /// Do not write OUT.sha256 beside the bundle (`cheval ingest` uses it to know the
        /// bundle arrived complete)
        #[arg(long)]
        no_checksum_file: bool,
        /// No progress bar (on a terminal) or progress lines (in a log) on stderr
        #[arg(long)]
        no_progress: bool,
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
        /// No progress bar (on a terminal) or progress lines (in a log) on stderr
        #[arg(long)]
        no_progress: bool,
    },
}

#[derive(Subcommand)]
enum SnapCmd {
    /// Create a snapshot (default name: timestamp)
    Create {
        name: Option<String>,
        /// No progress bar (on a terminal) or progress lines (in a log) on stderr
        #[arg(long)]
        no_progress: bool,
    },
    List,
    Delete {
        name: String,
    },
}

/// "90", "90s", "5m", "2h", "1d" -> a duration.
fn parse_duration(s: &str) -> std::result::Result<std::time::Duration, String> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().map_err(|_| format!("{s:?}: expected a number with s, m, h or d"))?;
    let mult = match unit.trim() {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        u => return Err(format!("{s:?}: unknown unit {u:?} (use s, m, h or d)")),
    };
    Ok(std::time::Duration::from_secs(n * mult))
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
        Cmd::Ingest {
            drop,
            to,
            state,
            done,
            failed,
            keep,
            settle,
            require_checksum,
            gap_wait,
            verify,
            keep_deleted,
            once,
            interval,
        } => {
            // With --to and no --config, no configuration is read: one found by chance (in
            // /etc/cheval, say) could describe a different mirror.
            let cfg = if cli.config.is_some() || to.is_none() { Some(load_config(&cli.config)?) } else { None };
            if let (Some(c), Some(t)) = (&cfg, &to)
                && *t != c.global.mirror_path()
                && verify != Some(ingest::VerifyAfter::Off)
            {
                bail!(
                    "--to {} is not the mirror of {} ({}); verifying would check the wrong tree. \
                     Set base_path to match, or add --verify off",
                    t.display(),
                    cli.config.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
                    c.global.mirror_path().display()
                );
            }
            let dest = match (to, &cfg) {
                (Some(d), _) => d,
                (None, Some(c)) => c.global.mirror_path(),
                (None, None) => unreachable!(),
            };
            let state = state.unwrap_or_else(|| match &cfg {
                Some(c) => c.global.state_path().join("ingest"),
                None => PathBuf::from("/var/lib/cheval/ingest"),
            });
            let verify = verify.unwrap_or(if cfg.as_ref().is_some_and(|c| !c.repos.is_empty()) {
                ingest::VerifyAfter::Quick
            } else {
                ingest::VerifyAfter::Off
            });
            let opts = ingest::IngestOptions {
                done: done.unwrap_or_else(|| drop.join("done")),
                failed: failed.unwrap_or_else(|| drop.join("failed")),
                drop,
                dest,
                state,
                settle,
                require_checksum,
                gap_wait,
                keep_done: keep,
                keep_deleted,
                verify,
                once,
                interval,
            };
            let mut ing = ingest::Ingest::new(opts, cfg)?;
            Ok(if ing.run()? { 0 } else { 1 })
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
                if r.format != cheval::config::Format::Apt {
                    let trust = match (r.verify(g), &r.keyring, &r.metalink, r.format) {
                        (cheval::config::VerifyMode::Off, ..) => "off",
                        (_, Some(_), _, cheval::config::Format::Rpm) => "repomd.xml signature",
                        (_, _, Some(_), _) => "metalink",
                        (_, Some(_), _, _) if r.signature.is_some() => "signed checksum list",
                        _ => "NONE (HTTPS only)",
                    };
                    println!(
                        "  {:<24} format={}{}  verify={trust} clean={:?}",
                        r.name,
                        r.format,
                        if r.enabled { "" } else { "  (disabled)" },
                        r.clean(g)
                    );
                    for t in r.targets(g)? {
                        println!("      {:<22} {}\n      {:<22} -> {}", t.label, t.url, "", t.dir.display());
                    }
                    if r.format == cheval::config::Format::Files {
                        println!(
                            "      checksums [{}]{} include [{}]",
                            r.checksums.join(" "),
                            r.signature.as_ref().map(|s| format!(" signature {s}")).unwrap_or_default(),
                            if r.include.is_empty() { "everything listed".to_string() } else { r.include.join(" ") }
                        );
                    }
                    continue;
                }
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
                if r.format != cheval::config::Format::Apt {
                    for t in r.targets(g)? {
                        let rel = t.dir.strip_prefix(g.mirror_path()).unwrap_or(&t.dir).to_string_lossy().into_owned();
                        let url = format!("{base}/{rel}/");
                        if r.format == cheval::config::Format::Files {
                            println!("# {} {}: files (not a package repository) at {url}\n", r.name, t.label);
                            continue;
                        }
                        // A yum/dnf .repo stanza; save as /etc/yum.repos.d/<name>.repo.
                        let id: String = format!("{}-{}", r.name, t.label)
                            .chars()
                            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
                            .collect();
                        println!(
                            "[{id}]\nname={} {} (cheval mirror)\nbaseurl={url}\nenabled=1\ngpgcheck=1\n# gpgkey=file:///etc/pki/rpm-gpg/<key>\n",
                            r.name, t.label
                        );
                    }
                    continue;
                }
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
                SnapCmd::Create { name, no_progress } => {
                    snapshot::create_with(&cfg.global, name, cheval::meter::Progress::from_flag(no_progress))?;
                }
                SnapCmd::List => snapshot::list(&cfg.global)?,
                SnapCmd::Delete { name } => snapshot::delete(&cfg.global, &name)?,
            }
            Ok(0)
        }
        Cmd::Bundle { cmd } => {
            match cmd {
                BundleCmd::Create {
                    out,
                    full,
                    manifest,
                    only,
                    compress,
                    no_hard_links,
                    no_checksum_file,
                    no_progress,
                } => {
                    let cfg = load_config(&cli.config)?;
                    let opts = bundle::CreateOptions {
                        full,
                        manifest,
                        hard_links: !no_hard_links,
                        compress,
                        checksum_file: !no_checksum_file,
                        progress: cheval::meter::Progress::from_flag(no_progress),
                    };
                    bundle::create_with(&cfg, &only, &out, &opts)?;
                }
                BundleCmd::Apply { bundle: file, to, keep_deleted, no_progress } => {
                    // The run lock is held for the whole apply (it used to be released before
                    // the apply started, so a sync could run at the same time).
                    let (dest, _lock) = match to {
                        Some(d) => (d, None),
                        None => {
                            let cfg = load_config(&cli.config)?;
                            let lock = sync::lock(&cfg.global)?;
                            (cfg.global.mirror_path(), Some(lock))
                        }
                    };
                    let progress =
                        if no_progress { cheval::meter::Progress::Off } else { cheval::meter::Progress::Auto };
                    bundle::apply_with(&file, &dest, keep_deleted, progress)?;
                }
            }
            Ok(0)
        }
        Cmd::Verify { full, only, no_progress } => {
            let cfg = load_config(&cli.config)?;
            Ok(if verify::run_with(&cfg, &only, full, cheval::meter::Progress::from_flag(no_progress))? {
                0
            } else {
                1
            })
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
            // Report the result as soon as the run ends, not when the TUI is closed: a
            // receiver must not show RUNNING while the summary sits on screen.
            if let Some((hub, reporter)) = reporting {
                let error = r.as_ref().err().map(|e| format!("{e:#}"));
                reporter.finish_with(r.as_ref().ok(), error).await;
                hub.close(Duration::from_secs(2)).await;
            }
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
