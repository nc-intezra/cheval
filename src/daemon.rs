//! `cheval daemon`: runs syncs on a schedule and keeps the status streams and the HTTP API
//! up between runs. The sync itself is the same engine `cheval sync` uses.
use crate::config::{Config, Repo};
use crate::progress::Progress;
pub use crate::schedule::Schedule;
use crate::status::{Body, EndMsg, EventMsg, HeartbeatMsg, Hub, LastRun, RepoMsg, Reporter, now_ts};
use crate::sync::{self, SyncOptions};
use anyhow::{Context, Result};
use chrono::{DateTime, Local, SecondsFormat, Utc};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

// ----------------------------------------------------------------------- mirror freshness

/// Age in seconds of the oldest published Release file of a repository, read from the local
/// mirror. `None` when nothing has been published yet.
pub fn release_age(cfg: &Config, repo: &Repo) -> Option<u64> {
    let root = repo.root(&cfg.global).ok()?;
    let mut oldest: Option<DateTime<Utc>> = None;
    for suite in &repo.suites {
        let dir = root.join(Repo::dist_dir(suite).ok()?);
        let text = ["InRelease", "Release"].iter().find_map(|f| std::fs::read(dir.join(f)).ok())?;
        let head = String::from_utf8_lossy(&text[..text.len().min(16_384)]).into_owned();
        let date = head.lines().find_map(|l| l.strip_prefix("Date:")).and_then(crate::release::parse_date)?;
        oldest = Some(oldest.map_or(date, |o| o.min(date)));
    }
    oldest.map(|d| (Utc::now() - d).num_seconds().max(0) as u64)
}

fn last_run_from_state(cfg: &Config) -> Option<LastRun> {
    let text = std::fs::read(cfg.global.state_path().join("last-run.json")).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&text).ok()?;
    let end: EndMsg = serde_json::from_value(v.get("end")?.clone()).ok()?;
    let finished = v.get("finished_at")?.as_str()?;
    let finished_at = DateTime::parse_from_rfc3339(finished)
        .map(|d| d.with_timezone(&Utc).to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_else(|_| finished.to_string());
    Some(LastRun {
        run: String::new(),
        state: end.state,
        exit_code: end.exit_code,
        finished_at,
        repos_ok: end.repos_ok,
        repos_failed: end.repos_failed,
    })
}

// -------------------------------------------------------------------------------- daemon

fn say(msg: impl AsRef<str>) {
    eprintln!("{} cheval daemon: {}", Local::now().format("%Y-%m-%d %H:%M:%S"), msg.as_ref());
}

fn event(hub: &Hub, level: &str, text: impl Into<String>) {
    let text = text.into();
    say(&text);
    hub.emit(Body::Event(EventMsg { level: level.into(), kind: "daemon".into(), repo: String::new(), text }));
}

/// One sync run, reported through the hub. Returns the result that was sent as `end`.
pub async fn run_once(cfg: Arc<Config>, hub: Arc<Hub>, opts: SyncOptions, stop: CancellationToken) -> (String, EndMsg) {
    let names: Vec<String> = cfg.repos.iter().map(|r| r.name.clone()).collect();
    let progress = Progress::new(&names);
    progress.echo.store(true, Ordering::Relaxed);
    let log_dir = cfg.global.base_path.join("log");
    if std::fs::create_dir_all(&log_dir).is_ok()
        && let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(log_dir.join("cheval.log"))
    {
        progress.set_logfile(f);
    }
    progress.info(None, format!("cheval {} starting (daemon)", env!("CARGO_PKG_VERSION")));
    let reporter = Reporter::spawn(hub, progress.clone(), opts.dry_run);
    let run = reporter.run.clone();
    let result = sync::run(cfg, opts, progress.clone(), stop).await.map_err(|e| format!("{e:#}"));
    match &result {
        Ok(summary) => eprint!("{}", summary.render()),
        Err(e) => progress.error(None, e.clone()),
    }
    progress.finished.store(true, Ordering::Relaxed);
    (run, reporter.finish(&result).await)
}

struct Idle {
    cursor: usize,
}

impl Idle {
    /// "Alive and idle", plus a few repositories so a receiver that joined late fills in.
    async fn heartbeat(
        &mut self,
        hub: &Arc<Hub>,
        cfg: &Arc<Config>,
        last: &Option<LastRun>,
        next: Option<DateTime<Local>>,
    ) {
        let c = cfg.clone();
        let ages: Vec<Option<u64>> =
            tokio::task::spawn_blocking(move || c.repos.iter().map(|r| release_age(&c, r)).collect())
                .await
                .unwrap_or_default();
        hub.emit(Body::Heartbeat(HeartbeatMsg {
            state: "idle".into(),
            uptime_s: hub.uptime().as_secs(),
            last_run: last.clone(),
            next_run: next.map(|n| n.to_rfc3339_opts(SecondsFormat::Secs, false)),
            oldest_release_age_s: ages.iter().flatten().max().copied(),
            repos_total: cfg.repos.len() as u64,
            dropped: hub.dropped(),
        }));
        let n = cfg.repos.len();
        for _ in 0..n.min(4) {
            self.cursor = (self.cursor + 1) % n;
            let name = &cfg.repos[self.cursor].name;
            let mut body = match hub.store.repo(name).map(|m| m.body) {
                Some(Body::Repo(r)) => r,
                _ => RepoMsg { name: name.clone(), phase: "unknown".into(), ..Default::default() },
            };
            body.release_age_s = ages.get(self.cursor).copied().flatten();
            hub.emit(Body::Repo(body));
        }
    }
}

/// Run until `stop` is cancelled (SIGINT and SIGTERM cancel it too).
///
/// `load` re-reads the configuration before every run, so repository changes need no restart;
/// sinks, the HTTP listener and the schedule are fixed at start.
pub async fn run(
    cfg: Config,
    load: impl Fn() -> Result<Config> + Send + Sync,
    run_on_start: bool,
    stop: CancellationToken,
) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut cfg = Arc::new(cfg);
    let schedule = match &cfg.daemon.schedule {
        Some(s) => Some(Schedule::parse(s).context("daemon.schedule")?),
        None => None,
    };
    let hub = Hub::new(&cfg.status)?;
    if let Some(h) = &cfg.status.http {
        let addr = h.addr()?;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("status.http: cannot listen on {addr}"))?;
        say(format!("HTTP API on http://{}", listener.local_addr().unwrap_or(addr)));
        tokio::spawn(crate::api::serve(listener, hub.store.clone(), h.token()?, stop.clone()));
    }
    let mut usr1 = signal(SignalKind::user_defined1()).context("installing the SIGUSR1 handler")?;
    let mut term = signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
    let mut int = signal(SignalKind::interrupt()).context("installing the SIGINT handler")?;
    {
        let stop = stop.clone();
        tokio::spawn(async move {
            tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
            say("signal received: stopping cleanly");
            stop.cancel();
        });
    }

    let started = Local::now();
    let mut last_start = started;
    let mut last = last_run_from_state(&cfg);
    let mut idle = Idle { cursor: 0 };
    let mut run_now = run_on_start;
    event(
        &hub,
        "info",
        format!(
            "daemon started (cheval {}), schedule: {}, {} status sink(s)",
            env!("CARGO_PKG_VERSION"),
            cfg.daemon.schedule.as_deref().unwrap_or("none, runs on SIGUSR1 only"),
            cfg.status.sinks.len()
        ),
    );

    while !stop.is_cancelled() {
        let next = schedule.as_ref().map(|s| s.next(Local::now(), last_start));
        if !run_now {
            // A manual `cheval sync` between daemon runs counts as the last run too.
            if let Some(disk) = last_run_from_state(&cfg)
                && last.as_ref().is_none_or(|l| disk.finished_at > l.finished_at)
            {
                last = Some(disk);
            }
            idle.heartbeat(&hub, &cfg, &last, next).await;
            let until_run = next.map(|n| (n - Local::now()).to_std().unwrap_or_default());
            let nap = until_run.map_or(hub.heartbeat, |u| u.min(hub.heartbeat));
            tokio::select! {
                _ = stop.cancelled() => break,
                _ = usr1.recv() => {
                    event(&hub, "info", "run requested by SIGUSR1");
                    run_now = true;
                }
                _ = tokio::time::sleep(nap) => {
                    run_now = next.is_some_and(|n| Local::now() >= n);
                }
            }
            if !run_now {
                continue;
            }
        }
        run_now = false;
        match load() {
            Ok(fresh) => cfg = Arc::new(fresh),
            Err(e) => {
                event(&hub, "error", format!("configuration could not be reloaded, using the previous one: {e:#}"))
            }
        }
        last_start = Local::now();
        let (run, end) = run_once(cfg.clone(), hub.clone(), SyncOptions::default(), stop.child_token()).await;
        // Requests that arrived while the run was in flight are satisfied by that run.
        while tokio::time::timeout(Duration::ZERO, usr1.recv()).await.is_ok() {}
        last = Some(LastRun {
            run,
            state: end.state,
            exit_code: end.exit_code,
            finished_at: now_ts(),
            repos_ok: end.repos_ok,
            repos_failed: end.repos_failed,
        });
    }
    event(&hub, "info", "daemon stopping");
    hub.close(Duration::from_secs(2)).await;
    Ok(())
}
