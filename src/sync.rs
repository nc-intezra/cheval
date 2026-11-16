//! The mirroring engine.
//!
//! Ordering is what makes the mirror consistent at every instant:
//!   1. Release files and indices are downloaded into a private staging area.
//!   2. Every package file they reference is downloaded and verified.
//!   3. Only then are indices published (by-hash first, Release/InRelease last).
//!   4. Only after every repository sharing a directory succeeded is anything deleted.
use crate::clean::{self, CleanInput};
use crate::config::{Config, Filters, Global, Recheck, Repo, VerifyMode};
use crate::http::{FetchError, Job, Net, RepoHttp};
use crate::plan::{self, IndexKind, PoolFile, Selection};
use crate::progress::{Phase, Progress};
use crate::release::{FileEntry, Release};
use crate::sig::{Keyring, strip_cleartext};
use crate::util::{self, can_decode, file_matches, human_bytes, link_or_copy_atomic, split_compression};
use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use futures_util::StreamExt;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Default)]
pub struct SyncOptions {
    pub dry_run: bool,
    pub recheck: Option<Recheck>,
    pub only: Vec<String>,
    pub no_clean: bool,
    pub force_clean: bool,
}

#[derive(Debug, Default)]
pub struct RepoOutcome {
    pub name: String,
    pub root: PathBuf,
    pub ran: bool,
    pub complete: bool,
    pub cancelled: bool,
    pub suites_ok: Vec<String>,
    pub suites_failed: Vec<(String, String)>,
    pub files_fetched: u64,
    pub bytes_fetched: u64,
    pub files_present: u64,
    pub files_failed: u64,
    pub pending_files: u64,
    pub pending_bytes: u64,
    pub expected: HashSet<PathBuf>,
}

#[derive(Debug, Default)]
pub struct Summary {
    pub repos: Vec<RepoOutcome>,
    pub cleaned_files: u64,
    pub cleaned_bytes: u64,
    pub cancelled: bool,
    pub dry_run: bool,
    pub elapsed: Duration,
}

impl Summary {
    pub fn success(&self) -> bool {
        !self.cancelled
            && self.repos.iter().all(|r| !r.ran || (r.complete || self.dry_run) && r.suites_failed.is_empty())
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "\ncheval {} in {}\n",
            if self.cancelled {
                "CANCELLED"
            } else if self.success() {
                if self.dry_run { "dry run finished" } else { "finished successfully" }
            } else {
                "finished WITH ERRORS"
            },
            util::human_duration(self.elapsed.as_secs())
        ));
        for r in &self.repos {
            if !r.ran {
                s.push_str(&format!("  {:<24} skipped\n", r.name));
                continue;
            }
            let state = if r.cancelled {
                "cancelled"
            } else if r.suites_failed.is_empty() {
                "ok"
            } else if r.suites_ok.is_empty() {
                "FAILED"
            } else {
                "PARTIAL"
            };
            s.push_str(&format!(
                "  {:<24} {:<9} fetched {} files ({}), {} already present, {} failed\n",
                r.name,
                state,
                r.files_fetched,
                human_bytes(r.bytes_fetched),
                r.files_present,
                r.files_failed
            ));
            if self.dry_run {
                s.push_str(&format!(
                    "  {:<24} would download {} files ({})\n",
                    "",
                    r.pending_files,
                    human_bytes(r.pending_bytes)
                ));
            }
            for (suite, why) in &r.suites_failed {
                s.push_str(&format!("      suite {suite}: {why}\n"));
            }
        }
        if self.cleaned_files > 0 {
            s.push_str(&format!(
                "  cleaned {} obsolete files ({})\n",
                self.cleaned_files,
                human_bytes(self.cleaned_bytes)
            ));
        }
        s
    }
}

struct Ctx {
    g: Global,
    net: Net,
    opts: SyncOptions,
    progress: Arc<Progress>,
    cancel: CancellationToken,
}

#[derive(Debug, Default)]
struct PublishItem {
    src: PathBuf,
    by_hash: Vec<PathBuf>,
    canonical: Option<PathBuf>,
}

#[derive(Default)]
struct SuiteWork {
    suite: String,
    items: Vec<PublishItem>,
    /// (staged, final) for InRelease / Release / Release.gpg — published last.
    release_files: Vec<(PathBuf, PathBuf)>,
    remove: Vec<PathBuf>,
    pool: Vec<PoolFile>,
    expected: Vec<PathBuf>,
}

enum IndexState {
    Present,
    Staged,
    Absent(String),
    Failed(String),
}

/// Take the exclusive run lock so two instances never write the same tree.
pub fn lock(g: &Global) -> Result<std::fs::File> {
    let dir = g.state_path();
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join("cheval.lock");
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&path)?;
    // Retry briefly: a lock released a moment ago can still be held for an instant by
    // a process that was forked while the previous holder had the file open.
    for attempt in 0..40 {
        if f.try_lock().is_ok() {
            return Ok(f);
        }
        if attempt < 39 {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    bail!("another cheval instance is running (lock {})", path.display())
}

pub async fn run(
    cfg: Arc<Config>,
    opts: SyncOptions,
    progress: Arc<Progress>,
    cancel: CancellationToken,
) -> Result<Summary> {
    let started = Instant::now();
    let g = cfg.global.clone();
    for d in [g.mirror_path(), g.staging_path(), g.state_path()] {
        std::fs::create_dir_all(&d).with_context(|| format!("creating {}", d.display()))?;
    }
    let _lock = lock(&g)?;
    for name in &opts.only {
        if !cfg.repos.iter().any(|r| &r.name == name) {
            bail!("--only {name}: no such repository in the configuration");
        }
    }
    let ctx = Arc::new(Ctx {
        net: Net::new(&g, progress.clone(), cancel.clone())?,
        g: g.clone(),
        opts: opts.clone(),
        progress: progress.clone(),
        cancel: cancel.clone(),
    });

    let mut outcomes: Vec<Option<RepoOutcome>> = (0..cfg.repos.len()).map(|_| None).collect();
    let mut work = Vec::new();
    for (i, repo) in cfg.repos.iter().enumerate() {
        let selected = repo.enabled && (opts.only.is_empty() || opts.only.contains(&repo.name));
        if selected {
            work.push((i, repo.clone()));
        } else {
            progress.repos[i].set_phase(Phase::Skipped);
            outcomes[i] = Some(RepoOutcome {
                name: repo.name.clone(),
                root: repo.root(&g).unwrap_or_default(),
                ..Default::default()
            });
        }
    }
    // Repositories whose directories overlap (two suites of one archive, say) share files in
    // pool/ and dists/. Running them at the same time would download the same file twice into
    // the same place, so each such group runs one repository after another; groups still run
    // in parallel.
    let groups = share_groups(&work, &g);
    let results: Vec<Vec<(usize, RepoOutcome)>> = futures_util::stream::iter(groups)
        .map(|group| {
            let ctx = ctx.clone();
            async move {
                let mut done = Vec::with_capacity(group.len());
                for (i, repo) in group {
                    done.push((i, sync_repo(ctx.clone(), i, repo).await));
                }
                done
            }
        })
        .buffer_unordered(g.repo_parallel)
        .collect()
        .await;
    for (i, o) in results.into_iter().flatten() {
        outcomes[i] = Some(o);
    }
    let mut summary = Summary {
        repos: outcomes.into_iter().map(|o| o.unwrap()).collect(),
        cancelled: cancel.is_cancelled(),
        dry_run: opts.dry_run,
        ..Default::default()
    };

    if !opts.no_clean && !opts.dry_run && !summary.cancelled {
        let inputs: Vec<CleanInput> = summary
            .repos
            .iter_mut()
            .enumerate()
            .map(|(i, o)| CleanInput {
                idx: i,
                name: o.name.clone(),
                root: o.root.clone(),
                expected: std::mem::take(&mut o.expected),
                complete: o.ran && o.complete,
                mode: cfg.repos[i].clean(&g),
            })
            .collect();
        let (p, gl, force) = (progress.clone(), g.clone(), opts.force_clean);
        let (files, bytes) =
            tokio::task::spawn_blocking(move || clean::run(inputs, &gl, &p, force)).await.unwrap_or((0, 0));
        summary.cleaned_files = files;
        summary.cleaned_bytes = bytes;
    }
    for (i, o) in summary.repos.iter().enumerate() {
        if o.ran && progress.repos[i].phase() == Phase::Cleaning {
            progress.repos[i].set_phase(Phase::Done);
        }
    }
    summary.elapsed = started.elapsed();
    write_state(&g, &summary, &progress);
    progress.finished.store(true, Ordering::Relaxed);
    Ok(summary)
}

fn write_state(g: &Global, s: &Summary, p: &Progress) {
    let repos: Vec<serde_json::Value> = s
        .repos
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name, "ran": r.ran, "complete": r.complete,
                "suites_ok": r.suites_ok,
                "suites_failed": r.suites_failed.iter().map(|(a, b)| serde_json::json!({"suite": a, "error": b})).collect::<Vec<_>>(),
                "files_fetched": r.files_fetched, "bytes_fetched": r.bytes_fetched,
                "files_present": r.files_present, "files_failed": r.files_failed,
            })
        })
        .collect();
    let v = serde_json::json!({
        "finished_at": Utc::now().to_rfc3339(),
        "success": s.success(), "cancelled": s.cancelled, "dry_run": s.dry_run,
        "elapsed_secs": s.elapsed.as_secs(),
        "cleaned_files": s.cleaned_files, "cleaned_bytes": s.cleaned_bytes,
        "repos": repos,
        // The same object the status stream sends as its `end` message.
        "end": crate::status::EndMsg::from_summary(s, p),
    });
    let path = g.state_path().join("last-run.json");
    let _ = std::fs::write(&path, serde_json::to_vec_pretty(&v).unwrap_or_default());
}

async fn sync_repo(ctx: Arc<Ctx>, idx: usize, repo: Repo) -> RepoOutcome {
    let rp = &ctx.progress.repos[idx];
    let mut out = RepoOutcome {
        name: repo.name.clone(),
        root: repo.root(&ctx.g).unwrap_or_default(),
        ran: true,
        ..Default::default()
    };
    let staging = ctx.g.staging_path().join(&repo.name);
    let res = sync_repo_inner(&ctx, idx, &repo, &staging, &mut out).await;
    let _ = tokio::fs::remove_dir_all(&staging).await;
    if let Err(e) = res {
        if !ctx.cancel.is_cancelled() {
            ctx.progress.error(Some(idx), format!("{e:#}"));
        }
        if out.suites_failed.is_empty() {
            out.suites_failed.push(("*".into(), format!("{e:#}")));
        }
        out.complete = false;
    }
    out.files_fetched = rp.files_fetched.load(Ordering::Relaxed);
    out.bytes_fetched = rp.net_bytes.load(Ordering::Relaxed);
    out.files_present = rp.files_present.load(Ordering::Relaxed);
    out.files_failed = rp.files_failed.load(Ordering::Relaxed);
    if ctx.cancel.is_cancelled() {
        out.cancelled = true;
        out.complete = false;
        rp.set_phase(Phase::Cancelled);
    } else if out.suites_failed.is_empty() {
        // Cleaning happens once every repository has finished.
        rp.set_phase(if ctx.opts.dry_run || ctx.opts.no_clean { Phase::Done } else { Phase::Cleaning });
    } else if out.suites_ok.is_empty() {
        rp.set_phase(Phase::Failed);
    } else {
        rp.set_phase(Phase::Partial);
    }
    out
}

async fn sync_repo_inner(ctx: &Arc<Ctx>, idx: usize, repo: &Repo, staging: &Path, out: &mut RepoOutcome) -> Result<()> {
    let p = &ctx.progress;
    let rp = &p.repos[idx];
    let g = &ctx.g;
    let rh = Arc::new(RepoHttp::new(idx, repo, g)?);
    let filters = Arc::new(repo.filters()?);
    let root = repo.root(g)?;
    let verify = repo.verify(g);
    let keyring = match (&repo.keyring, verify) {
        (_, VerifyMode::Off) => None,
        (Some(k), _) => Some(Arc::new(Keyring::load(k)?)),
        (None, VerifyMode::Require) => bail!("verify = \"require\" but no keyring configured"),
        (None, VerifyMode::Auto) => {
            p.warn(Some(idx), "no keyring configured: Release signatures are NOT verified (set `keyring`)");
            None
        }
    };
    let _ = tokio::fs::remove_dir_all(staging).await;
    tokio::fs::create_dir_all(staging).await?;
    tokio::fs::create_dir_all(&root).await?;
    p.info(Some(idx), format!("syncing {} -> {}", rh.base, root.display()));

    rp.set_phase(Phase::Release);
    let mut suites: Vec<SuiteWork> = Vec::new();
    for suite in &repo.suites {
        if ctx.cancel.is_cancelled() {
            bail!("cancelled");
        }
        let r = prepare_suite(ctx, &rh, repo, &filters, keyring.as_deref(), &root, staging, suite).await;
        match r {
            Ok(sw) => suites.push(sw),
            Err(e) => {
                if ctx.cancel.is_cancelled() {
                    bail!("cancelled");
                }
                p.error(Some(idx), format!("suite {suite}: {e:#}"));
                out.suites_failed.push((suite.clone(), format!("{e:#}")));
            }
        }
    }

    if suites.is_empty() {
        return Ok(()); // every suite failed during the metadata phase
    }

    // ---- pool -----------------------------------------------------------------
    rp.set_phase(Phase::Scanning);
    let all: Vec<PoolFile> = suites.iter().flat_map(|s| s.pool.iter().cloned()).collect();
    let (pool, conflicts) = plan::dedupe(all);
    if !conflicts.is_empty() {
        p.warn(
            Some(idx),
            format!(
                "{} file(s) are listed with different contents by different indices (\"duplicate packages\"); \
                 mirror such suites as separate repositories. First: {}",
                conflicts.len(),
                conflicts[0]
            ),
        );
    }
    let recheck = ctx.opts.recheck.unwrap_or(g.recheck);
    let (need, present) = scan(root.clone(), pool.clone(), recheck).await;
    let need_bytes: u64 = need.iter().map(|f| f.size).sum();
    rp.files_total.fetch_add(pool.len() as u64, Ordering::Relaxed);
    rp.files_present.fetch_add(present, Ordering::Relaxed);
    rp.bytes_total.fetch_add(need_bytes, Ordering::Relaxed);
    out.pending_files = need.len() as u64;
    out.pending_bytes = need_bytes;
    p.info(
        Some(idx),
        format!(
            "{} package files referenced, {} present, {} to download ({})",
            pool.len(),
            present,
            need.len(),
            human_bytes(need_bytes)
        ),
    );
    if ctx.opts.dry_run {
        out.suites_ok = suites.iter().map(|s| s.suite.clone()).collect();
        out.complete = out.suites_failed.is_empty();
        return Ok(());
    }

    rp.set_phase(Phase::Downloading);
    let failed: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let ignored: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    futures_util::stream::iter(need)
        .for_each_concurrent(g.threads * 2, |pf| {
            let (ctx, rh, root, failed, ignored, filters) =
                (ctx.clone(), rh.clone(), root.clone(), failed.clone(), ignored.clone(), filters.clone());
            async move {
                let rp = &ctx.progress.repos[idx];
                let url = match rh.url_for(&pf.path) {
                    Ok(u) => u,
                    Err(e) => {
                        ctx.progress.error(Some(idx), format!("{}: {e}", pf.path));
                        rp.files_failed.fetch_add(1, Ordering::Relaxed);
                        failed.lock().unwrap().insert(pf.path);
                        return;
                    }
                };
                let alt_url = if pf.path.contains('%') { rh.url_raw(&pf.path) } else { None };
                let dest = root.join(&pf.path);
                let job = Job {
                    rh: &rh,
                    url,
                    alt_url,
                    dest: &dest,
                    size: Some(pf.size),
                    sum: pf.sum.clone(),
                    label: pf.path.clone(),
                };
                match ctx.net.fetch(job).await {
                    Ok(_) => {
                        rp.files_fetched.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(FetchError::Cancelled) => {
                        failed.lock().unwrap().insert(pf.path);
                    }
                    Err(e) => {
                        // The byte budget shrinks so the progress bar can still reach 100%.
                        rp.bytes_total
                            .fetch_sub(pf.size.min(rp.bytes_total.load(Ordering::Relaxed)), Ordering::Relaxed);
                        if filters.may_be_missing(&pf.path) {
                            ctx.progress.warn(Some(idx), format!("{}: {e} (ignored by ignore_missing)", pf.path));
                            ignored.lock().unwrap().insert(pf.path);
                        } else {
                            ctx.progress.error(Some(idx), format!("{}: {e}", pf.path));
                            rp.files_failed.fetch_add(1, Ordering::Relaxed);
                            failed.lock().unwrap().insert(pf.path);
                        }
                    }
                }
            }
        })
        .await;
    if ctx.cancel.is_cancelled() {
        bail!("cancelled");
    }
    let failed = std::mem::take(&mut *failed.lock().unwrap());
    let ignored = std::mem::take(&mut *ignored.lock().unwrap());

    // ---- publish --------------------------------------------------------------
    rp.set_phase(Phase::Publishing);
    for sw in &suites {
        let bad = sw.pool.iter().filter(|f| failed.contains(&f.path)).count();
        if bad > 0 && !repo.publish_partial {
            let why =
                format!("{bad} package file(s) could not be fetched; new indices NOT published, previous state kept");
            p.error(Some(idx), format!("suite {}: {why}", sw.suite));
            out.suites_failed.push((sw.suite.clone(), why));
            continue;
        }
        let (items, rel, rm) = (
            sw.items
                .iter()
                .map(|i| PublishItem { src: i.src.clone(), by_hash: i.by_hash.clone(), canonical: i.canonical.clone() })
                .collect::<Vec<_>>(),
            sw.release_files.clone(),
            sw.remove.clone(),
        );
        let published = tokio::task::spawn_blocking(move || publish(&items, &rel, &rm)).await?;
        match published {
            Ok(n) => {
                if bad > 0 {
                    let why = format!("published with {bad} missing package file(s) (publish_partial)");
                    p.warn(Some(idx), format!("suite {}: {why}", sw.suite));
                    out.suites_failed.push((sw.suite.clone(), why));
                } else {
                    if n == 0 {
                        p.info(Some(idx), format!("suite {} is up to date", sw.suite));
                    } else {
                        p.info(Some(idx), format!("suite {} published ({n} metadata files updated)", sw.suite));
                    }
                    out.suites_ok.push(sw.suite.clone());
                }
            }
            Err(e) => {
                p.error(Some(idx), format!("suite {}: publishing failed: {e:#}", sw.suite));
                out.suites_failed.push((sw.suite.clone(), format!("publishing failed: {e:#}")));
            }
        }
    }

    // ---- extra files ------------------------------------------------------------
    for extra in &repo.extra_files {
        let dest = root.join(util::safe_rel_path(extra)?);
        let tmp = staging.join("extra").join(util::safe_rel_path(extra)?);
        let job = Job {
            rh: &rh,
            url: rh.url_for(extra)?,
            alt_url: None,
            dest: &tmp,
            size: None,
            sum: None,
            label: extra.clone(),
        };
        match ctx.net.fetch(job).await {
            Ok(_) => {
                link_or_copy_atomic(&tmp, &dest)?;
                out.expected.insert(dest);
            }
            Err(e) => {
                p.warn(Some(idx), format!("extra file {extra}: {e}"));
                if dest.exists() {
                    out.expected.insert(dest);
                }
            }
        }
    }

    for sw in &suites {
        out.expected.extend(sw.expected.iter().cloned());
    }
    for f in &pool {
        if !ignored.contains(&f.path) {
            out.expected.insert(root.join(&f.path));
        }
    }
    out.complete = out.suites_failed.is_empty();
    Ok(())
}

/// Split the pool into files to download and a count of files already in place.
async fn scan(root: PathBuf, pool: Vec<PoolFile>, recheck: Recheck) -> (Vec<PoolFile>, u64) {
    let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).min(8);
    let chunk = pool.len().div_ceil(workers).max(1);
    let mut handles = Vec::new();
    for part in pool.chunks(chunk) {
        let (part, root) = (part.to_vec(), root.clone());
        handles.push(tokio::task::spawn_blocking(move || {
            let mut need = Vec::new();
            let mut present = 0u64;
            for f in part {
                let path = root.join(&f.path);
                let sum = if recheck == Recheck::Hash { f.sum.as_ref() } else { None };
                if file_matches(&path, Some(f.size), sum) {
                    present += 1;
                } else {
                    need.push(f);
                }
            }
            (need, present)
        }));
    }
    let mut need = Vec::new();
    let mut present = 0;
    for h in handles {
        if let Ok((n, p)) = h.await {
            need.extend(n);
            present += p;
        }
    }
    (need, present)
}

fn publish(items: &[PublishItem], release: &[(PathBuf, PathBuf)], remove: &[PathBuf]) -> Result<usize> {
    let mut n = 0;
    // by-hash first: clients holding either the old or the new Release keep working.
    for it in items {
        for d in &it.by_hash {
            if !d.exists() {
                link_or_copy_atomic(&it.src, d).with_context(|| format!("publishing {}", d.display()))?;
            }
        }
    }
    for it in items {
        if let Some(c) = &it.canonical {
            link_or_copy_atomic(&it.src, c).with_context(|| format!("publishing {}", c.display()))?;
            n += 1;
        }
    }
    // Release files last; InRelease is ordered last by the caller.
    for (src, dst) in release {
        let same = matches!((std::fs::read(src), std::fs::read(dst)), (Ok(a), Ok(b)) if a == b);
        if !same {
            link_or_copy_atomic(src, dst).with_context(|| format!("publishing {}", dst.display()))?;
            n += 1;
        }
    }
    for r in remove {
        let _ = std::fs::remove_file(r);
    }
    Ok(n)
}

fn join_url_path(dist: &Path, rel: &str) -> String {
    let d = dist.to_string_lossy();
    if d.is_empty() { rel.to_string() } else { format!("{d}/{rel}") }
}

/// Fetch an optional top-level file; `Ok(None)` means it is absent upstream.
/// A 401/403 answer is remembered in `denied` so a credentials problem is not
/// reported as a plain "not found".
async fn fetch_optional(
    ctx: &Ctx,
    rh: &RepoHttp,
    rel: &str,
    dest: &Path,
    denied: &mut Option<u16>,
) -> Result<Option<u64>, FetchError> {
    let url = rh.url_for(rel).map_err(|e| FetchError::Io(e.to_string()))?;
    let job = Job { rh, url, alt_url: None, dest, size: None, sum: None, label: rel.to_string() };
    match ctx.net.fetch(job).await {
        Ok(n) => Ok(Some(n)),
        Err(FetchError::NotFound(_)) => Ok(None),
        // Object stores answer 403 for missing keys, so treat it like 404 here.
        Err(FetchError::Denied(code)) => {
            *denied = Some(code);
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

fn normalize(text: &str) -> String {
    text.lines().map(|l| l.trim_end()).collect::<Vec<_>>().join("\n").trim_end().to_string()
}

/// Read and authenticate the Release data in `dir`. Returns the trusted text.
pub fn load_release_text(
    dir: &Path,
    have_inrelease: bool,
    have_release: bool,
    have_gpg: bool,
    keyring: Option<&Keyring>,
) -> Result<(String, Option<String>)> {
    if have_inrelease {
        let raw = std::fs::read(dir.join("InRelease"))?;
        let text = String::from_utf8_lossy(&raw).into_owned();
        return match keyring {
            Some(k) => {
                let (body, fp) = k.verify_cleartext(&text).context("InRelease signature")?;
                Ok((body, Some(fp)))
            }
            None => Ok((strip_cleartext(&text), None)),
        };
    }
    if have_release {
        let data = std::fs::read(dir.join("Release"))?;
        let mut signer = None;
        if let Some(k) = keyring {
            if !have_gpg {
                bail!("Release is not signed (no InRelease or Release.gpg) but a keyring is configured");
            }
            let sig = std::fs::read(dir.join("Release.gpg"))?;
            signer = Some(k.verify_detached(&sig, &data).context("Release.gpg signature")?);
        }
        return Ok((String::from_utf8_lossy(&data).into_owned(), signer));
    }
    bail!("no Release file")
}

#[allow(clippy::too_many_arguments)]
async fn prepare_suite(
    ctx: &Arc<Ctx>,
    rh: &Arc<RepoHttp>,
    repo: &Repo,
    filters: &Arc<Filters>,
    keyring: Option<&Keyring>,
    root: &Path,
    staging: &Path,
    suite: &str,
) -> Result<SuiteWork> {
    let p = &ctx.progress;
    let idx = rh.idx;
    let rp = &p.repos[idx];
    let g = &ctx.g;
    let flat = Repo::is_flat(suite);
    let dist = Repo::dist_dir(suite)?;
    let stage = if dist.as_os_str().is_empty() { staging.join("_root") } else { staging.join("_d").join(&dist) };
    let final_dir = root.join(&dist);
    tokio::fs::create_dir_all(&stage).await?;
    let mut sw = SuiteWork { suite: suite.to_string(), ..Default::default() };

    // ---- Release ----------------------------------------------------------------
    let mut attempt = 0;
    let mut denied: Option<u16> = None;
    let (text, have) = loop {
        attempt += 1;
        let inrel = fetch_optional(ctx, rh, &join_url_path(&dist, "InRelease"), &stage.join("InRelease"), &mut denied)
            .await
            .map_err(|e| anyhow!("InRelease: {e}"))?
            .is_some();
        let rel = fetch_optional(ctx, rh, &join_url_path(&dist, "Release"), &stage.join("Release"), &mut denied)
            .await
            .map_err(|e| anyhow!("Release: {e}"))?
            .is_some();
        let gpg = rel
            && fetch_optional(ctx, rh, &join_url_path(&dist, "Release.gpg"), &stage.join("Release.gpg"), &mut denied)
                .await
                .map_err(|e| anyhow!("Release.gpg: {e}"))?
                .is_some();
        if !inrel && !rel {
            break (None, (false, false, false));
        }
        let (text, signer) = load_release_text(&stage, inrel, rel, gpg, keyring)?;
        if let Some(fp) = signer {
            p.info(Some(idx), format!("suite {suite}: signature OK (key {fp})"));
        }
        if inrel && rel {
            let plain = String::from_utf8_lossy(&std::fs::read(stage.join("Release"))?).into_owned();
            if normalize(&plain) != normalize(&text) {
                if attempt < 3 {
                    p.debug(Some(idx), format!("suite {suite}: InRelease and Release differ, refetching"));
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
                p.warn(
                    Some(idx),
                    format!("suite {suite}: upstream Release differs from InRelease; mirroring InRelease only"),
                );
                break (Some(text), (true, false, false));
            }
        }
        break (Some(text), (inrel, rel, gpg));
    };

    let Some(text) = text else {
        if let Some(code) = denied {
            bail!(
                "HTTP {code} for {} — access denied: check [repo.auth] credentials, try user_agent = \"apt\", \
                 and make sure a proxy is not blocking the host",
                rh.url_for(&join_url_path(&dist, "InRelease"))?
            );
        }
        if flat && repo.verify(g) != VerifyMode::Require && keyring.is_none() {
            return bare_flat(ctx, rh, filters, root, &stage, &dist, sw).await;
        }
        bail!(
            "no InRelease or Release at {} — check the URL and suite name (try `cheval probe {}`)",
            rh.url_for(&join_url_path(&dist, "InRelease"))?,
            rh.base
        );
    };
    let release = Release::parse(&text)?;
    let now = Utc::now();
    if repo.check_valid_until(g)
        && let Some(v) = release.valid_until
        && v < now
    {
        bail!("Release expired on {v} (stale or replayed upstream); set check_valid_until = false to accept");
    }
    // Refuse to go back in time (a lagging upstream mirror behind a round-robin).
    if !repo.allow_downgrade {
        let old = ["InRelease", "Release"].iter().find_map(|n| std::fs::read(final_dir.join(n)).ok());
        if let Some(old) = old
            && let Ok(old) = Release::parse(&strip_cleartext(&String::from_utf8_lossy(&old)))
            && let (Some(o), Some(n)) = (old.date, release.date)
            && n < o
        {
            bail!(
                "upstream Release ({n}) is older than the mirrored one ({o}); keeping current state (allow_downgrade = true to override)"
            );
        }
    }
    if release.files.is_empty() {
        bail!("Release lists no index files");
    }
    if !release.files.values().any(|e| e.sha256.is_some() || e.sha512.is_some()) {
        p.warn(Some(idx), format!("suite {suite}: Release only carries weak checksums (MD5/SHA1)"));
    }

    // ---- index selection ------------------------------------------------------------
    let archs = repo.architectures(g);
    let sel = Selection {
        components: &repo.components,
        architectures: archs,
        source: repo.source(g),
        installer: repo.installer,
        pdiffs: repo.pdiffs,
        languages: repo.languages.as_deref(),
        flat,
    };
    let selected: Vec<(String, FileEntry)> =
        plan::select(&release, &sel, filters).into_iter().map(|(p, e)| (p.to_string(), e.clone())).collect();
    let has_kind = |k: IndexKind| selected.iter().any(|(p, _)| plan::index_kind(p) == k);
    if !has_kind(IndexKind::Packages) && !has_kind(IndexKind::Sources) {
        bail!(
            "nothing to mirror: Release offers components [{}] and architectures [{}], configuration asks for components [{}] and architectures [{}]",
            release.components.join(" "),
            release.architectures.join(" "),
            repo.components.join(" "),
            archs.join(" ")
        );
    }
    if !flat {
        for a in archs {
            if !selected
                .iter()
                .any(|(p, _)| plan::path_arch(p) == Some(a.as_str()) && plan::index_kind(p) == IndexKind::Packages)
            {
                p.warn(
                    Some(idx),
                    format!(
                        "suite {suite}: architecture {a} is not published (Release has: {})",
                        release.architectures.join(" ")
                    ),
                );
            }
        }
        for c in &repo.components {
            let base = c.rsplit('/').next().unwrap_or(c);
            if !selected.iter().any(|(p, _)| p.starts_with(&format!("{c}/")) || p.starts_with(&format!("{base}/"))) {
                p.warn(
                    Some(idx),
                    format!(
                        "suite {suite}: component {c} is not published (Release has: {})",
                        release.components.join(" ")
                    ),
                );
            }
        }
    }

    // ---- index download ---------------------------------------------------------
    rp.set_phase(Phase::Indices);
    rp.files_total.fetch_add(selected.len() as u64, Ordering::Relaxed);
    let by_hash = release.acquire_by_hash;
    let states: Vec<(String, FileEntry, IndexState)> = futures_util::stream::iter(selected)
        .map(|(path, entry)| {
            let (ctx, rh, stage, final_dir, dist) =
                (ctx.clone(), rh.clone(), stage.clone(), final_dir.clone(), dist.clone());
            async move {
                let rp = &ctx.progress.repos[rh.idx];
                let sum = entry.best();
                let final_path = final_dir.join(&path);
                let (fp, sz, sm) = (final_path.clone(), entry.size, sum.clone());
                let present = tokio::task::spawn_blocking(move || file_matches(&fp, Some(sz), sm.as_ref()))
                    .await
                    .unwrap_or(false);
                if present {
                    rp.files_present.fetch_add(1, Ordering::Relaxed);
                    return (path, entry, IndexState::Present);
                }
                let staged = stage.join(&path);
                if entry.size == 0 {
                    // Empty index: no need to ask the server (often not even hosted).
                    let ok = std::fs::create_dir_all(staged.parent().unwrap())
                        .and_then(|_| std::fs::write(&staged, b""))
                        .is_ok()
                        && file_matches(&staged, Some(0), sum.as_ref());
                    rp.files_present.fetch_add(1, Ordering::Relaxed);
                    let st =
                        if ok { IndexState::Staged } else { IndexState::Failed("cannot create empty index".into()) };
                    return (path, entry, st);
                }
                let canonical = rh.url_for(&join_url_path(&dist, &path));
                let (url, alt) = match (&sum, by_hash) {
                    (Some(c), true) => {
                        let dir = path.rsplit_once('/').map(|(d, _)| format!("{d}/")).unwrap_or_default();
                        let bh = format!("{dir}by-hash/{}/{}", c.algo.release_field(), c.hex);
                        (rh.url_for(&join_url_path(&dist, &bh)), canonical.ok())
                    }
                    _ => (canonical, None),
                };
                let url = match url {
                    Ok(u) => u,
                    Err(e) => return (path, entry, IndexState::Failed(e.to_string())),
                };
                rp.bytes_total.fetch_add(entry.size, Ordering::Relaxed);
                let job = Job {
                    rh: &rh,
                    url,
                    alt_url: alt,
                    dest: &staged,
                    size: Some(entry.size),
                    sum,
                    label: join_url_path(&dist, &path),
                };
                let st = match ctx.net.fetch(job).await {
                    Ok(_) => {
                        rp.files_fetched.fetch_add(1, Ordering::Relaxed);
                        IndexState::Staged
                    }
                    Err(e) => {
                        rp.bytes_total
                            .fetch_sub(entry.size.min(rp.bytes_total.load(Ordering::Relaxed)), Ordering::Relaxed);
                        rp.files_total.fetch_sub(1, Ordering::Relaxed);
                        match e {
                            FetchError::NotFound(_) | FetchError::Denied(_) => IndexState::Absent(e.to_string()),
                            e => IndexState::Failed(e.to_string()),
                        }
                    }
                };
                (path, entry, st)
            }
        })
        .buffer_unordered(8)
        .collect()
        .await;
    if ctx.cancel.is_cancelled() {
        bail!("cancelled");
    }

    // ---- evaluate per index (all compression variants of one file) -----------------
    let mut groups: BTreeMap<String, Vec<(&str, &FileEntry, &IndexState)>> = BTreeMap::new();
    for (path, entry, st) in &states {
        groups.entry(split_compression(path).0.to_string()).or_default().push((path, entry, st));
    }
    let mut problems: Vec<String> = Vec::new();
    let mut to_parse: Vec<(IndexKind, PathBuf)> = Vec::new();
    for (stem, variants) in &groups {
        let kind = plan::index_kind(stem);
        for (path, _, st) in variants {
            if let IndexState::Failed(e) = st {
                problems.push(format!("{path}: {e}"));
            }
        }
        let ok: Vec<&(&str, &FileEntry, &IndexState)> =
            variants.iter().filter(|(_, _, s)| matches!(s, IndexState::Present | IndexState::Staged)).collect();
        if ok.is_empty() {
            let why = variants
                .iter()
                .find_map(|(_, _, s)| if let IndexState::Absent(e) = s { Some(e.clone()) } else { None })
                .unwrap_or_default();
            if variants.iter().any(|(_, _, s)| matches!(s, IndexState::Failed(_))) {
                continue;
            }
            if filters.may_be_missing(stem) {
                p.debug(Some(idx), format!("suite {suite}: {stem} absent upstream (ignored)"));
            } else if kind == IndexKind::Other {
                p.warn(Some(idx), format!("suite {suite}: {stem} is listed in Release but absent upstream ({why})"));
            } else {
                problems.push(format!("{stem}: listed in Release but no variant exists upstream ({why})"));
            }
            continue;
        }
        if kind != IndexKind::Other {
            const PREF: &[&str] = &["", ".zst", ".gz", ".xz", ".bz2", ".lzma"];
            let best = ok
                .iter()
                .filter(|(p, _, _)| can_decode(split_compression(p).1))
                .min_by_key(|(p, _, _)| PREF.iter().position(|e| *e == split_compression(p).1).unwrap_or(99));
            match best {
                Some((path, _, st)) => {
                    let file = if matches!(st, IndexState::Staged) { stage.join(path) } else { final_dir.join(path) };
                    to_parse.push((kind, file));
                }
                None => problems.push(format!("{stem}: only available in a compression cheval cannot read")),
            }
        }
    }
    if !problems.is_empty() {
        let n = problems.len();
        problems.truncate(4);
        bail!("{n} index problem(s): {}", problems.join("; "));
    }

    for (path, entry, st) in &states {
        let canonical = final_dir.join(path);
        let (src, canon) = match st {
            IndexState::Staged => (stage.join(path), Some(canonical.clone())),
            IndexState::Present => (canonical.clone(), None),
            _ => continue,
        };
        let mut item = PublishItem { src, canonical: canon, by_hash: Vec::new() };
        if by_hash {
            let dir = Path::new(path).parent().map(|d| final_dir.join(d)).unwrap_or_else(|| final_dir.clone());
            for c in entry.all() {
                item.by_hash.push(dir.join("by-hash").join(c.algo.release_field()).join(&c.hex));
            }
        }
        sw.expected.push(canonical);
        sw.expected.extend(item.by_hash.iter().cloned());
        sw.items.push(item);
    }
    // Publish order: Release.gpg, Release, then InRelease last.
    for (name, present) in [("Release.gpg", have.2), ("Release", have.1), ("InRelease", have.0)] {
        let dst = final_dir.join(name);
        if present {
            sw.release_files.push((stage.join(name), dst.clone()));
            sw.expected.push(dst);
        } else if dst.exists() {
            sw.remove.push(dst);
        }
    }

    // ---- parse --------------------------------------------------------------------
    sw.pool = parse_indices(ctx, idx, suite, to_parse, filters.clone()).await?;
    Ok(sw)
}

async fn parse_indices(
    ctx: &Arc<Ctx>,
    idx: usize,
    suite: &str,
    to_parse: Vec<(IndexKind, PathBuf)>,
    filters: Arc<Filters>,
) -> Result<Vec<PoolFile>> {
    let p = &ctx.progress;
    let mut pool = Vec::new();
    for (kind, file) in to_parse {
        let f = filters.clone();
        let file2 = file.clone();
        let (files, st) = tokio::task::spawn_blocking(move || -> Result<_> {
            let mut v = Vec::new();
            let st = match kind {
                IndexKind::Sources => plan::parse_sources(&file2, &f, &mut v)?,
                _ => plan::parse_packages(&file2, &f, &mut v)?,
            };
            Ok((v, st))
        })
        .await?
        .with_context(|| format!("parsing {}", file.display()))?;
        p.debug(
            Some(idx),
            format!(
                "suite {suite}: {} -> {} entries, {} filtered",
                file.components()
                    .rev()
                    .take(3)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/"),
                st.packages,
                st.filtered
            ),
        );
        for s in st.skipped.iter().take(5) {
            p.warn(Some(idx), format!("suite {suite}: skipped {s}"));
        }
        if st.skipped.len() > 5 {
            p.warn(Some(idx), format!("suite {suite}: ... and {} more skipped entries", st.skipped.len() - 5));
        }
        pool.extend(files);
    }
    Ok(pool)
}

/// Flat repository without any Release file: mirror the bare Packages index.
async fn bare_flat(
    ctx: &Arc<Ctx>,
    rh: &Arc<RepoHttp>,
    filters: &Arc<Filters>,
    root: &Path,
    stage: &Path,
    dist: &Path,
    mut sw: SuiteWork,
) -> Result<SuiteWork> {
    let idx = rh.idx;
    ctx.progress.warn(
        Some(idx),
        format!("suite {}: no Release file — indices cannot be authenticated, mirroring bare Packages", sw.suite),
    );
    let final_dir = root.join(dist);
    let mut parse = None;
    for name in ["Packages", "Packages.gz", "Packages.xz", "Packages.bz2", "Packages.zst"] {
        let staged = stage.join(name);
        match fetch_optional(ctx, rh, &join_url_path(dist, name), &staged, &mut None).await {
            Ok(Some(_)) => {
                sw.items.push(PublishItem {
                    src: staged.clone(),
                    by_hash: vec![],
                    canonical: Some(final_dir.join(name)),
                });
                sw.expected.push(final_dir.join(name));
                parse.get_or_insert(staged);
            }
            Ok(None) => {}
            Err(e) => bail!("{name}: {e}"),
        }
    }
    let Some(file) = parse else {
        bail!("neither Release nor Packages found at {}", rh.url_for(&join_url_path(dist, "Packages"))?);
    };
    sw.pool = parse_indices(ctx, idx, &sw.suite.clone(), vec![(IndexKind::Packages, file)], filters.clone()).await?;
    Ok(sw)
}

/// Group repositories whose mirror directories are equal or nested, keeping configuration order.
fn share_groups(work: &[(usize, Repo)], g: &Global) -> Vec<Vec<(usize, Repo)>> {
    let roots: Vec<PathBuf> = work.iter().map(|(_, r)| r.root(g).unwrap_or_default()).collect();
    let overlap = |a: &PathBuf, b: &PathBuf| a.starts_with(b) || b.starts_with(a);
    let mut group_of: Vec<usize> = (0..work.len()).collect();
    for i in 0..work.len() {
        for j in 0..i {
            if overlap(&roots[i], &roots[j]) {
                let (gi, gj) = (group_of[i], group_of[j]);
                for k in group_of.iter_mut() {
                    if *k == gi {
                        *k = gj;
                    }
                }
            }
        }
    }
    let mut order: Vec<usize> = Vec::new();
    let mut groups: Vec<Vec<(usize, Repo)>> = Vec::new();
    for (k, item) in work.iter().enumerate() {
        match order.iter().position(|&gid| gid == group_of[k]) {
            Some(pos) => groups[pos].push(item.clone()),
            None => {
                order.push(group_of[k]);
                groups.push(vec![item.clone()]);
            }
        }
    }
    groups
}

#[cfg(test)]
mod share_tests {
    use super::*;

    #[test]
    fn overlapping_directories_run_one_after_another() {
        let cfg: Config = toml::from_str(
            r#"
            [global]
            base_path = "/srv/cheval"
            [[repo]]
            name = "debian"
            url = "http://deb.debian.org/debian"
            suites = ["trixie"]
            [[repo]]
            name = "docker"
            url = "https://download.docker.com/linux/debian"
            suites = ["trixie"]
            [[repo]]
            name = "debian-updates"
            url = "http://deb.debian.org/debian"
            suites = ["trixie-updates"]
            [[repo]]
            name = "security"
            url = "http://deb.debian.org/debian-security"
            suites = ["trixie-security"]
            "#,
        )
        .unwrap();
        let work: Vec<(usize, Repo)> = cfg.repos.iter().cloned().enumerate().collect();
        let names: Vec<Vec<&str>> = share_groups(&work, &cfg.global)
            .iter()
            .map(|g| {
                g.iter().map(|(_, r)| cfg.repos.iter().find(|x| x.name == r.name).unwrap().name.as_str()).collect()
            })
            .collect();
        assert_eq!(names, vec![vec!["debian", "debian-updates"], vec!["docker"], vec!["security"]]);
    }
}
