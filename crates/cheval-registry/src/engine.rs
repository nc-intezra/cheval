//! What the three registry backends share: fetching metadata during planning, then
//! downloading the files a plan wants, then publishing listings last.
//!
//! A backend's `plan` walks the registry (index files, `go.mod`, POMs) and returns:
//! - `wants`: files to download into the mirror, each checked (checksum, or Go's `h1:`);
//! - `publish`: staged files to put in place after every download succeeded, in order
//!   (listings and the index root last).
//!
//! If any download fails the listings are not replaced (unless `publish_partial`), so
//! clients never see a version whose files are missing.
use crate::config::{Format, Global, Recheck, Repo, url_dir};
use crate::http::{FetchError, Job, Net, RepoHttp};
use crate::progress::{Phase, Progress};
use crate::summary::RepoOutcome;
use crate::util::{Checksum, file_matches, human_bytes, link_or_copy_atomic};
use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;
use url::Url;

/// What a sync run gives a backend.
pub struct Env<'a> {
    pub g: &'a Global,
    pub net: &'a Net,
    pub progress: &'a Arc<Progress>,
    pub cancel: &'a CancellationToken,
    pub dry_run: bool,
    pub recheck: Recheck,
}

/// A check made after download, beyond a plain checksum.
#[derive(Debug, Clone)]
pub enum PostCheck {
    None,
    /// A Go module zip: every file under `prefix` (`module@version/`), and when known the
    /// `h1:` hash from `go.sum`.
    GoZip {
        prefix: String,
        h1: Option<String>,
    },
}

/// A file to download into the mirror.
#[derive(Debug, Clone)]
pub struct Want {
    pub url: Url,
    pub dest: PathBuf,
    pub size: Option<u64>,
    pub sum: Option<Checksum>,
    pub post: PostCheck,
    pub label: String,
}

#[derive(Default)]
pub struct Plan {
    pub wants: Vec<Want>,
    /// (staged, final), published in order after the downloads.
    pub publish: Vec<(PathBuf, PathBuf)>,
    /// A line for the log: what was selected.
    pub summary: String,
}

impl Plan {
    pub fn want(&mut self, w: Want) {
        if !self.wants.iter().any(|x| x.dest == w.dest) {
            self.wants.push(w);
        }
    }
    pub fn publish(&mut self, staged: PathBuf, fin: PathBuf) {
        self.publish.retain(|(_, f)| f != &fin);
        self.publish.push((staged, fin));
    }
}

/// One entry's sync state, handed to its backend.
pub struct Ctx<'a> {
    pub env: &'a Env<'a>,
    pub idx: usize,
    pub repo: &'a Repo,
    pub rh: Arc<RepoHttp>,
    pub base: Url,
    pub root: PathBuf,
    staging: PathBuf,
    seq: AtomicU64,
}

impl<'a> Ctx<'a> {
    pub fn g(&self) -> &Global {
        self.env.g
    }
    pub fn info(&self, m: impl Into<String>) {
        self.env.progress.info(Some(self.idx), m);
    }
    pub fn warn(&self, m: impl Into<String>) {
        self.env.progress.warn(Some(self.idx), m);
    }
    pub fn cancelled(&self) -> bool {
        self.env.cancel.is_cancelled()
    }
    /// How many metadata requests to run at once.
    pub fn parallel(&self) -> usize {
        (self.env.g.threads * 2).max(4)
    }

    /// Where a URL is stored: below the entry's root when it is under the entry's URL
    /// (so `mirror_dir` applies), else under its own host directory.
    pub fn local(&self, url: &Url) -> Result<PathBuf> {
        let (b, u) = (self.base.as_str(), url.as_str());
        if let Some(rel) = u.strip_prefix(b) {
            let rel = rel.split(['?', '#']).next().unwrap_or("");
            let dec = percent_encoding::percent_decode_str(rel).decode_utf8_lossy().into_owned();
            return Ok(self.root.join(crate::util::safe_rel_path(&dec)?));
        }
        url_dir(self.env.g, u)
    }

    /// A fresh staging path (keeping the file name, for messages).
    pub fn stage_path(&self, name: &str) -> PathBuf {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let name: String = name.chars().map(|c| if c == '/' || c == '\\' { '_' } else { c }).collect();
        self.staging.join(format!("{n:06}-{name}"))
    }

    /// Write generated content to staging.
    pub fn stage_bytes(&self, name: &str, data: &[u8]) -> Result<PathBuf> {
        let p = self.stage_path(name);
        std::fs::create_dir_all(&self.staging)?;
        std::fs::write(&p, data).with_context(|| format!("writing {}", p.display()))?;
        Ok(p)
    }

    /// Fetch a small file into staging: `Ok(None)` when upstream says it does not exist.
    pub async fn fetch(&self, url: &Url) -> Result<Option<(PathBuf, Vec<u8>)>> {
        let name = url.path().rsplit('/').next().unwrap_or("file").to_string();
        let dest = self.stage_path(&name);
        let job =
            Job { rh: &self.rh, url: url.clone(), alt_url: None, dest: &dest, size: None, sum: None, label: name };
        match self.env.net.fetch(job).await {
            Ok(_) => {
                let data = tokio::fs::read(&dest).await?;
                Ok(Some((dest, data)))
            }
            Err(e) if e.is_not_found() => Ok(None),
            Err(FetchError::Cancelled) => bail!("cancelled"),
            Err(e) => Err(anyhow::anyhow!("{url}: {e}")),
        }
    }

    /// An immutable file (a POM, a `.mod`, an `.info`): read from the mirror when it is
    /// there, else fetch it and add it to the plan's publish list. `Ok(None)` if missing.
    pub async fn immutable(&self, url: &Url) -> Result<Option<(Vec<u8>, Option<PathBuf>)>> {
        let fin = self.local(url)?;
        if let Ok(data) = tokio::fs::read(&fin).await {
            return Ok(Some((data, None)));
        }
        Ok(self.fetch(url).await?.map(|(p, d)| (d, Some(p))))
    }
}

/// Sync one `crates`, `go` or `maven` entry.
pub async fn sync_entry(env: &Env<'_>, idx: usize, repo: &Repo, staging: &Path, out: &mut RepoOutcome) -> Result<()> {
    let p = env.progress;
    let rp = &p.repos[idx];
    let g = env.g;
    let ctx = Ctx {
        env,
        idx,
        repo,
        rh: Arc::new(RepoHttp::new(idx, repo, g)?),
        base: repo.base_url()?,
        root: repo.root(g)?,
        staging: staging.to_path_buf(),
        seq: AtomicU64::new(0),
    };
    tokio::fs::create_dir_all(staging).await?;
    // Registries are additive: what is in the mirror stays, failed run or not.
    let dirs = repo.dirs(g)?;
    let keep = |out: &mut RepoOutcome| {
        for d in &dirs {
            out.expected.extend(walk_files(d));
        }
    };
    keep(out);

    rp.set_phase(Phase::Indices);
    let plan = match repo.format {
        Format::Crates => crate::cargo::plan(&ctx).await,
        Format::Go => crate::go::plan(&ctx).await,
        Format::Maven => crate::maven::plan(&ctx).await,
        f => bail!("internal: {f} entry given to the registry backend"),
    };
    let plan = match plan {
        Ok(pl) => pl,
        Err(e) => {
            if env.cancel.is_cancelled() {
                bail!("cancelled");
            }
            return Err(e);
        }
    };
    if !plan.summary.is_empty() {
        ctx.info(plan.summary.clone());
    }

    // ---- scan -----------------------------------------------------------------------
    rp.set_phase(Phase::Scanning);
    let all = plan.wants.clone();
    let recheck = env.recheck;
    let (need, present) = tokio::task::spawn_blocking(move || {
        let mut need = Vec::new();
        let mut present = 0u64;
        for w in all {
            let ok = match &w.post {
                PostCheck::None => {
                    let sum = if recheck == Recheck::Hash || w.size.is_none() { w.sum.as_ref() } else { None };
                    file_matches(&w.dest, w.size, sum)
                }
                PostCheck::GoZip { prefix, h1 } => {
                    w.dest.is_file()
                        && (recheck != Recheck::Hash || crate::go::check_zip(&w.dest, prefix, h1.as_deref()).is_ok())
                }
            };
            if ok {
                present += 1;
            } else {
                need.push(w);
            }
        }
        (need, present)
    })
    .await?;
    let total = plan.wants.len() as u64;
    let need_bytes: u64 = need.iter().filter_map(|w| w.size).sum();
    rp.files_total.fetch_add(total, Ordering::Relaxed);
    rp.files_present.fetch_add(present, Ordering::Relaxed);
    rp.bytes_total.fetch_add(need_bytes, Ordering::Relaxed);
    out.pending_files = need.len() as u64;
    out.pending_bytes = need_bytes;
    let unknown = need.iter().filter(|w| w.size.is_none()).count();
    ctx.info(format!(
        "{total} files referenced, {present} present, {} to download ({}{})",
        need.len(),
        human_bytes(need_bytes),
        if unknown > 0 { format!(" + {unknown} of unknown size") } else { String::new() }
    ));
    if env.dry_run {
        out.suites_ok = vec![repo.format.to_string()];
        out.complete = true;
        return Ok(());
    }

    // ---- download ---------------------------------------------------------------------
    rp.set_phase(Phase::Downloading);
    let failed: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let ctx_ref = &ctx;
    futures_util::stream::iter(need)
        .for_each_concurrent(g.threads * 2, |w| {
            let failed = failed.clone();
            async move {
                match download(ctx_ref, &w).await {
                    Ok(()) => {
                        rp.files_fetched.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        if !ctx_ref.cancelled() {
                            p.error(Some(idx), format!("{}: {e:#}", w.label));
                            rp.files_failed.fetch_add(1, Ordering::Relaxed);
                        }
                        if let Some(s) = w.size {
                            rp.bytes_total.fetch_sub(s.min(rp.bytes_total.load(Ordering::Relaxed)), Ordering::Relaxed);
                        }
                        failed.lock().unwrap().push(w.label.clone());
                    }
                }
            }
        })
        .await;
    if env.cancel.is_cancelled() {
        keep(out);
        bail!("cancelled");
    }
    let failed = std::mem::take(&mut *failed.lock().unwrap());

    // ---- publish ------------------------------------------------------------------------
    rp.set_phase(Phase::Publishing);
    let label = repo.format.to_string();
    if !failed.is_empty() && !repo.publish_partial {
        let why = format!("{} file(s) could not be fetched; listings NOT updated, previous state kept", failed.len());
        p.error(Some(idx), why.clone());
        out.suites_failed.push((label, why));
        keep(out);
        return Ok(());
    }
    let publish = plan.publish.clone();
    let n = tokio::task::spawn_blocking(move || -> Result<usize> {
        let mut n = 0;
        for (staged, fin) in &publish {
            if fin.exists() && same_content(staged, fin) {
                continue;
            }
            if let Some(d) = fin.parent() {
                std::fs::create_dir_all(d)?;
            }
            link_or_copy_atomic(staged, fin).with_context(|| format!("publishing {}", fin.display()))?;
            n += 1;
        }
        Ok(n)
    })
    .await??;
    keep(out);
    if failed.is_empty() {
        out.suites_ok.push(label);
    } else {
        out.suites_failed.push((label, "published with missing files (publish_partial)".into()));
    }
    out.complete = out.suites_failed.is_empty();
    ctx.info(if n == 0 { "listings unchanged".to_string() } else { format!("{n} listing/metadata file(s) updated") });
    Ok(())
}

/// Download one file. Files with a post-check go through staging, so the mirror never
/// holds a file that has not passed.
async fn download(ctx: &Ctx<'_>, w: &Want) -> Result<()> {
    let job_dest;
    let via_stage = !matches!(w.post, PostCheck::None);
    let dest: &Path = if via_stage {
        job_dest = ctx.stage_path(w.dest.file_name().and_then(|n| n.to_str()).unwrap_or("file"));
        &job_dest
    } else {
        &w.dest
    };
    let job = Job {
        rh: &ctx.rh,
        url: w.url.clone(),
        alt_url: None,
        dest,
        size: w.size,
        sum: w.sum.clone(),
        label: w.label.clone(),
    };
    match ctx.env.net.fetch(job).await {
        Ok(_) => {}
        Err(FetchError::Cancelled) => bail!("cancelled"),
        Err(e) => bail!("{e}"),
    }
    if let PostCheck::GoZip { prefix, h1 } = &w.post {
        let (staged, fin, prefix, h1) = (dest.to_path_buf(), w.dest.clone(), prefix.clone(), h1.clone());
        tokio::task::spawn_blocking(move || -> Result<()> {
            crate::go::check_zip(&staged, &prefix, h1.as_deref())?;
            if let Some(d) = fin.parent() {
                std::fs::create_dir_all(d)?;
            }
            link_or_copy_atomic(&staged, &fin)?;
            let _ = std::fs::remove_file(&staged);
            Ok(())
        })
        .await??;
    }
    Ok(())
}

pub fn walk_files(dir: &Path) -> Vec<PathBuf> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| !e.file_name().to_string_lossy().ends_with(".cheval-part"))
        .map(|e| e.into_path())
        .collect()
}

fn same_content(a: &Path, b: &Path) -> bool {
    match (std::fs::read(a), std::fs::read(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// Run `f` over `items` with up to `n` at once, collecting results in any order.
pub async fn par<T, R, F, Fut>(items: Vec<T>, n: usize, f: F) -> Vec<R>
where
    F: Fn(T) -> Fut,
    Fut: std::future::Future<Output = R>,
{
    futures_util::stream::iter(items.into_iter().map(f)).buffer_unordered(n).collect().await
}
