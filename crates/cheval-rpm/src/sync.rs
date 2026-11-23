//! Syncing `rpm` and `files` entries. Each entry expands into one or more repositories
//! (targets); a target that fails is reported on its own and the others carry on.
//!
//! RPM, per target:
//! 1. fetch `repodata/repomd.xml` and check it can be trusted: `repomd.xml.asc` against
//!    the keyring, or the checksum in a metalink, else (with a warning) HTTPS alone;
//! 2. fetch every metadata file it lists into staging, checking each checksum;
//! 3. read the package list from `primary.xml`, skip source packages and filtered ones;
//! 4. download missing packages straight into the mirror (each lands complete or not at all);
//! 5. publish: metadata files, then `repomd.xml.asc`, then `repomd.xml` last. The previous
//!    generation of metadata stays (cleanup leaves it), so a client that read the old
//!    `repomd.xml` a moment ago still finds its files.
//!
//! Files (ISOs), per target: fetch the checksum lists (and their signature), pick the names
//! `include` allows, download what is missing or changed, store identical files once (hard
//! links), then publish the lists themselves.
use crate::config::{Format, Global, Recheck, Repo, Target, VerifyMode};
use crate::http::{FetchError, Job, Net, RepoHttp};
use crate::meta::{self, Package, Repomd};
use crate::progress::{Phase, Progress};
use crate::sig::Keyring;
use crate::summary::RepoOutcome;
use crate::sums::{self, Listed};
use crate::util::{self, Checksum, file_matches, glob_match, human_bytes, link_or_copy_atomic, safe_rel_path};
use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
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

/// A file to download into the mirror.
#[derive(Debug, Clone)]
struct Want {
    /// Absolute destination.
    dest: PathBuf,
    /// Relative to the entry's base URL.
    rel: String,
    size: Option<u64>,
    sum: Checksum,
    /// Which target it belongs to (index into the plan list, set when the plan is added).
    target: usize,
}

/// One target's plan, built before anything is downloaded.
struct Plan {
    target: Target,
    /// Staged metadata to publish, in order: (staged, final). The root file comes last.
    publish: Vec<(PathBuf, PathBuf)>,
    /// Files that must stay (published now, or still needed).
    expected: Vec<PathBuf>,
    wants: Vec<Want>,
    /// Identical files stored once: (existing copy, other names).
    links: Vec<(PathBuf, Vec<PathBuf>)>,
    /// Nothing changed upstream since the last run.
    unchanged: bool,
}

/// Sync one `rpm` or `files` entry.
pub async fn sync_entry(env: &Env<'_>, idx: usize, repo: &Repo, staging: &Path, out: &mut RepoOutcome) -> Result<()> {
    let p = env.progress;
    let rp = &p.repos[idx];
    let g = env.g;
    let rh = Arc::new(RepoHttp::new(idx, repo, g)?);
    let keyring = match &repo.keyring {
        Some(k) => Some(Keyring::load(k).with_context(|| format!("keyring {}", k.display()))?),
        None => None,
    };
    let filters = Arc::new(repo.filters()?);
    let prefix = repo.base_url()?;

    // ---- metadata ---------------------------------------------------------------
    rp.set_phase(Phase::Release);
    let mut plans: Vec<Plan> = Vec::new();
    for target in repo.targets(g)? {
        if env.cancel.is_cancelled() {
            bail!("cancelled");
        }
        let rel = target.url.path().strip_prefix(prefix.path()).unwrap_or("").to_string();
        let rel = percent_decode(&rel);
        let stage = staging.join(safe_rel_path(target.label.trim_matches('/')).unwrap_or_else(|_| PathBuf::from("t")));
        let made = match repo.format {
            Format::Rpm => plan_rpm(env, idx, repo, &rh, keyring.as_ref(), &filters, &target, &rel, &stage).await,
            Format::Files => plan_files(env, idx, repo, &rh, keyring.as_ref(), &target, &rel, &stage).await,
            _ => bail!("internal: {} entry given to the RPM backend", repo.format),
        };
        match made {
            Ok(mut plan) => {
                plan.target = target;
                // Downloads report failures by plan number.
                for w in &mut plan.wants {
                    w.target = plans.len();
                }
                plans.push(plan);
            }
            Err(e) => {
                if env.cancel.is_cancelled() {
                    bail!("cancelled");
                }
                p.error(Some(idx), format!("{}: {e:#}", target.label));
                out.suites_failed.push((target.label.clone(), format!("{e:#}")));
                // Keep whatever is there: a failed target is not cleaned.
                if target.dir.exists() {
                    out.expected.extend(walk_files(&target.dir));
                }
            }
        }
    }

    // ---- scan -----------------------------------------------------------------------
    rp.set_phase(Phase::Scanning);
    let all: Vec<Want> = plans.iter().flat_map(|pl| pl.wants.iter().cloned()).collect();
    let recheck = env.recheck;
    let (need, present) = tokio::task::spawn_blocking(move || {
        let mut need = Vec::new();
        let mut present = 0u64;
        // A file wanted by two targets (or listed twice) is fetched once.
        let mut seen = HashSet::new();
        for w in all {
            if !seen.insert(w.dest.clone()) {
                continue;
            }
            let sum = if recheck == Recheck::Hash || w.size.is_none() { Some(&w.sum) } else { None };
            if file_matches(&w.dest, w.size, sum) {
                present += 1;
            } else {
                need.push(w);
            }
        }
        (need, present)
    })
    .await?;
    let total: u64 = plans.iter().map(|pl| pl.wants.len() as u64).sum();
    let need_bytes: u64 = need.iter().filter_map(|w| w.size).sum();
    rp.files_total.fetch_add(total, Ordering::Relaxed);
    rp.files_present.fetch_add(present, Ordering::Relaxed);
    rp.bytes_total.fetch_add(need_bytes, Ordering::Relaxed);
    out.pending_files = need.len() as u64;
    out.pending_bytes = need_bytes;
    let unknown = need.iter().filter(|w| w.size.is_none()).count();
    p.info(
        Some(idx),
        format!(
            "{total} files referenced, {present} present, {} to download ({}{})",
            need.len(),
            human_bytes(need_bytes),
            if unknown > 0 { format!(" + {unknown} of unknown size") } else { String::new() }
        ),
    );
    if env.dry_run {
        out.suites_ok = plans.iter().map(|pl| pl.target.label.clone()).collect();
        out.complete = out.suites_failed.is_empty();
        return Ok(());
    }

    // ---- download ---------------------------------------------------------------------
    rp.set_phase(Phase::Downloading);
    let failed: Arc<Mutex<HashSet<usize>>> = Arc::new(Mutex::new(HashSet::new()));
    let failed_files: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    futures_util::stream::iter(need)
        .for_each_concurrent(g.threads * 2, |w| {
            let (rh, failed, failed_files, filters) =
                (rh.clone(), failed.clone(), failed_files.clone(), filters.clone());
            async move {
                let url = match rh.url_for(&w.rel) {
                    Ok(u) => u,
                    Err(e) => {
                        p.error(Some(idx), format!("{}: {e}", w.rel));
                        failed.lock().unwrap().insert(w.target);
                        return;
                    }
                };
                let job = Job {
                    rh: &rh,
                    url,
                    alt_url: None,
                    dest: &w.dest,
                    size: w.size,
                    sum: Some(w.sum.clone()),
                    label: w.rel.clone(),
                };
                match env.net.fetch(job).await {
                    Ok(_) => {
                        rp.files_fetched.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(FetchError::Cancelled) => {
                        failed.lock().unwrap().insert(w.target);
                    }
                    Err(e) => {
                        if let Some(s) = w.size {
                            rp.bytes_total.fetch_sub(s.min(rp.bytes_total.load(Ordering::Relaxed)), Ordering::Relaxed);
                        }
                        if filters.may_be_missing(&w.rel) {
                            p.warn(Some(idx), format!("{}: {e} (ignored by ignore_missing)", w.rel));
                        } else {
                            p.error(Some(idx), format!("{}: {e}", w.rel));
                            rp.files_failed.fetch_add(1, Ordering::Relaxed);
                            failed.lock().unwrap().insert(w.target);
                            failed_files.lock().unwrap().push(w.rel.clone());
                        }
                    }
                }
            }
        })
        .await;
    if env.cancel.is_cancelled() {
        bail!("cancelled");
    }
    let failed = std::mem::take(&mut *failed.lock().unwrap());

    // ---- publish ------------------------------------------------------------------------
    rp.set_phase(Phase::Publishing);
    for (i, pl) in plans.iter().enumerate() {
        let label = &pl.target.label;
        // Old files always stay expected for a target that does not publish.
        if failed.contains(&i) && !repo.publish_partial {
            let n = pl.wants.iter().filter(|w| !w.dest.exists()).count();
            let why = format!("{n} file(s) could not be fetched; new metadata NOT published, previous state kept");
            p.error(Some(idx), format!("{label}: {why}"));
            out.suites_failed.push((label.clone(), why));
            out.expected.extend(walk_files(&pl.target.dir));
            out.expected.extend(pl.wants.iter().map(|w| w.dest.clone()));
            continue;
        }
        let (publish, links) = (pl.publish.clone(), pl.links.clone());
        let done = tokio::task::spawn_blocking(move || -> Result<usize> {
            for (have, others) in &links {
                for o in others {
                    if have.exists() && !same_file(have, o) {
                        link_or_copy_atomic(have, o)?;
                    }
                }
            }
            let mut n = 0;
            for (staged, fin) in &publish {
                if fin.exists() && same_content(staged, fin) {
                    continue;
                }
                link_or_copy_atomic(staged, fin).with_context(|| format!("publishing {}", fin.display()))?;
                n += 1;
            }
            Ok(n)
        })
        .await?;
        match done {
            Ok(n) => {
                if failed.contains(&i) {
                    let why = "published with missing files (publish_partial)".to_string();
                    p.warn(Some(idx), format!("{label}: {why}"));
                    out.suites_failed.push((label.clone(), why));
                } else {
                    if pl.unchanged && n == 0 {
                        p.info(Some(idx), format!("{label} is up to date"));
                    } else {
                        p.info(Some(idx), format!("{label} published ({n} metadata files updated)"));
                    }
                    out.suites_ok.push(label.clone());
                }
                out.expected.extend(pl.expected.iter().cloned());
                out.expected.extend(pl.wants.iter().map(|w| w.dest.clone()));
                out.expected.extend(pl.links.iter().flat_map(|(_, o)| o.iter().cloned()));
            }
            Err(e) => {
                p.error(Some(idx), format!("{label}: publishing failed: {e:#}"));
                out.suites_failed.push((label.clone(), format!("publishing failed: {e:#}")));
                out.expected.extend(walk_files(&pl.target.dir));
            }
        }
    }
    out.complete = out.suites_failed.is_empty();
    Ok(())
}

fn percent_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={}", s.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

fn walk_files(dir: &Path) -> Vec<PathBuf> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect()
}

#[cfg(unix)]
fn same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(x), Ok(y)) => x.dev() == y.dev() && x.ino() == y.ino(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn same_file(_: &Path, _: &Path) -> bool {
    false
}

fn same_content(a: &Path, b: &Path) -> bool {
    match (std::fs::read(a), std::fs::read(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// Fetch a small file (metadata, signature, checksum list) into `dest`; `Ok(None)` if the
/// server says it does not exist.
async fn fetch_small(
    env: &Env<'_>,
    rh: &RepoHttp,
    url: Url,
    dest: &Path,
    sum: Option<Checksum>,
    size: Option<u64>,
) -> Result<Option<()>> {
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let label = url.path().rsplit('/').next().unwrap_or("").to_string();
    let job = Job { rh, url: url.clone(), alt_url: None, dest, size, sum, label };
    match env.net.fetch(job).await {
        Ok(_) => Ok(Some(())),
        Err(e) if e.is_not_found() => Ok(None),
        Err(FetchError::Cancelled) => bail!("cancelled"),
        Err(e) => Err(anyhow::anyhow!("{url}: {e}")),
    }
}

/// Decide whether `repomd.xml` can be trusted, per the entry's keyring, metalink and
/// verify policy.
#[allow(clippy::too_many_arguments)]
async fn check_repomd(
    env: &Env<'_>,
    idx: usize,
    repo: &Repo,
    rh: &RepoHttp,
    keyring: Option<&Keyring>,
    target: &Target,
    repomd: &[u8],
    asc: Option<&[u8]>,
    stage: &Path,
) -> Result<()> {
    let mode = repo.verify(env.g);
    if mode == VerifyMode::Off {
        return Ok(());
    }
    if let (Some(k), Some(sig)) = (keyring, asc) {
        let fp = k.verify_detached(sig, repomd).context("repomd.xml.asc does not verify")?;
        env.progress.info(Some(idx), format!("{}: repomd.xml signed by {fp}", target.label));
        return Ok(());
    }
    if let Some(ml) = &repo.metalink {
        let url = fill(ml, &target.label, repo);
        let url = Url::parse(&url).with_context(|| format!("metalink {url}"))?;
        let dest = stage.join("metalink.xml");
        fetch_small(env, rh, url.clone(), &dest, None, None)
            .await?
            .with_context(|| format!("metalink {url} not found"))?;
        let sums = meta::parse_metalink(&std::fs::read(&dest)?).with_context(|| format!("metalink {url}"))?;
        for s in &sums {
            let mut h = util::Hasher::new(s.algo);
            h.update(repomd);
            if h.finish() == s.hex {
                return Ok(());
            }
        }
        bail!("repomd.xml does not match the metalink ({url}): a stale or tampered mirror");
    }
    if keyring.is_some() && asc.is_none() {
        if mode == VerifyMode::Require {
            bail!("no repomd.xml.asc upstream, and verify = \"require\"");
        }
        env.progress.warn(Some(idx), format!("{}: no repomd.xml.asc upstream; trusting HTTPS only", target.label));
        return Ok(());
    }
    if mode == VerifyMode::Require {
        bail!("verify = \"require\" needs a keyring or a metalink");
    }
    Ok(())
}

/// Fill the placeholders of `template` with the values a target was made from.
fn fill(template: &str, label: &str, repo: &Repo) -> String {
    let mut parts = label.split('/');
    let mut s = template.to_string();
    for (ph, used) in [
        ("{release}", repo.url.contains("{release}")),
        ("{repo}", repo.url.contains("{repo}")),
        ("{arch}", repo.url.contains("{arch}")),
    ] {
        if used && let Some(v) = parts.next() {
            s = s.replace(ph, v);
        }
    }
    s
}

#[allow(clippy::too_many_arguments)]
async fn plan_rpm(
    env: &Env<'_>,
    idx: usize,
    repo: &Repo,
    rh: &RepoHttp,
    keyring: Option<&Keyring>,
    filters: &Arc<crate::config::Filters>,
    target: &Target,
    rel: &str,
    stage: &Path,
) -> Result<Plan> {
    let p = env.progress;
    let dir = &target.dir;
    let url = |f: &str| rh.url_for(&format!("{rel}{f}"));
    // repomd.xml and its signature, staged.
    let repomd_stage = stage.join("repodata/repomd.xml");
    let _ = tokio::fs::remove_file(&repomd_stage).await;
    fetch_small(env, rh, url("repodata/repomd.xml")?, &repomd_stage, None, None)
        .await?
        .with_context(|| format!("no repodata/repomd.xml at {} (not an RPM repository?)", target.url))?;
    let repomd_bytes = std::fs::read(&repomd_stage)?;
    let asc_stage = stage.join("repodata/repomd.xml.asc");
    let _ = tokio::fs::remove_file(&asc_stage).await;
    let asc = if keyring.is_some() {
        fetch_small(env, rh, url("repodata/repomd.xml.asc")?, &asc_stage, None, None)
            .await?
            .map(|_| std::fs::read(&asc_stage))
            .transpose()?
    } else {
        None
    };
    check_repomd(env, idx, repo, rh, keyring, target, &repomd_bytes, asc.as_deref(), stage).await?;
    let md: Repomd = meta::parse_repomd(&repomd_bytes)?;
    let unchanged = std::fs::read(dir.join("repodata/repomd.xml")).map(|b| b == repomd_bytes).unwrap_or(false);

    // Every metadata file it lists, checked; reused from the mirror when already there.
    p.repos[idx].set_phase(Phase::Indices);
    let mut publish = Vec::new();
    let mut expected = Vec::new();
    let mut seen = HashSet::new();
    for e in &md.entries {
        if !seen.insert(e.href.clone()) {
            continue;
        }
        let fin = dir.join(safe_rel_path(&e.href)?);
        let staged = stage.join(safe_rel_path(&e.href)?);
        if file_matches(&fin, e.size, Some(&e.checksum)) {
            expected.push(fin);
            continue;
        }
        fetch_small(env, rh, url(&e.href)?, &staged, Some(e.checksum.clone()), e.size)
            .await?
            .with_context(|| format!("{} is listed in repomd.xml but missing upstream", e.href))?;
        publish.push((staged, fin.clone()));
        expected.push(fin);
    }
    // The previous generation stays one more run.
    if let Ok(old) = std::fs::read(dir.join("repodata/repomd.xml"))
        && let Ok(old) = meta::parse_repomd(&old)
    {
        for e in old.entries {
            if let Ok(r) = safe_rel_path(&e.href) {
                expected.push(dir.join(r));
            }
        }
    }

    // Packages from primary.xml.
    let primary = md.primary().context("repomd.xml lists no primary metadata")?;
    let primary_path = {
        let staged = stage.join(safe_rel_path(&primary.href)?);
        if staged.exists() { staged } else { dir.join(safe_rel_path(&primary.href)?) }
    };
    let (rel_owned, dir_owned) = (rel.to_string(), dir.clone());
    let filters = filters.clone();
    let (wants, skipped_src, skipped_filter) = tokio::task::spawn_blocking(move || -> Result<(Vec<Want>, u64, u64)> {
        let mut wants = Vec::new();
        let (mut src, mut filtered) = (0u64, 0u64);
        let input = util::open_decoded(&primary_path)?;
        meta::read_primary(input, |pkg: Package| {
            if pkg.is_source() {
                src += 1;
                return Ok(());
            }
            if !filters.package_wanted(&pkg.name) || filters.path_excluded(&pkg.href) {
                filtered += 1;
                return Ok(());
            }
            wants.push(Want {
                dest: dir_owned.join(safe_rel_path(&pkg.href)?),
                rel: format!("{rel_owned}{}", pkg.href),
                size: Some(pkg.size),
                sum: pkg.checksum,
                target: usize::MAX,
            });
            Ok(())
        })?;
        Ok((wants, src, filtered))
    })
    .await??;
    if skipped_src + skipped_filter > 0 {
        p.info(
            Some(idx),
            format!("{}: skipping {skipped_src} source and {skipped_filter} filtered package(s)", target.label),
        );
    }
    // Root files last: signature, then repomd.xml.
    if asc.is_some() {
        publish.push((asc_stage, dir.join("repodata/repomd.xml.asc")));
        expected.push(dir.join("repodata/repomd.xml.asc"));
    }
    publish.push((repomd_stage, dir.join("repodata/repomd.xml")));
    expected.push(dir.join("repodata/repomd.xml"));
    Ok(Plan { target: target.clone(), publish, expected, wants, links: Vec::new(), unchanged })
}

#[allow(clippy::too_many_arguments)]
async fn plan_files(
    env: &Env<'_>,
    idx: usize,
    repo: &Repo,
    rh: &RepoHttp,
    keyring: Option<&Keyring>,
    target: &Target,
    rel: &str,
    stage: &Path,
) -> Result<Plan> {
    let p = env.progress;
    let dir = &target.dir;
    let url = |f: &str| rh.url_for(&format!("{rel}{f}"));
    let mut publish = Vec::new();
    let mut listed: BTreeMap<String, Listed> = BTreeMap::new();
    let mut first: Option<(Vec<u8>, String)> = None;
    for name in &repo.checksums {
        let staged = stage.join(name);
        let _ = tokio::fs::remove_file(&staged).await;
        fetch_small(env, rh, url(name)?, &staged, None, None)
            .await?
            .with_context(|| format!("checksum list {name} not found at {}", target.url))?;
        let bytes = std::fs::read(&staged)?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if first.is_none() {
            first = Some((bytes, text.clone()));
        }
        sums::parse_into(&text, &mut listed).with_context(|| name.to_string())?;
        publish.push((staged, dir.join(name)));
    }
    // The signature covers the first list: detached, or a clear-signed copy of it.
    let mode = repo.verify(env.g);
    if let Some(sig_name) = &repo.signature {
        let staged = stage.join(sig_name);
        let _ = tokio::fs::remove_file(&staged).await;
        let got = fetch_small(env, rh, url(sig_name)?, &staged, None, None).await?;
        match (got, keyring, mode) {
            (_, _, VerifyMode::Off) => {}
            (None, _, VerifyMode::Require) => bail!("signature {sig_name} not found, and verify = \"require\""),
            (None, _, _) => {
                p.warn(Some(idx), format!("{}: signature {sig_name} not found; trusting HTTPS only", target.label))
            }
            (Some(()), None, VerifyMode::Require) => bail!("verify = \"require\" needs a keyring"),
            (Some(()), None, _) => {
                p.warn(Some(idx), format!("{}: no keyring configured; {sig_name} not checked", target.label))
            }
            (Some(()), Some(k), _) => {
                let sig = std::fs::read(&staged)?;
                let (data, _) = first.as_ref().context("no checksum list")?;
                let fp = if sig.starts_with(b"-----BEGIN PGP SIGNED MESSAGE-----") {
                    let (signed, fp) = k
                        .verify_cleartext(&String::from_utf8_lossy(&sig))
                        .with_context(|| format!("{sig_name} does not verify"))?;
                    // Use what was signed, not the unsigned copy.
                    listed.clear();
                    sums::parse_into(&signed, &mut listed)?;
                    fp
                } else {
                    k.verify_detached(&sig, data).with_context(|| format!("{sig_name} does not verify"))?
                };
                p.info(Some(idx), format!("{}: checksums signed by {fp}", target.label));
            }
        }
        if staged.exists() {
            publish.push((staged, dir.join(sig_name)));
        }
    } else if mode == VerifyMode::Require {
        bail!("verify = \"require\" needs `signature`");
    }
    listed.retain(|_, l| !l.sums.is_empty());
    // Pick the files.
    let mut picked: Vec<(String, Listed)> = Vec::new();
    for pat in &repo.include {
        let before = picked.len();
        for (name, l) in &listed {
            if glob_match(pat, name) && !picked.iter().any(|(n, _)| n == name) {
                picked.push((name.clone(), l.clone()));
            }
        }
        if picked.len() == before && !picked.iter().any(|(n, _)| glob_match(pat, n)) {
            bail!("include pattern {pat:?} matches nothing in {}", repo.checksums.join(", "));
        }
    }
    if repo.include.is_empty() {
        picked = listed.into_iter().collect();
    }
    let mut wants = Vec::new();
    let mut links: Vec<(PathBuf, Vec<PathBuf>)> = Vec::new();
    let mut by_hash: HashMap<String, usize> = HashMap::new();
    for (name, l) in picked {
        let sum = l.best().context("no checksum")?.clone();
        if sum.algo.is_weak() {
            p.warn(Some(idx), format!("{}: {name} is only listed with {:?}", target.label, sum.algo));
        }
        let dest = dir.join(&name);
        match by_hash.get(&sum.hex) {
            Some(&k) => {
                let have = wants.get(k).map(|w: &Want| w.dest.clone()).unwrap_or_default();
                match links.iter_mut().find(|(h, _)| *h == have) {
                    Some((_, o)) => o.push(dest),
                    None => links.push((have, vec![dest])),
                }
            }
            None => {
                by_hash.insert(sum.hex.clone(), wants.len());
                wants.push(Want { dest, rel: format!("{rel}{name}"), size: l.size, sum, target: usize::MAX });
            }
        }
    }
    let expected = publish.iter().map(|(_, f)| f.clone()).collect();
    let unchanged = publish.iter().all(|(s, f)| same_content(s, f));
    Ok(Plan { target: target.clone(), publish, expected, wants, links, unchanged })
}
