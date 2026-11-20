//! Offline verification of the local mirror against its own (signed) indices.
use crate::config::{Config, Repo, VerifyMode};
use crate::meter::{Counters, Meter, Progress};
use crate::plan::{self, IndexKind, PoolFile, Selection};
use crate::release::Release;
use crate::sig::Keyring;
use crate::sync::load_release_text;
use crate::util::{can_decode, file_matches, split_compression};
use anyhow::{Result, bail};
use std::collections::{BTreeMap, HashSet};

#[derive(Default, Debug)]
pub struct Report {
    pub suites: u64,
    pub indices_ok: u64,
    pub files_ok: u64,
    pub problems: Vec<String>,
}

pub fn verify_repo(cfg: &Config, repo: &Repo, full: bool, report: &mut Report) -> Result<()> {
    verify_repo_with(cfg, repo, full, report, Progress::Auto)
}

/// [`verify_repo`], choosing whether progress is shown. The indices are read first, so the
/// package checks run with known totals (bytes for `full`, files otherwise).
pub fn verify_repo_with(cfg: &Config, repo: &Repo, full: bool, report: &mut Report, progress: Progress) -> Result<()> {
    let g = &cfg.global;
    if repo.format != crate::config::Format::Apt {
        let c = cheval_rpm::verify::verify_entry(g, repo, full, progress)?;
        report.suites += c.targets;
        report.indices_ok += c.meta_ok;
        report.files_ok += c.files_ok;
        report.problems.extend(c.problems.into_iter().map(|p| format!("{}: {p}", repo.name)));
        return Ok(());
    }
    let root = repo.root(g)?;
    let filters = repo.filters()?;
    let keyring = match (&repo.keyring, repo.verify(g)) {
        (Some(k), m) if m != VerifyMode::Off => Some(Keyring::load(k)?),
        _ => None,
    };
    let mut seen: HashSet<String> = HashSet::new();
    // Package files to check, with the suite they were listed under.
    let mut checks: Vec<(String, PoolFile)> = Vec::new();
    for suite in &repo.suites {
        let tag = format!("{}/{}", repo.name, suite);
        let dir = root.join(Repo::dist_dir(suite)?);
        let (i, r, s) =
            (dir.join("InRelease").is_file(), dir.join("Release").is_file(), dir.join("Release.gpg").is_file());
        if !i && !r {
            if Repo::is_flat(suite) && ["Packages", "Packages.gz", "Packages.xz"].iter().any(|n| dir.join(n).is_file())
            {
                report.problems.push(format!("{tag}: no Release file (unsigned flat repository) — cannot verify"));
            } else {
                report.problems.push(format!("{tag}: not mirrored yet (no Release in {})", dir.display()));
            }
            continue;
        }
        let text = match load_release_text(&dir, i, r, s, keyring.as_ref()) {
            Ok((t, _)) => t,
            Err(e) => {
                report.problems.push(format!("{tag}: {e:#}"));
                continue;
            }
        };
        let release = Release::parse(&text)?;
        report.suites += 1;
        if let Some(v) = release.valid_until
            && v < chrono::Utc::now()
        {
            report.problems.push(format!("{tag}: Release expired on {v} (clients will reject it; sync again)"));
        }
        let sel = Selection {
            components: &repo.components,
            architectures: repo.architectures(g),
            source: repo.source(g),
            installer: repo.installer,
            pdiffs: repo.pdiffs,
            languages: repo.languages.as_deref(),
            flat: Repo::is_flat(suite),
        };
        let mut groups: BTreeMap<String, Vec<(String, bool)>> = BTreeMap::new();
        for (path, entry) in plan::select(&release, &sel, &filters) {
            let file = dir.join(path);
            let ok = if file.exists() {
                let good = file_matches(&file, Some(entry.size), entry.best().as_ref());
                if good {
                    report.indices_ok += 1;
                } else {
                    report.problems.push(format!("{tag}: index {path} does not match Release"));
                }
                good
            } else {
                false
            };
            groups.entry(split_compression(path).0.to_string()).or_default().push((path.to_string(), ok));
        }
        for (stem, variants) in groups {
            let kind = plan::index_kind(&stem);
            if kind == IndexKind::Other {
                continue;
            }
            let Some((path, _)) = variants.iter().find(|(p, ok)| *ok && can_decode(split_compression(p).1)) else {
                if !filters.may_be_missing(&stem) {
                    report.problems.push(format!("{tag}: no usable copy of index {stem}"));
                }
                continue;
            };
            let mut pool = Vec::new();
            let file = dir.join(path);
            match kind {
                IndexKind::Sources => plan::parse_sources(&file, &filters, &mut pool)?,
                _ => plan::parse_packages(&file, &filters, &mut pool)?,
            };
            for f in pool {
                if seen.insert(f.path.clone()) {
                    checks.push((tag.clone(), f));
                }
            }
        }
    }
    let total_bytes = full.then(|| checks.iter().map(|(_, f)| f.size).sum());
    let meter = Meter::start("verify", total_bytes, std::sync::Arc::new(Counters::default()), progress);
    meter.set_total_files(checks.len() as u64);
    for (tag, f) in checks {
        let sum = if full { f.sum.as_ref() } else { None };
        if file_matches(&root.join(&f.path), Some(f.size), sum) {
            report.files_ok += 1;
        } else if !filters.may_be_missing(&f.path) {
            let what = if root.join(&f.path).exists() { "corrupt" } else { "missing" };
            report.problems.push(format!("{tag}: {what} {}", f.path));
        }
        if full {
            meter.counters().add_bytes(f.size);
        }
        meter.file_done();
    }
    Ok(())
}

pub fn run(cfg: &Config, only: &[String], full: bool) -> Result<bool> {
    run_with(cfg, only, full, Progress::Auto)
}

/// [`run`], choosing whether progress is shown.
pub fn run_with(cfg: &Config, only: &[String], full: bool, progress: Progress) -> Result<bool> {
    let mut report = Report::default();
    for name in only {
        if !cfg.repos.iter().any(|r| &r.name == name) {
            bail!("--only {name}: no such repository");
        }
    }
    for repo in cfg.repos.iter().filter(|r| r.enabled && (only.is_empty() || only.contains(&r.name))) {
        eprintln!("verifying {} ({})...", repo.name, if full { "full checksums" } else { "presence and size" });
        if let Err(e) = verify_repo_with(cfg, repo, full, &mut report, progress) {
            report.problems.push(format!("{}: {e:#}", repo.name));
        }
    }
    println!(
        "{} suite(s), {} index files and {} package files verified, {} problem(s)",
        report.suites,
        report.indices_ok,
        report.files_ok,
        report.problems.len()
    );
    for p in report.problems.iter().take(200) {
        println!("  PROBLEM {p}");
    }
    if report.problems.len() > 200 {
        println!("  ... and {} more", report.problems.len() - 200);
    }
    Ok(report.problems.is_empty())
}
