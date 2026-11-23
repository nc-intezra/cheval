//! Offline checks of `crates`, `go` and `maven` entries against what the mirror lists:
//! every listed version must have its files; with `full`, their checksums are checked too.
use crate::config::{Format, Global, Repo};
use crate::util::{HashAlgo, hash_file};
use anyhow::{Context, Result};
use cheval_core::meter::{Counters, Meter, Progress};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct Counts {
    /// Index or listing files read.
    pub meta_ok: u64,
    /// Package files found correct.
    pub files_ok: u64,
    pub problems: Vec<String>,
}

enum How {
    /// Present, or with `full` matching this digest.
    Digest(HashAlgo, String),
    /// A Go module zip: well-formed under the prefix, with the `h1:` hash when known.
    GoZip(String, Option<String>),
    Present,
}

struct Check {
    path: PathBuf,
    how: How,
}

pub fn verify_entry(g: &Global, repo: &Repo, full: bool, progress: Progress) -> Result<Counts> {
    let mut c = Counts::default();
    let root = repo.root(g)?;
    if !root.is_dir() {
        c.problems.push(format!("not mirrored yet ({} does not exist)", root.display()));
        return Ok(c);
    }
    let mut checks = Vec::new();
    match repo.format {
        Format::Crates => crates(g, &root, &mut c, &mut checks)?,
        Format::Go => go(repo, &root, &mut c, &mut checks)?,
        Format::Maven => maven(&root, &mut c, &mut checks),
        _ => {}
    }
    let total_bytes =
        full.then(|| checks.iter().filter_map(|k| std::fs::metadata(&k.path).ok()).map(|m| m.len()).sum());
    let meter = Meter::start("verify", total_bytes, Arc::new(Counters::default()), progress);
    meter.set_total_files(checks.len() as u64);
    for k in checks {
        let r: Result<()> = (|| {
            let md = std::fs::metadata(&k.path).context("missing")?;
            if full {
                meter.counters().add_bytes(md.len());
                match &k.how {
                    How::Digest(a, want) => {
                        let got = hash_file(&k.path, *a)?;
                        anyhow::ensure!(got.eq_ignore_ascii_case(want), "corrupt (checksum differs)");
                    }
                    How::GoZip(prefix, h1) => {
                        crate::go::check_zip(&k.path, prefix, h1.as_deref())?;
                    }
                    How::Present => {}
                }
            }
            Ok(())
        })();
        match r {
            Ok(()) => c.files_ok += 1,
            Err(e) => c.problems.push(format!("{}: {e:#}", k.path.display())),
        }
        meter.file_done();
    }
    Ok(c)
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    crate::engine::walk_files(dir)
}

fn crates(g: &Global, root: &Path, c: &mut Counts, checks: &mut Vec<Check>) -> Result<()> {
    let cfg = std::fs::read(root.join("config.json")).context("not mirrored yet (no config.json)")?;
    let cfg: serde_json::Value = serde_json::from_slice(&cfg).context("config.json")?;
    let dl = cfg.get("dl").and_then(|v| v.as_str()).context("config.json has no dl")?.to_string();
    c.meta_ok += 1;
    for f in files_under(root) {
        if f.file_name().is_some_and(|n| n == "config.json") {
            continue;
        }
        let Ok(data) = std::fs::read(&f) else { continue };
        let (lines, bad) = crate::cargo::parse_index(&data);
        if bad > 0 {
            c.problems.push(format!("{}: {bad} unreadable index line(s)", f.display()));
        }
        c.meta_ok += 1;
        for (_, l) in lines {
            let url = crate::cargo::download_url(&dl, &l.name, &l.vers, &l.cksum)?;
            let path = crate::config::url_dir(g, url.as_str())?;
            checks.push(Check { path, how: How::Digest(HashAlgo::Sha256, l.cksum) });
        }
    }
    Ok(())
}

fn go(repo: &Repo, root: &Path, c: &mut Counts, checks: &mut Vec<Check>) -> Result<()> {
    let mut sums = crate::go::Sums::new();
    for l in &repo.lockfiles {
        if let Ok(t) = std::fs::read_to_string(l) {
            sums.extend(crate::go::read_go_sum(&t).unwrap_or_default());
        }
    }
    for f in files_under(root) {
        let Some(name) = f.file_name().map(|n| n.to_string_lossy().into_owned()) else { continue };
        let Some(dir) = f.parent() else { continue };
        if !dir.ends_with("@v") {
            continue;
        }
        let Some(module) = dir
            .parent()
            .and_then(|m| m.strip_prefix(root).ok())
            .and_then(|m| crate::go::unescape(&m.to_string_lossy()))
        else {
            continue;
        };
        if name == "list" {
            c.meta_ok += 1;
            for v in std::fs::read_to_string(&f).unwrap_or_default().lines().filter(|l| !l.is_empty()) {
                let e = crate::go::escape(v);
                for ext in ["info", "mod"] {
                    checks.push(Check { path: dir.join(format!("{e}.{ext}")), how: How::Present });
                }
            }
        } else if let Some(ev) = name.strip_suffix(".zip") {
            let Some(v) = crate::go::unescape(ev) else { continue };
            let h1 = sums.get(&(module.clone(), v.clone())).and_then(|s| s.0.clone());
            checks.push(Check { path: f.clone(), how: How::GoZip(format!("{module}@{v}/"), h1) });
            checks.push(Check { path: dir.join(format!("{ev}.mod")), how: How::Present });
        } else if let Some(ev) = name.strip_suffix(".mod") {
            let Some(v) = crate::go::unescape(ev) else { continue };
            if let Some(h) = sums.get(&(module.clone(), v)).and_then(|s| s.1.clone()) {
                let data = std::fs::read(&f)?;
                if crate::go::mod_h1(&data) != h {
                    c.problems.push(format!("{}: go.mod hash differs from go.sum", f.display()));
                }
            }
        }
    }
    Ok(())
}

fn maven(root: &Path, c: &mut Counts, checks: &mut Vec<Check>) {
    for f in files_under(root) {
        let s = f.to_string_lossy().into_owned();
        if let Some(main) = s.strip_suffix(".sha1") {
            let hex = std::fs::read_to_string(&f)
                .unwrap_or_default()
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            let main = PathBuf::from(main);
            if hex.len() == 40 {
                checks.push(Check { path: main, how: How::Digest(HashAlgo::Sha1, hex) });
            } else {
                c.problems.push(format!("{}: unreadable", f.display()));
            }
        } else if s.ends_with("/maven-metadata.xml") {
            c.meta_ok += 1;
            let Some(dir) = f.parent() else { continue };
            let a = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let (vs, _) = crate::maven::metadata_versions(&std::fs::read(&f).unwrap_or_default());
            for v in vs {
                let pom = dir.join(&v).join(format!("{a}-{v}.pom"));
                // Group-level plugin metadata lists plugins, not versions.
                if !vs_is_plugin_listing(&f) {
                    checks.push(Check { path: pom, how: How::Present });
                }
            }
        }
    }
}

fn vs_is_plugin_listing(f: &Path) -> bool {
    std::fs::read_to_string(f).map(|s| s.contains("<plugins>")).unwrap_or(false)
}
