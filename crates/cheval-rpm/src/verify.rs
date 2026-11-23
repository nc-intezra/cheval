//! Offline checks of `rpm` and `files` entries against the metadata stored in the mirror,
//! the counterpart of APT's `verify`: what `repomd.xml` (or the checksum list) promises must
//! be there, with the right size, or with `full` the right checksum.
use crate::config::{Format, Global, Repo, Target, VerifyMode};
use crate::meta;
use crate::meter::{Counters, Meter, Progress};
use crate::sig::Keyring;
use crate::sums;
use crate::util::{self, Checksum, file_matches, glob_match, safe_rel_path};
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Default)]
pub struct Counts {
    /// Repositories (targets) looked at.
    pub targets: u64,
    /// Metadata files and checksum lists found correct.
    pub meta_ok: u64,
    /// Packages or listed files found correct.
    pub files_ok: u64,
    pub problems: Vec<String>,
}

/// A file to check.
struct Check {
    label: String,
    path: PathBuf,
    size: Option<u64>,
    sum: Checksum,
}

/// Check every repository of an `rpm` or `files` entry.
pub fn verify_entry(g: &Global, repo: &Repo, full: bool, progress: Progress) -> Result<Counts> {
    let mut c = Counts::default();
    let keyring = match (&repo.keyring, repo.verify(g)) {
        (Some(k), m) if m != VerifyMode::Off => Some(Keyring::load(k)?),
        _ => None,
    };
    let filters = repo.filters()?;
    let mut checks: Vec<Check> = Vec::new();
    for t in repo.targets(g)? {
        c.targets += 1;
        let r = match repo.format {
            Format::Rpm => rpm_target(&t, keyring.as_ref(), &filters, &mut c, &mut checks),
            Format::Files => files_target(repo, &t, keyring.as_ref(), &mut c, &mut checks),
            _ => Ok(()),
        };
        if let Err(e) = r {
            c.problems.push(format!("{}: {e:#}", t.label));
        }
    }
    let total_bytes = full.then(|| checks.iter().filter_map(|k| k.size).sum());
    let meter = Meter::start("verify", total_bytes, std::sync::Arc::new(Counters::default()), progress);
    meter.set_total_files(checks.len() as u64);
    for k in checks {
        // Without a known size, presence alone says little: hash it.
        let sum = if full || k.size.is_none() { Some(&k.sum) } else { None };
        if file_matches(&k.path, k.size, sum) {
            c.files_ok += 1;
        } else {
            let what = if k.path.exists() { "corrupt" } else { "missing" };
            c.problems.push(format!("{}: {what} {}", k.label, k.path.display()));
        }
        if full {
            meter.counters().add_bytes(k.size.unwrap_or(0));
        }
        meter.file_done();
    }
    Ok(c)
}

fn rpm_target(
    t: &Target,
    keyring: Option<&Keyring>,
    filters: &crate::config::Filters,
    c: &mut Counts,
    checks: &mut Vec<Check>,
) -> Result<()> {
    let repomd_path = t.dir.join("repodata/repomd.xml");
    let bytes = std::fs::read(&repomd_path).context("not mirrored yet (no repodata/repomd.xml)")?;
    if let Some(k) = keyring
        && let Ok(sig) = std::fs::read(t.dir.join("repodata/repomd.xml.asc"))
    {
        k.verify_detached(&sig, &bytes).context("repomd.xml.asc does not verify")?;
    }
    let md = meta::parse_repomd(&bytes)?;
    for e in &md.entries {
        let path = t.dir.join(safe_rel_path(&e.href)?);
        if file_matches(&path, e.size, Some(&e.checksum)) {
            c.meta_ok += 1;
        } else {
            let what = if path.exists() { "corrupt" } else { "missing" };
            c.problems.push(format!("{}: {what} metadata {}", t.label, e.href));
        }
    }
    let primary = md.primary().context("repomd.xml lists no primary metadata")?;
    let input = util::open_decoded(&t.dir.join(safe_rel_path(&primary.href)?))?;
    meta::read_primary(input, |p| {
        if !p.is_source() && filters.package_wanted(&p.name) && !filters.path_excluded(&p.href) {
            checks.push(Check {
                label: t.label.clone(),
                path: t.dir.join(safe_rel_path(&p.href)?),
                size: Some(p.size),
                sum: p.checksum,
            });
        }
        Ok(())
    })?;
    Ok(())
}

fn files_target(
    repo: &Repo,
    t: &Target,
    keyring: Option<&Keyring>,
    c: &mut Counts,
    checks: &mut Vec<Check>,
) -> Result<()> {
    let mut listed = BTreeMap::new();
    let mut first: Option<Vec<u8>> = None;
    for name in &repo.checksums {
        let bytes = std::fs::read(t.dir.join(name)).with_context(|| format!("not mirrored yet (no {name})"))?;
        sums::parse_into(&String::from_utf8_lossy(&bytes), &mut listed)?;
        first.get_or_insert(bytes);
        c.meta_ok += 1;
    }
    if let (Some(k), Some(sig_name)) = (keyring, &repo.signature)
        && let Ok(sig) = std::fs::read(t.dir.join(sig_name))
    {
        if sig.starts_with(b"-----BEGIN PGP SIGNED MESSAGE-----") {
            let (signed, _) = k
                .verify_cleartext(&String::from_utf8_lossy(&sig))
                .with_context(|| format!("{sig_name} does not verify"))?;
            listed.clear();
            sums::parse_into(&signed, &mut listed)?;
        } else {
            k.verify_detached(&sig, first.as_deref().unwrap_or_default())
                .with_context(|| format!("{sig_name} does not verify"))?;
        }
    }
    for (name, l) in listed {
        if !repo.include.is_empty() && !repo.include.iter().any(|p| glob_match(p, &name)) {
            continue;
        }
        if let Some(sum) = l.best() {
            checks.push(Check { label: t.label.clone(), path: t.dir.join(&name), size: l.size, sum: sum.clone() });
        }
    }
    Ok(())
}
