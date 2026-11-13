//! Offline transfer: pack what changed in the mirror into a tar file, carry it across
//! an air gap, and apply it on the other side in an order that keeps the destination
//! consistent (packages first, indices next, Release files last, deletions at the end).
use crate::config::Global;
use crate::util::{HashAlgo, hash_file, human_bytes, safe_rel_path};
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const META_DIR: &str = ".cheval-bundle";

/// Repository metadata (as opposed to immutable package files).
fn is_meta(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    rel.split('/').any(|c| c == "dists" || c == "by-hash")
        || matches!(name, "InRelease" | "Release" | "Release.gpg")
        || name.starts_with("Packages")
        || name.starts_with("Sources")
}

/// Sort key implementing the safe apply order.
fn rank(rel: &str) -> u8 {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    match name {
        "InRelease" => 5,
        "Release" => 4,
        "Release.gpg" => 3,
        _ if rel.split('/').any(|c| c == "by-hash") => 1,
        _ if is_meta(rel) => 2,
        _ => 0,
    }
}

type Manifest = BTreeMap<String, (u64, String)>;

fn scan(root: &Path) -> Result<Manifest> {
    let mut m = Manifest::new();
    for e in WalkDir::new(root).follow_links(false) {
        let e = e?;
        if !e.file_type().is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy();
        if name.ends_with(".cheval-part") || name.ends_with(".cheval-new") {
            continue;
        }
        let rel = e.path().strip_prefix(root).unwrap().to_string_lossy().into_owned();
        // Metadata is small and mutable: track it by content. Packages by size.
        let sum = if is_meta(&rel) { hash_file(e.path(), HashAlgo::Sha256)? } else { "-".to_string() };
        m.insert(rel, (e.metadata()?.len(), sum));
    }
    Ok(m)
}

fn load_manifest(path: &Path) -> Result<Manifest> {
    let mut m = Manifest::new();
    let f = std::fs::File::open(path).with_context(|| format!("reading manifest {}", path.display()))?;
    for line in std::io::BufReader::new(f).lines() {
        let line = line?;
        let mut it = line.splitn(3, '\t');
        if let (Some(size), Some(sum), Some(p)) = (it.next(), it.next(), it.next()) {
            m.insert(p.to_string(), (size.parse().unwrap_or(0), sum.to_string()));
        }
    }
    Ok(m)
}

fn save_manifest(path: &Path, m: &Manifest) -> Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
    for (p, (size, sum)) in m {
        writeln!(f, "{size}\t{sum}\t{p}")?;
    }
    f.flush()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn append_bytes<W: Write>(tar: &mut tar::Builder<W>, name: &str, data: &[u8]) -> Result<()> {
    let mut h = tar::Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(chrono::Utc::now().timestamp() as u64);
    h.set_cksum();
    tar.append_data(&mut h, name, data)?;
    Ok(())
}

/// Create a bundle of everything that changed since the manifest was last written.
pub fn create(g: &Global, out: &Path, full: bool, manifest: Option<PathBuf>) -> Result<()> {
    let _lock = crate::sync::lock(g)?; // a consistent view: never bundle mid-sync
    let root = g.mirror_path();
    if !root.is_dir() {
        bail!("mirror directory {} does not exist yet", root.display());
    }
    let manifest_path = manifest.unwrap_or_else(|| g.state_path().join("bundle-manifest.tsv"));
    let prev = if full || !manifest_path.exists() { Manifest::new() } else { load_manifest(&manifest_path)? };
    eprintln!("scanning {} ...", root.display());
    let cur = scan(&root)?;
    let mut changed: Vec<&String> = cur.iter().filter(|(p, v)| prev.get(*p) != Some(v)).map(|(p, _)| p).collect();
    changed.sort_by_key(|p| (rank(p), p.as_str()));
    let deleted: Vec<&String> = prev.keys().filter(|p| !cur.contains_key(*p)).collect();
    let bytes: u64 = changed.iter().map(|p| cur[*p].0).sum();
    if changed.is_empty() && deleted.is_empty() {
        println!("nothing changed since the last bundle; no file written");
        return Ok(());
    }
    let tmp = out.with_extension("partial");
    let mut tar = tar::Builder::new(std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(&tmp)?));
    let info = serde_json::json!({
        "format": 1, "created": chrono::Utc::now().to_rfc3339(),
        "incremental": !prev.is_empty(), "files": changed.len(), "bytes": bytes, "deletions": deleted.len(),
    });
    append_bytes(&mut tar, &format!("{META_DIR}/info.json"), &serde_json::to_vec_pretty(&info)?)?;
    for rel in &changed {
        let mut f = std::fs::File::open(root.join(rel)).with_context(|| format!("opening {rel}"))?;
        tar.append_file(rel, &mut f).with_context(|| format!("adding {rel}"))?;
    }
    let del: String = deleted.iter().map(|p| format!("{p}\n")).collect();
    append_bytes(&mut tar, &format!("{META_DIR}/delete"), del.as_bytes())?;
    tar.into_inner()?.flush()?;
    std::fs::rename(&tmp, out)?;
    save_manifest(&manifest_path, &cur)?;
    println!(
        "{} bundle {}: {} files ({}), {} deletions",
        if prev.is_empty() { "full" } else { "incremental" },
        out.display(),
        changed.len(),
        human_bytes(bytes),
        deleted.len()
    );
    println!("manifest: {} (the next bundle is relative to it)", manifest_path.display());
    Ok(())
}

/// Apply a bundle to `dest` (a mirror directory). Entries are trusted no further than
/// their paths can be validated: only regular files inside `dest` are ever written.
pub fn apply(bundle: &Path, dest: &Path, keep_deleted: bool) -> Result<()> {
    std::fs::create_dir_all(dest)?;
    let f = std::fs::File::open(bundle).with_context(|| format!("opening {}", bundle.display()))?;
    let mut ar = tar::Archive::new(std::io::BufReader::with_capacity(1 << 20, f));
    let (mut files, mut bytes) = (0u64, 0u64);
    let mut deletions: Vec<String> = Vec::new();
    let mut seen_info = false;
    for entry in ar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().into_owned();
        if let Some(meta) = path.strip_prefix(&format!("{META_DIR}/")) {
            let mut s = String::new();
            entry.read_to_string(&mut s)?;
            match meta {
                "info.json" => seen_info = true,
                "delete" => deletions = s.lines().map(str::to_string).collect(),
                _ => {}
            }
            continue;
        }
        if !seen_info {
            bail!("{} is not a cheval bundle", bundle.display());
        }
        if !entry.header().entry_type().is_file() {
            bail!("bundle contains a non-regular entry ({path}); refusing to apply");
        }
        let rel = safe_rel_path(&path).with_context(|| format!("bundle entry {path:?}"))?;
        let target = dest.join(&rel);
        std::fs::create_dir_all(target.parent().unwrap())?;
        let mut tmp = target.as_os_str().to_owned();
        tmp.push(".cheval-new");
        let tmp = PathBuf::from(tmp);
        let mut out = std::fs::File::create(&tmp)?;
        bytes += std::io::copy(&mut entry, &mut out).with_context(|| format!("extracting {path}"))?;
        drop(out);
        std::fs::rename(&tmp, &target)?;
        files += 1;
    }
    if !seen_info {
        bail!("{} is not a cheval bundle", bundle.display());
    }
    let mut removed = 0;
    if !keep_deleted {
        for d in &deletions {
            if let Ok(rel) = safe_rel_path(d)
                && std::fs::remove_file(dest.join(rel)).is_ok()
            {
                removed += 1;
            }
        }
    }
    println!(
        "applied {}: {files} files ({}), {removed} removed, into {}",
        bundle.display(),
        human_bytes(bytes),
        dest.display()
    );
    println!("run `cheval verify --full` on this side to confirm integrity");
    Ok(())
}
