//! Offline transfer: pack what changed in the mirror into a tar file, carry it across
//! an air gap, and apply it on the other side in an order that keeps the destination
//! consistent (packages first, indices next, Release files last, deletions at the end).
use crate::config::{Config, Global};
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

/// Record every file below `dir` (which lies inside `root`) under its path relative to `root`.
fn scan_into(m: &mut Manifest, root: &Path, dir: &Path) -> Result<()> {
    for e in WalkDir::new(dir).follow_links(false) {
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
    Ok(())
}

/// Is `rel` the directory `scope` or something inside it?
fn within(rel: &str, scope: &str) -> bool {
    rel.strip_prefix(scope).is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

fn in_scope(rel: &str, scope: &[String]) -> bool {
    scope.iter().any(|s| within(rel, s))
}

/// What a bundle covers: the whole mirror, or the directories of selected repositories.
#[derive(Debug)]
struct Scope {
    /// Directories relative to the mirror root; empty means everything.
    dirs: Vec<String>,
    repos: Vec<String>,
}

/// Turn `--only` names into mirror directories. Repositories whose directories overlap
/// share package files and cannot be told apart on disk, so they must be selected together.
fn resolve_scope(cfg: &Config, only: &[String]) -> Result<Scope> {
    if only.is_empty() {
        return Ok(Scope { dirs: Vec::new(), repos: Vec::new() });
    }
    let mirror = cfg.global.mirror_path();
    let mut all: Vec<(&str, String)> = Vec::new();
    for r in &cfg.repos {
        let root = r.root(&cfg.global)?;
        let rel = root.strip_prefix(&mirror).unwrap_or(&root).to_string_lossy().into_owned();
        all.push((r.name.as_str(), rel));
    }
    for name in only {
        if !all.iter().any(|(n, _)| n == name) {
            let known: Vec<&str> = all.iter().map(|(n, _)| *n).collect();
            bail!("--only {name}: no such repository in the configuration (known: {})", known.join(", "));
        }
    }
    let mut scope = Scope { dirs: Vec::new(), repos: Vec::new() };
    for (name, dir) in all.iter().filter(|(n, _)| only.iter().any(|o| o == n)) {
        let sharing: Vec<&str> = all
            .iter()
            .filter(|(n, d)| !only.iter().any(|o| o == n) && (within(d, dir) || within(dir, d)))
            .map(|(n, _)| *n)
            .collect();
        if !sharing.is_empty() {
            let add: String = sharing.iter().map(|n| format!(" --only {n}")).collect();
            bail!(
                "repository {name} shares the directory {dir} with {}: their package files cannot be \
                 separated, so bundle them together (add{add})",
                sharing.join(", ")
            );
        }
        if !scope.repos.iter().any(|n| n == name) {
            scope.repos.push(name.to_string());
        }
        if !scope.dirs.contains(dir) {
            scope.dirs.push(dir.clone());
        }
    }
    // A directory inside another selected one is already covered.
    let dirs = scope.dirs.clone();
    scope.dirs.retain(|d| !dirs.iter().any(|o| o != d && within(d, o)));
    Ok(scope)
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

/// Create a bundle of everything in the mirror that changed since the manifest was last written.
pub fn create(g: &Global, out: &Path, full: bool, manifest: Option<PathBuf>) -> Result<()> {
    create_scoped(g, &Scope { dirs: Vec::new(), repos: Vec::new() }, out, full, manifest)
}

/// As [`create`], limited to the repositories named in `only` (all of them when empty).
///
/// The manifest records what the destination already has, for the whole mirror. A bundle of
/// some repositories reads and updates only their part of it, so per-repository and
/// whole-mirror bundles can be mixed freely without sending anything twice or missing a change.
pub fn create_only(cfg: &Config, only: &[String], out: &Path, full: bool, manifest: Option<PathBuf>) -> Result<()> {
    create_scoped(&cfg.global, &resolve_scope(cfg, only)?, out, full, manifest)
}

fn create_scoped(g: &Global, scope: &Scope, out: &Path, full: bool, manifest: Option<PathBuf>) -> Result<()> {
    let _lock = crate::sync::lock(g)?; // a consistent view: never bundle mid-sync
    let root = g.mirror_path();
    if !root.is_dir() {
        bail!("mirror directory {} does not exist yet", root.display());
    }
    let whole = scope.dirs.is_empty();
    let covered = |rel: &str| whole || in_scope(rel, &scope.dirs);
    let manifest_path = manifest.unwrap_or_else(|| g.state_path().join("bundle-manifest.tsv"));
    let recorded = if manifest_path.exists() { load_manifest(&manifest_path)? } else { Manifest::new() };
    // What the destination is known to have, within this bundle's reach.
    let prev: Manifest = if full {
        Manifest::new()
    } else {
        recorded.iter().filter(|(p, _)| covered(p)).map(|(p, v)| (p.clone(), v.clone())).collect()
    };
    let mut cur = Manifest::new();
    if whole {
        eprintln!("scanning {} ...", root.display());
        scan_into(&mut cur, &root, &root)?;
    } else {
        for dir in &scope.dirs {
            let path = root.join(dir);
            if path.is_dir() {
                eprintln!("scanning {} ...", path.display());
                scan_into(&mut cur, &root, &path)?;
            } else if !prev.keys().any(|p| within(p, dir)) {
                bail!("nothing has been mirrored to {} yet: run `cheval sync` first", path.display());
            }
        }
    }
    let mut changed: Vec<&String> = cur.iter().filter(|(p, v)| prev.get(*p) != Some(v)).map(|(p, _)| p).collect();
    changed.sort_by_key(|p| (rank(p), p.as_str()));
    let deleted: Vec<&String> = prev.keys().filter(|p| !cur.contains_key(*p)).collect();
    let bytes: u64 = changed.iter().map(|p| cur[*p].0).sum();
    let what = if whole { "the mirror".to_string() } else { scope.repos.join(", ") };
    if changed.is_empty() && deleted.is_empty() {
        println!("nothing changed in {what} since the last bundle; no file written");
        return Ok(());
    }
    let tmp = out.with_extension("partial");
    let mut tar = tar::Builder::new(std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(&tmp)?));
    let mut info = serde_json::json!({
        "format": 1, "created": chrono::Utc::now().to_rfc3339(),
        "incremental": !prev.is_empty(), "files": changed.len(), "bytes": bytes, "deletions": deleted.len(),
    });
    if !whole {
        // `scope` lets the receiving side refuse anything outside these directories.
        info["scope"] = serde_json::json!(scope.dirs);
        info["repos"] = serde_json::json!(scope.repos);
    }
    append_bytes(&mut tar, &format!("{META_DIR}/info.json"), &serde_json::to_vec_pretty(&info)?)?;
    for rel in &changed {
        let mut f = std::fs::File::open(root.join(rel)).with_context(|| format!("opening {rel}"))?;
        tar.append_file(rel, &mut f).with_context(|| format!("adding {rel}"))?;
    }
    let del: String = deleted.iter().map(|p| format!("{p}\n")).collect();
    append_bytes(&mut tar, &format!("{META_DIR}/delete"), del.as_bytes())?;
    tar.into_inner()?.flush()?;
    std::fs::rename(&tmp, out)?;
    // Replace this bundle's part of the record; everything else stays as it was.
    let mut record: Manifest = recorded.into_iter().filter(|(p, _)| !covered(p)).collect();
    record.extend(cur.iter().map(|(p, v)| (p.clone(), v.clone())));
    save_manifest(&manifest_path, &record)?;
    println!(
        "{} bundle of {what} {}: {} files ({}), {} deletions",
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
    // Set for a per-repository bundle: nothing outside these directories may be touched.
    let mut scope: Option<Vec<String>> = None;
    for entry in ar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().into_owned();
        if let Some(meta) = path.strip_prefix(&format!("{META_DIR}/")) {
            let mut s = String::new();
            entry.read_to_string(&mut s)?;
            match meta {
                "info.json" => {
                    seen_info = true;
                    let info: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
                    if let Some(list) = info.get("scope").and_then(|v| v.as_array()) {
                        let mut dirs = Vec::new();
                        for d in list {
                            let d = d.as_str().context("bundle scope is not a list of directories")?;
                            safe_rel_path(d).with_context(|| format!("bundle scope {d:?}"))?;
                            dirs.push(d.trim_end_matches('/').to_string());
                        }
                        let repos: Vec<&str> = info
                            .get("repos")
                            .and_then(|v| v.as_array())
                            .map(|a| a.iter().filter_map(|n| n.as_str()).collect())
                            .unwrap_or_default();
                        println!("bundle covers {} ({})", repos.join(", "), dirs.join(", "));
                        scope = Some(dirs);
                    }
                }
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
        if let Some(dirs) = &scope
            && !in_scope(&rel.to_string_lossy(), dirs)
        {
            bail!("bundle entry {path:?} lies outside the directories the bundle says it covers; refusing to apply");
        }
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
                && scope.as_ref().is_none_or(|dirs| in_scope(&rel.to_string_lossy(), dirs))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_matches_whole_path_components() {
        assert!(within("deb.debian.org/debian/pool/a.deb", "deb.debian.org/debian"));
        assert!(within("deb.debian.org/debian", "deb.debian.org/debian"));
        assert!(!within("deb.debian.org/debian-security/pool/a.deb", "deb.debian.org/debian"));
        assert!(!within("deb.debian.org", "deb.debian.org/debian"));
        assert!(in_scope("b/x", &["a".into(), "b".into()]));
        assert!(!in_scope("c/x", &["a".into(), "b".into()]));
    }

    #[test]
    fn scope_resolution() {
        let cfg: Config = toml::from_str(
            r#"
            [global]
            base_path = "/srv/cheval"
            [[repo]]
            name = "debian"
            url = "http://deb.debian.org/debian"
            suites = ["trixie"]
            [[repo]]
            name = "debian-updates"
            url = "http://deb.debian.org/debian"
            suites = ["trixie-updates"]
            [[repo]]
            name = "security"
            url = "http://deb.debian.org/debian-security"
            suites = ["trixie-security"]
            [[repo]]
            name = "docker"
            url = "https://download.docker.com/linux/debian"
            suites = ["trixie"]
            "#,
        )
        .unwrap();
        let names = |n: &[&str]| n.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let whole = resolve_scope(&cfg, &[]).unwrap();
        assert!(whole.dirs.is_empty());
        let s = resolve_scope(&cfg, &names(&["security", "docker"])).unwrap();
        assert_eq!(s.dirs, ["deb.debian.org/debian-security", "download.docker.com/linux/debian"]);
        assert_eq!(s.repos, ["security", "docker"]);
        // Two repositories in one directory: only together, and named once.
        let err = resolve_scope(&cfg, &names(&["debian"])).unwrap_err().to_string();
        assert!(err.contains("debian-updates") && err.contains("--only debian-updates"), "{err}");
        let both = resolve_scope(&cfg, &names(&["debian", "debian-updates", "debian"])).unwrap();
        assert_eq!(both.dirs, ["deb.debian.org/debian"]);
        assert_eq!(both.repos, ["debian", "debian-updates"]);
        // "debian" and "debian-security" are siblings, not nested.
        assert!(resolve_scope(&cfg, &names(&["security"])).is_ok());
        let err = resolve_scope(&cfg, &names(&["nope"])).unwrap_err().to_string();
        assert!(err.contains("no such repository") && err.contains("docker"), "{err}");
    }
}
