//! Offline transfer: pack what changed in the mirror into a tar file, carry it across
//! an air gap, and apply it on the other side in an order that keeps the destination
//! consistent (packages first, indices next, Release files last, deletions at the end).
use crate::config::{Config, Global};
use crate::meter::{Counters, Counting, Meter, Progress};
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

/// Identity of a file on disk: (device, inode, link count). Files with the same device and
/// inode are hard links to one another and need to travel only once.
type Ident = (u64, u64, u64);

#[cfg(unix)]
fn ident(meta: &std::fs::Metadata) -> Option<Ident> {
    use std::os::unix::fs::MetadataExt;
    Some((meta.dev(), meta.ino(), meta.nlink()))
}

#[cfg(not(unix))]
fn ident(_meta: &std::fs::Metadata) -> Option<Ident> {
    None
}

/// Record every file below `dir` (which lies inside `root`) under its path relative to `root`.
/// Metadata files are hashed on all cores; package files are tracked by size.
fn scan_into(
    m: &mut Manifest,
    ids: &mut BTreeMap<String, Ident>,
    root: &Path,
    dir: &Path,
    counters: &Counters,
) -> Result<()> {
    let mut to_hash: Vec<(String, PathBuf, u64)> = Vec::new();
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
        let meta = e.metadata()?;
        counters.file_done();
        if let Some(id) = ident(&meta) {
            ids.insert(rel.clone(), id);
        }
        if is_meta(&rel) {
            to_hash.push((rel, e.path().to_path_buf(), meta.len()));
        } else {
            m.insert(rel, (meta.len(), "-".to_string()));
        }
    }
    // Hard links share content: hash each inode once.
    let mut by_inode: BTreeMap<Ident, usize> = BTreeMap::new();
    let mut unique: Vec<usize> = Vec::new();
    let mut alias: Vec<usize> = Vec::with_capacity(to_hash.len());
    for (i, (rel, _, _)) in to_hash.iter().enumerate() {
        match ids.get(rel).map(|id| (id.0, id.1, 0)) {
            Some(key) => {
                let first = *by_inode.entry(key).or_insert_with(|| {
                    unique.push(i);
                    i
                });
                alias.push(first);
            }
            None => {
                unique.push(i);
                alias.push(i);
            }
        }
    }
    let sums = parallel_hash(&unique.iter().map(|&i| to_hash[i].1.clone()).collect::<Vec<_>>(), counters)?;
    let sum_of: BTreeMap<usize, String> = unique.iter().copied().zip(sums).collect();
    for (i, (rel, _, len)) in to_hash.into_iter().enumerate() {
        m.insert(rel, (len, sum_of[&alias[i]].clone()));
    }
    Ok(())
}

/// SHA-256 of each file, spread over the available cores.
fn parallel_hash(paths: &[PathBuf], counters: &Counters) -> Result<Vec<String>> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).clamp(1, 8);
    let next = AtomicUsize::new(0);
    let results: Vec<std::sync::Mutex<Option<Result<String>>>> =
        paths.iter().map(|_| std::sync::Mutex::new(None)).collect();
    std::thread::scope(|sc| {
        for _ in 0..workers.min(paths.len().max(1)) {
            sc.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= paths.len() {
                        break;
                    }
                    let r = hash_file(&paths[i], HashAlgo::Sha256)
                        .with_context(|| format!("hashing {}", paths[i].display()));
                    counters.add_bytes(std::fs::metadata(&paths[i]).map(|m| m.len()).unwrap_or(0));
                    *results[i].lock().unwrap() = Some(r);
                }
            });
        }
    });
    results.into_iter().map(|r| r.into_inner().unwrap().expect("every path hashed")).collect()
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
        // An entry may write into several host directories (crates: index and downloads).
        for root in r.dirs(&cfg.global)? {
            let rel = root.strip_prefix(&mirror).unwrap_or(&root).to_string_lossy().into_owned();
            all.push((r.name.as_str(), rel));
        }
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

/// How `bundle create` writes its file.
#[derive(Debug, Clone)]
pub struct CreateOptions {
    /// Ignore the manifest and pack everything in reach.
    pub full: bool,
    /// Record of what the destination has [default: <state>/bundle-manifest.tsv].
    pub manifest: Option<PathBuf>,
    /// Store hard-linked files once and the other names as tar hard-link entries
    /// (needs cheval 0.6.2 or newer to apply). On by default.
    pub hard_links: bool,
    /// zstd level (1-19) for a compressed bundle; `None` writes a plain tar.
    pub compress: Option<i32>,
    /// Also write `OUT.sha256` (in `sha256sum` format) once the bundle is complete, so a
    /// receiver such as `cheval ingest` knows the transfer finished and arrived intact.
    pub checksum_file: bool,
    /// Progress on stderr while scanning and writing (see [`crate::meter`]).
    pub progress: Progress,
}

impl Default for CreateOptions {
    fn default() -> Self {
        CreateOptions {
            full: false,
            manifest: None,
            hard_links: true,
            compress: None,
            checksum_file: true,
            progress: Progress::Auto,
        }
    }
}

/// Create a bundle of everything in the mirror that changed since the manifest was last written.
pub fn create(g: &Global, out: &Path, full: bool, manifest: Option<PathBuf>) -> Result<()> {
    let opts = CreateOptions { full, manifest, ..Default::default() };
    create_scoped(g, &Scope { dirs: Vec::new(), repos: Vec::new() }, out, &opts)
}

/// As [`create`], limited to the repositories named in `only` (all of them when empty).
///
/// The manifest records what the destination already has, for the whole mirror. A bundle of
/// some repositories reads and updates only their part of it, so per-repository and
/// whole-mirror bundles can be mixed freely without sending anything twice or missing a change.
pub fn create_only(cfg: &Config, only: &[String], out: &Path, full: bool, manifest: Option<PathBuf>) -> Result<()> {
    let opts = CreateOptions { full, manifest, ..Default::default() };
    create_scoped(&cfg.global, &resolve_scope(cfg, only)?, out, &opts)
}

/// [`create_only`] with every option.
pub fn create_with(cfg: &Config, only: &[String], out: &Path, opts: &CreateOptions) -> Result<()> {
    create_scoped(&cfg.global, &resolve_scope(cfg, only)?, out, opts)
}

/// A file that hashes (SHA-256) everything written to it, so the bundle's checksum file
/// costs no second read of a possibly very large bundle.
struct Hashed {
    file: std::fs::File,
    hash: sha2::Sha256,
}

impl Write for Hashed {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.file.write(buf)?;
        sha2::Digest::update(&mut self.hash, &buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// The bundle file being written: plain, or zstd-compressed on all cores.
enum Sink {
    Plain(std::io::BufWriter<Hashed>),
    Zstd(zstd::stream::Encoder<'static, std::io::BufWriter<Hashed>>),
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Sink::Plain(w) => w.write(buf),
            Sink::Zstd(w) => w.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Sink::Plain(w) => w.flush(),
            Sink::Zstd(w) => w.flush(),
        }
    }
}

impl Sink {
    fn open(path: &Path, level: Option<i32>) -> Result<Sink> {
        let file = Hashed { file: std::fs::File::create(path)?, hash: sha2::Digest::new() };
        let file = std::io::BufWriter::with_capacity(1 << 20, file);
        Ok(match level {
            None => Sink::Plain(file),
            Some(l) => {
                let mut enc = zstd::stream::Encoder::new(file, l)?;
                let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as u32;
                // Multithreading is optional in libzstd; a build without it still works.
                let _ = enc.multithread(threads);
                Sink::Zstd(enc)
            }
        })
    }
    /// Flush everything, sync the file to disk and return its SHA-256 (hex).
    fn finish(self) -> Result<String> {
        let w = match self {
            Sink::Plain(w) => w,
            Sink::Zstd(enc) => enc.finish()?,
        };
        let h = w.into_inner().map_err(|e| e.into_error())?;
        h.file.sync_all()?;
        Ok(hex::encode(sha2::Digest::finalize(h.hash)))
    }
}

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
const MIN_LINK_SIZE: u64 = 4096;

fn link_entry<W: Write>(tar: &mut tar::Builder<W>, path: &str, target: &str) -> Result<()> {
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Link);
    h.set_size(0);
    h.set_mode(0o644);
    h.set_mtime(chrono::Utc::now().timestamp() as u64);
    tar.append_link(&mut h, path, target).with_context(|| format!("adding link {path} -> {target}"))?;
    Ok(())
}

fn create_scoped(g: &Global, scope: &Scope, out: &Path, opts: &CreateOptions) -> Result<()> {
    if let Some(l) = opts.compress
        && !(1..=19).contains(&l)
    {
        bail!("compression level {l}: use 1 (fastest) to 19 (smallest)");
    }
    let _lock = crate::lock::lock(g)?; // a consistent view: never bundle mid-sync
    let root = g.mirror_path();
    if !root.is_dir() {
        bail!("mirror directory {} does not exist yet", root.display());
    }
    let whole = scope.dirs.is_empty();
    let covered = |rel: &str| whole || in_scope(rel, &scope.dirs);
    let manifest_path = opts.manifest.clone().unwrap_or_else(|| g.state_path().join("bundle-manifest.tsv"));
    let recorded = if manifest_path.exists() { load_manifest(&manifest_path)? } else { Manifest::new() };
    // What the destination is known to have, within this bundle's reach.
    let prev: Manifest = if opts.full {
        Manifest::new()
    } else {
        recorded.iter().filter(|(p, _)| covered(p)).map(|(p, v)| (p.clone(), v.clone())).collect()
    };
    let mut cur = Manifest::new();
    let mut ids: BTreeMap<String, Ident> = BTreeMap::new();
    // Running counts while scanning: files looked at, index bytes hashed.
    let scan_meter = Meter::start("scan", None, std::sync::Arc::new(Counters::default()), opts.progress);
    if whole {
        eprintln!("scanning {} ...", root.display());
        scan_into(&mut cur, &mut ids, &root, &root, scan_meter.counters())?;
    } else {
        for dir in &scope.dirs {
            let path = root.join(dir);
            if path.is_dir() {
                eprintln!("scanning {} ...", path.display());
                scan_into(&mut cur, &mut ids, &root, &path, scan_meter.counters())?;
            } else if !prev.keys().any(|p| within(p, dir)) {
                bail!("nothing has been mirrored to {} yet: run `cheval sync` first", path.display());
            }
        }
    }
    drop(scan_meter);
    let mut changed: Vec<&String> = cur.iter().filter(|(p, v)| prev.get(*p) != Some(v)).map(|(p, _)| p).collect();
    changed.sort_by_key(|p| (rank(p), p.as_str()));
    let deleted: Vec<&String> = prev.keys().filter(|p| !cur.contains_key(*p)).collect();
    let what = if whole { "the mirror".to_string() } else { scope.repos.join(", ") };
    if changed.is_empty() && deleted.is_empty() {
        println!("nothing changed in {what} since the last bundle; no file written");
        return Ok(());
    }
    // Which names are hard links to a file already placed earlier in this bundle.
    let mut first_of: BTreeMap<(u64, u64), &String> = BTreeMap::new();
    let mut link_to: BTreeMap<&String, &String> = BTreeMap::new();
    if opts.hard_links {
        for rel in &changed {
            // A link entry costs up to four tar blocks with long names: only worth it above that.
            if let Some(&(dev, ino, nlink)) = ids.get(*rel)
                && nlink > 1
                && cur[*rel].0 >= MIN_LINK_SIZE
            {
                match first_of.get(&(dev, ino)) {
                    Some(first) => {
                        link_to.insert(rel, first);
                    }
                    None => {
                        first_of.insert((dev, ino), rel);
                    }
                }
            }
        }
    }
    let bytes: u64 = changed.iter().filter(|p| !link_to.contains_key(**p)).map(|p| cur[*p].0).sum();
    let saved: u64 = link_to.keys().map(|p| cur[*p].0).sum();

    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let seq_path = sequence_path(&manifest_path);
    let (chain, sequence) = next_sequence(&seq_path)?;
    let tmp = out.with_extension("partial");
    let mut tar = tar::Builder::new(Sink::open(&tmp, opts.compress)?);
    let mut info = serde_json::json!({
        // format 2: may contain hard-link entries (cheval 0.6.2+)
        "format": if link_to.is_empty() { 1 } else { 2 },
        "created": chrono::Utc::now().to_rfc3339(),
        "incremental": !prev.is_empty(), "files": changed.len(), "bytes": bytes, "deletions": deleted.len(),
        "hard_links": link_to.len(),
        // Order on the receiving side: bundles of one chain (one manifest) apply in sequence.
        "chain": chain, "sequence": sequence, "full": prev.is_empty(), "whole": whole,
    });
    if !whole {
        // `scope` lets the receiving side refuse anything outside these directories.
        info["scope"] = serde_json::json!(scope.dirs);
        info["repos"] = serde_json::json!(scope.repos);
    }
    append_bytes(&mut tar, &format!("{META_DIR}/info.json"), &serde_json::to_vec_pretty(&info)?)?;
    let meter = Meter::start("write", Some(bytes), std::sync::Arc::new(Counters::default()), opts.progress);
    meter.set_total_files(changed.len() as u64);
    for rel in &changed {
        if let Some(target) = link_to.get(rel) {
            link_entry(&mut tar, rel, target)?;
            meter.file_done();
            continue;
        }
        let f = std::fs::File::open(root.join(rel)).with_context(|| format!("opening {rel}"))?;
        // What `append_file` writes, read through a counter for the progress meter.
        let mut h = tar::Header::new_gnu();
        h.set_metadata_in_mode(&f.metadata()?, tar::HeaderMode::Complete);
        let reader = Counting { inner: f, count: meter.counters().read.clone() };
        tar.append_data(&mut h, rel, reader).with_context(|| format!("adding {rel}"))?;
        meter.file_done();
    }
    drop(meter);
    let del: String = deleted.iter().map(|p| format!("{p}\n")).collect();
    append_bytes(&mut tar, &format!("{META_DIR}/delete"), del.as_bytes())?;
    let digest = tar.into_inner()?.finish()?;
    // The checksum file goes first so that the bundle never exists without it: a receiver that
    // sees `X.sha256` but no complete `X` keeps waiting. (Through a diode both may arrive in
    // any order; the receiver handles that too.)
    let sidecar = checksum_path(out);
    if opts.checksum_file {
        let name = out.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let tmp_sum = sidecar.with_extension("sha256.partial");
        std::fs::write(&tmp_sum, format!("{digest}  {name}\n"))?;
        std::fs::rename(&tmp_sum, &sidecar)?;
    } else {
        let _ = std::fs::remove_file(&sidecar); // never leave a stale one beside a new bundle
    }
    std::fs::rename(&tmp, out)?;
    let written = std::fs::metadata(out)?.len();
    // Replace this bundle's part of the record; everything else stays as it was.
    let mut record: Manifest = recorded.into_iter().filter(|(p, _)| !covered(p)).collect();
    record.extend(cur.iter().map(|(p, v)| (p.clone(), v.clone())));
    save_manifest(&manifest_path, &record)?;
    save_sequence(&seq_path, &chain, sequence)?;
    println!(
        "{} bundle of {what} {}: {} files ({}), {} deletions",
        if prev.is_empty() { "full" } else { "incremental" },
        out.display(),
        changed.len(),
        human_bytes(bytes),
        deleted.len()
    );
    if !link_to.is_empty() {
        println!("  {} hard links stored as links ({} not repeated)", link_to.len(), human_bytes(saved));
    }
    if opts.compress.is_some() {
        println!(
            "  zstd: {} on disk ({:.0}% of the content)",
            human_bytes(written),
            written as f64 * 100.0 / bytes.max(1) as f64
        );
    }
    println!("manifest: {} (the next bundle is relative to it)", manifest_path.display());
    println!(
        "sequence {sequence} of chain {chain}{}",
        if opts.checksum_file { format!("; checksum in {}", sidecar.display()) } else { String::new() }
    );
    Ok(())
}

/// Apply a bundle to `dest` (a mirror directory). Entries are trusted no further than
/// their paths can be validated: only regular files inside `dest` are ever written.
pub fn apply(bundle: &Path, dest: &Path, keep_deleted: bool) -> Result<ApplyReport> {
    apply_with(bundle, dest, keep_deleted, Progress::Auto)
}

/// [`apply`], choosing whether progress is shown (see [`crate::meter`]).
pub fn apply_with(bundle: &Path, dest: &Path, keep_deleted: bool, progress: Progress) -> Result<ApplyReport> {
    std::fs::create_dir_all(dest)?;
    let counters = std::sync::Arc::new(Counters::default());
    let file = std::fs::File::open(bundle).with_context(|| format!("opening {}", bundle.display()))?;
    let total = file.metadata().map(|m| m.len()).unwrap_or(0);
    let (mut ar, compressed) = open_reader(Box::new(Counting { inner: file, count: counters.read.clone() }))?;
    // Started once the header is read, so its "bundle covers …" line comes first.
    let mut meter: Option<Meter> = None;
    let (mut files, mut bytes, mut links) = (0u64, 0u64, 0u64);
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
                    let format = info.get("format").and_then(|v| v.as_u64()).unwrap_or(1);
                    if format > 2 {
                        bail!(
                            "{} was made by a newer cheval (bundle format {format}); upgrade cheval here",
                            bundle.display()
                        );
                    }
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
                    let m = Meter::start("apply", Some(total), counters.clone(), progress);
                    m.set_total_files(info.get("files").and_then(|v| v.as_u64()).unwrap_or(0));
                    meter = Some(m);
                }
                "delete" => deletions = s.lines().map(str::to_string).collect(),
                _ => {}
            }
            continue;
        }
        if !seen_info {
            bail!("{} is not a cheval bundle", bundle.display());
        }
        let kind = entry.header().entry_type();
        if !kind.is_file() && !kind.is_hard_link() {
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
        if kind.is_hard_link() {
            // Another name for a file this bundle already placed: link it (copy if the
            // filesystem cannot link). The target is checked like any other path.
            let link = entry.link_name()?.context("hard-link entry without a target")?.to_string_lossy().into_owned();
            let src_rel = safe_rel_path(&link).with_context(|| format!("link target {link:?}"))?;
            if let Some(dirs) = &scope
                && !in_scope(&src_rel.to_string_lossy(), dirs)
            {
                bail!("bundle link {path:?} points outside the directories the bundle covers; refusing to apply");
            }
            let src = dest.join(&src_rel);
            if !src.is_file() {
                bail!("bundle link {path:?} points to {link:?}, which is not in the bundle or on this side");
            }
            let _ = std::fs::remove_file(&tmp);
            if std::fs::hard_link(&src, &tmp).is_err() {
                std::fs::copy(&src, &tmp).with_context(|| format!("copying {link} to {path}"))?;
            }
            std::fs::rename(&tmp, &target)?;
            links += 1;
            files += 1;
            meter.as_ref().inspect(|m| m.file_done());
            continue;
        }
        let mut out = std::fs::File::create(&tmp)?;
        bytes += std::io::copy(&mut entry, &mut out).with_context(|| format!("extracting {path}"))?;
        drop(out);
        std::fs::rename(&tmp, &target)?;
        files += 1;
        meter.as_ref().inspect(|m| m.file_done());
    }
    if !seen_info {
        bail!("{} is not a cheval bundle", bundle.display());
    }
    let mut removed = 0;
    if !keep_deleted {
        if deletions.len() > 1000 {
            meter.take(); // clears the bar
            println!("removing {} files the sending side deleted ...", deletions.len());
        }
        for d in &deletions {
            if let Ok(rel) = safe_rel_path(d)
                && scope.as_ref().is_none_or(|dirs| in_scope(&rel.to_string_lossy(), dirs))
                && std::fs::remove_file(dest.join(rel)).is_ok()
            {
                removed += 1;
            }
        }
    }
    drop(meter); // clears the bar before the summary
    println!(
        "applied {}{}: {files} files ({}{}), {removed} removed, into {}",
        bundle.display(),
        if compressed { " (zstd)" } else { "" },
        human_bytes(bytes),
        if links > 0 { format!(", {links} of them hard links") } else { String::new() },
        dest.display()
    );
    println!("run `cheval verify --full` on this side to confirm integrity");
    Ok(ApplyReport { files, bytes, links, removed })
}

/// What [`apply`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct ApplyReport {
    pub files: u64,
    pub bytes: u64,
    pub links: u64,
    pub removed: u64,
}

/// What a bundle says about itself (its `info.json`).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BundleInfo {
    pub format: u64,
    pub created: Option<String>,
    /// The sender's manifest chain and this bundle's place in it (cheval 0.6.3+).
    pub chain: Option<String>,
    pub sequence: Option<u64>,
    /// Ignores what the destination had: complete for its scope.
    pub full: bool,
    /// Covers the whole mirror (no `--only`).
    pub whole: bool,
    pub repos: Vec<String>,
    pub scope: Vec<String>,
    pub files: u64,
    pub bytes: u64,
    pub deletions: u64,
    pub compressed: bool,
}

fn open_archive(bundle: &Path) -> Result<(tar::Archive<Box<dyn Read>>, bool)> {
    let f = std::fs::File::open(bundle).with_context(|| format!("opening {}", bundle.display()))?;
    open_reader(Box::new(f))
}

fn open_reader(raw: Box<dyn Read>) -> Result<(tar::Archive<Box<dyn Read>>, bool)> {
    let mut f = std::io::BufReader::with_capacity(1 << 20, raw);
    let compressed = f.fill_buf()?.starts_with(&ZSTD_MAGIC);
    let reader: Box<dyn Read> = if compressed { Box::new(zstd::stream::Decoder::with_buffer(f)?) } else { Box::new(f) };
    Ok((tar::Archive::new(reader), compressed))
}

fn parse_info(text: &str, compressed: bool) -> Result<BundleInfo> {
    let v: serde_json::Value = serde_json::from_str(text).context("bundle info.json is not JSON")?;
    let strs = |k: &str| -> Vec<String> {
        v.get(k)
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default()
    };
    let num = |k: &str| v.get(k).and_then(|n| n.as_u64()).unwrap_or(0);
    let scope = strs("scope");
    Ok(BundleInfo {
        format: v.get("format").and_then(|n| n.as_u64()).unwrap_or(1),
        created: v.get("created").and_then(|c| c.as_str()).map(String::from),
        chain: v.get("chain").and_then(|c| c.as_str()).map(String::from),
        sequence: v.get("sequence").and_then(|n| n.as_u64()),
        // Bundles before 0.6.3 say only whether they were incremental.
        full: v
            .get("full")
            .and_then(|b| b.as_bool())
            .unwrap_or_else(|| !v.get("incremental").and_then(|b| b.as_bool()).unwrap_or(true)),
        whole: v.get("whole").and_then(|b| b.as_bool()).unwrap_or(scope.is_empty()),
        repos: strs("repos"),
        scope,
        files: num("files"),
        bytes: num("bytes"),
        deletions: num("deletions"),
        compressed,
    })
}

/// Read only a bundle's header (its first entry). Cheap even for a huge bundle.
pub fn read_info(bundle: &Path) -> Result<BundleInfo> {
    let (mut ar, compressed) = open_archive(bundle)?;
    let mut entries = ar.entries()?;
    let mut first = entries.next().context("empty archive")?.context("reading the first entry")?;
    if first.path()?.to_string_lossy() != format!("{META_DIR}/info.json") {
        bail!("{} is not a cheval bundle", bundle.display());
    }
    let mut s = String::new();
    first.read_to_string(&mut s)?;
    parse_info(&s, compressed)
}

/// Read a whole bundle without writing anything: every entry must be readable to its end
/// (catches truncated or damaged transfers, including zstd frame checksums), every path
/// must be safe and inside the bundle's scope, every link must point to an earlier file of
/// the bundle, and the closing deletion list must be present.
pub fn check(bundle: &Path) -> Result<BundleInfo> {
    let (ar, compressed) = open_archive(bundle)?;
    check_archive(bundle, ar, compressed)
}

/// Reads the raw file and hashes every byte on the way.
struct HashingReader {
    file: std::fs::File,
    state: std::rc::Rc<std::cell::RefCell<(sha2::Sha256, u64)>>,
}

impl Read for HashingReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.file.read(buf)?;
        let mut st = self.state.borrow_mut();
        sha2::Digest::update(&mut st.0, &buf[..n]);
        st.1 += n as u64;
        Ok(n)
    }
}

/// [`check`], and the SHA-256 of the whole file, in one read.
pub fn check_hashed(bundle: &Path) -> Result<(BundleInfo, String)> {
    check_hashed_with(bundle, Progress::Auto)
}

/// [`check_hashed`], choosing whether progress is shown.
pub fn check_hashed_with(bundle: &Path, progress: Progress) -> Result<(BundleInfo, String)> {
    let state = std::rc::Rc::new(std::cell::RefCell::new((<sha2::Sha256 as sha2::Digest>::new(), 0u64)));
    let file = std::fs::File::open(bundle).with_context(|| format!("opening {}", bundle.display()))?;
    let total = file.metadata().map(|m| m.len()).unwrap_or(0);
    let counters = std::sync::Arc::new(Counters::default());
    let reader = Counting { inner: HashingReader { file, state: state.clone() }, count: counters.read.clone() };
    let (mut ar, compressed) = open_reader(Box::new(reader))?;
    let meter = Meter::start("check", Some(total), counters, progress);
    let result = check_entries(bundle, &mut ar, compressed);
    // Read to the end of the stream (tar end blocks, zstd epilogue) and of the file
    // (anything past the stream), so the hash covers every byte.
    let mut rest = ar.into_inner();
    let _ = std::io::copy(&mut rest, &mut std::io::sink());
    drop(rest);
    let (mut hasher, read) =
        std::rc::Rc::try_unwrap(state).map_err(|_| anyhow::anyhow!("reader still shared"))?.into_inner();
    let mut f = std::fs::File::open(bundle)?;
    std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(read))?;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        sha2::Digest::update(&mut hasher, &buf[..n]);
    }
    drop(meter);
    Ok((result?, hex::encode(sha2::Digest::finalize(hasher))))
}

fn check_archive(bundle: &Path, mut ar: tar::Archive<Box<dyn Read>>, compressed: bool) -> Result<BundleInfo> {
    check_entries(bundle, &mut ar, compressed)
}

fn check_entries(bundle: &Path, ar: &mut tar::Archive<Box<dyn Read>>, compressed: bool) -> Result<BundleInfo> {
    let mut info: Option<BundleInfo> = None;
    let mut placed: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut closed = false;
    for entry in ar.entries()? {
        let mut entry = entry.context("damaged or truncated bundle")?;
        let path = entry.path()?.to_string_lossy().into_owned();
        if closed {
            bail!("entry {path:?} after the end of the bundle");
        }
        if let Some(meta) = path.strip_prefix(&format!("{META_DIR}/")) {
            let mut s = String::new();
            entry.read_to_string(&mut s).context("damaged or truncated bundle")?;
            match meta {
                "info.json" if info.is_none() => {
                    let i = parse_info(&s, compressed)?;
                    if i.format > 2 {
                        bail!("bundle format {} is newer than this cheval understands; upgrade cheval here", i.format);
                    }
                    for d in &i.scope {
                        safe_rel_path(d).with_context(|| format!("bundle scope {d:?}"))?;
                    }
                    info = Some(i);
                }
                "delete" => {
                    for d in s.lines() {
                        safe_rel_path(d).with_context(|| format!("deletion {d:?}"))?;
                    }
                    closed = true;
                }
                _ => {}
            }
            continue;
        }
        let i = info.as_ref().with_context(|| format!("{} is not a cheval bundle", bundle.display()))?;
        let rel =
            safe_rel_path(&path).with_context(|| format!("bundle entry {path:?}"))?.to_string_lossy().into_owned();
        let dirs: Vec<String> = i.scope.iter().map(|d| d.trim_end_matches('/').to_string()).collect();
        if !dirs.is_empty() && !in_scope(&rel, &dirs) {
            bail!("bundle entry {path:?} lies outside the directories the bundle covers");
        }
        let kind = entry.header().entry_type();
        if kind.is_hard_link() {
            let link = entry.link_name()?.context("hard-link entry without a target")?.to_string_lossy().into_owned();
            let target =
                safe_rel_path(&link).with_context(|| format!("link target {link:?}"))?.to_string_lossy().into_owned();
            if !placed.contains(&target) {
                bail!("bundle link {path:?} points to {link:?}, which is not earlier in the bundle");
            }
        } else if kind.is_file() {
            std::io::copy(&mut entry, &mut std::io::sink())
                .with_context(|| format!("damaged or truncated bundle at {path}"))?;
        } else {
            bail!("bundle contains a non-regular entry ({path})");
        }
        placed.insert(rel);
    }
    if !closed {
        bail!("bundle is truncated (its closing deletion list is missing)");
    }
    info.with_context(|| format!("{} is not a cheval bundle", bundle.display()))
}

/// `OUT.sha256` beside a bundle.
pub fn checksum_path(bundle: &Path) -> PathBuf {
    let mut p = bundle.as_os_str().to_owned();
    p.push(".sha256");
    PathBuf::from(p)
}

/// Bundle numbering lives beside its manifest: one chain per manifest (= per destination).
fn sequence_path(manifest: &Path) -> PathBuf {
    let mut p = manifest.as_os_str().to_owned();
    p.push(".seq");
    PathBuf::from(p)
}

/// The chain id and the number for the next bundle. A new chain gets a random-enough id from
/// the clock, the process and the manifest path; it only has to differ between manifests.
fn next_sequence(path: &Path) -> Result<(String, u64)> {
    if let Ok(text) = std::fs::read_to_string(path) {
        let v: serde_json::Value =
            serde_json::from_str(&text).with_context(|| format!("reading bundle sequence {}", path.display()))?;
        if let (Some(c), Some(n)) =
            (v.get("chain").and_then(|c| c.as_str()), v.get("sequence").and_then(|n| n.as_u64()))
        {
            return Ok((c.to_string(), n + 1));
        }
        bail!("{} is not a bundle sequence file", path.display());
    }
    let seed = format!(
        "{}\0{}\0{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        std::process::id(),
        path.display()
    );
    let id = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(seed.as_bytes()));
    Ok((id[..16].to_string(), 1))
}

fn save_sequence(path: &Path, chain: &str, sequence: u64) -> Result<()> {
    let tmp = path.with_extension("seq.tmp");
    std::fs::write(&tmp, serde_json::to_vec(&serde_json::json!({ "chain": chain, "sequence": sequence }))?)?;
    std::fs::rename(&tmp, path)?;
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
