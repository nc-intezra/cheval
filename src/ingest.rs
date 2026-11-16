//! `cheval ingest`: the receiving end of a data diode. Watches a drop folder, takes each
//! bundle once it has arrived completely, applies bundles in the order they were made, and
//! keeps a record that monitoring can read.
//!
//! The rules, in the order they are applied:
//!
//! * **Arrival.** A bundle with a checksum file (`NAME.sha256`, written by `bundle create`)
//!   is taken when the file is complete and its SHA-256 matches. One without is taken after
//!   its size and modification time have not changed for `settle`.
//! * **Integrity.** Every bundle is read once end to end before anything is written: paths,
//!   scope, links, truncation. A damaged bundle goes to `failed/` and changes nothing.
//! * **Order.** Bundles carry their manifest's chain id and a sequence number. The next
//!   number is applied; one already applied (a repeat through the diode) is set aside; a
//!   later one waits for the missing one for `gap_wait` and is then applied anyway, with the
//!   gap recorded. A full bundle of the whole mirror supersedes everything before it.
//! * **Space.** A bundle waits while the mirror's filesystem has less free space than it holds.
//!
//! Interrupting an apply is safe: the bundle stays in the drop folder, is not recorded as
//! applied, and is applied again from the start next time.
use crate::bundle::{self, BundleInfo};
use crate::config::Config;
use crate::util::human_bytes;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum VerifyAfter {
    /// Do not verify
    Off,
    /// Check that every file the indices list is present with the right size
    Quick,
    /// Also hash every file (reads the whole repository)
    Full,
}

#[derive(Debug, Clone)]
pub struct IngestOptions {
    /// The drop folder the diode writes into.
    pub drop: PathBuf,
    /// The mirror directory bundles are applied to.
    pub dest: PathBuf,
    /// Where processed bundles go.
    pub done: PathBuf,
    pub failed: PathBuf,
    /// The record (`ingest.json`) and the lock.
    pub state: PathBuf,
    /// How long a bundle without a checksum file must stay unchanged.
    pub settle: Duration,
    /// Ignore bundles that have no checksum file.
    pub require_checksum: bool,
    /// How long a bundle waits for a missing earlier one.
    pub gap_wait: Duration,
    /// Applied bundles kept in `done/` (0: delete them once applied).
    pub keep_done: usize,
    pub keep_deleted: bool,
    pub verify: VerifyAfter,
    pub once: bool,
    pub interval: Duration,
}

/// The record kept in `<state>/ingest.json`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Record {
    #[serde(default)]
    pub chains: BTreeMap<String, Chain>,
    /// Bundles waiting for an earlier one: file name -> when that started (RFC 3339).
    #[serde(default)]
    pub held: BTreeMap<String, String>,
    /// Bundles from senders older than 0.6.3 (no sequence): name, size and creation time.
    #[serde(default)]
    pub unsequenced: Vec<Unsequenced>,
    #[serde(default)]
    pub done_files: Vec<String>,
    #[serde(default)]
    pub last: Option<Event>,
    #[serde(default)]
    pub last_verify: Option<VerifyResult>,
    #[serde(default)]
    pub applied_total: u64,
    #[serde(default)]
    pub failed_total: u64,
    #[serde(default)]
    pub updated: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Chain {
    pub applied: u64,
    #[serde(default)]
    pub missing: Vec<u64>,
    #[serde(default)]
    pub last_bundle: String,
    #[serde(default)]
    pub at: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Unsequenced {
    pub name: String,
    pub size: u64,
    pub created: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Event {
    pub bundle: String,
    pub outcome: String,
    #[serde(default)]
    pub detail: String,
    pub chain: Option<String>,
    pub sequence: Option<u64>,
    pub files: u64,
    pub bytes: u64,
    pub at: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub ok: bool,
    pub full: bool,
    pub repos: Vec<String>,
    pub at: String,
}

/// What one pass over the drop folder did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Pass {
    pub applied: Vec<String>,
    pub set_aside: Vec<String>,
    pub failed: Vec<String>,
    pub waiting: Vec<String>,
    pub verify_ok: Option<bool>,
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn load_record(path: &Path) -> Result<Record> {
    match std::fs::read_to_string(path) {
        Ok(t) => serde_json::from_str(&t).with_context(|| format!("reading {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Record::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn save_record(path: &Path, r: &mut Record) -> Result<()> {
    r.updated = Some(now());
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(r)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Names the diode or a copy tool uses while a file is still arriving, and our own files.
fn ignored(name: &str) -> bool {
    name.starts_with('.')
        || name.ends_with('~')
        || [".sha256", ".partial", ".part", ".tmp", ".filepart", ".crdownload", ".reason"]
            .iter()
            .any(|s| name.ends_with(s))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seen {
    size: u64,
    mtime: SystemTime,
}

fn seen(path: &Path) -> Option<Seen> {
    let m = std::fs::metadata(path).ok()?;
    m.is_file().then(|| Seen { size: m.len(), mtime: m.modified().unwrap_or(SystemTime::UNIX_EPOCH) })
}

/// Parse a `sha256sum` line: 64 hex digits, then the name. Incomplete (still arriving) → None.
fn read_checksum(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    if !text.ends_with('\n') {
        return None;
    }
    let hex = text.split_whitespace().next()?;
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| hex.to_ascii_lowercase())
}

/// Free bytes on the filesystem holding `dir`.
#[cfg(unix)]
fn free_space(dir: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path and `s` a writable statvfs.
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    Some(s.f_bavail as u64 * s.f_frsize as u64)
}

#[cfg(not(unix))]
fn free_space(_dir: &Path) -> Option<u64> {
    None
}

/// Move a file into `dir`, keeping its name (adding `.N` if taken). Falls back to copy and
/// delete across filesystems.
fn move_into(file: &Path, dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let name = file.file_name().context("file without a name")?.to_string_lossy().into_owned();
    let mut target = dir.join(&name);
    let mut n = 1;
    while target.exists() {
        target = dir.join(format!("{name}.{n}"));
        n += 1;
    }
    if std::fs::rename(file, &target).is_err() {
        std::fs::copy(file, &target).with_context(|| format!("copying {} to {}", file.display(), dir.display()))?;
        std::fs::remove_file(file)?;
    }
    Ok(target)
}

/// A bundle in the drop folder that has arrived and passed its integrity check.
struct Ready {
    path: PathBuf,
    name: String,
    size: u64,
    info: BundleInfo,
}

pub struct Ingest {
    opts: IngestOptions,
    cfg: Option<Config>,
    record_path: PathBuf,
    /// First time each (file, size, mtime) was seen unchanged, for the settle rule.
    stable_since: HashMap<PathBuf, (Seen, Instant)>,
    /// Files that already failed their checksum or check with this exact size and time (and
    /// why): not re-read.
    bad_hash: HashMap<PathBuf, (Seen, String)>,
    /// Bundles already checked with this exact size and time.
    checked: HashMap<PathBuf, (Seen, BundleInfo)>,
    _lock: std::fs::File,
}

impl Ingest {
    pub fn new(opts: IngestOptions, cfg: Option<Config>) -> Result<Ingest> {
        if !opts.drop.is_dir() {
            bail!("drop folder {} does not exist", opts.drop.display());
        }
        if opts.verify != VerifyAfter::Off && cfg.as_ref().is_none_or(|c| c.repos.is_empty()) {
            bail!(
                "verifying after apply needs the configuration with the [[repo]] entries; give --config or --verify off"
            );
        }
        std::fs::create_dir_all(&opts.state).with_context(|| format!("creating {}", opts.state.display()))?;
        std::fs::create_dir_all(&opts.dest).with_context(|| format!("creating {}", opts.dest.display()))?;
        let lock_path = opts.state.join("ingest.lock");
        let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&lock_path)?;
        if lock.try_lock().is_err() {
            bail!("another `cheval ingest` is running (lock {})", lock_path.display());
        }
        Ok(Ingest {
            record_path: opts.state.join("ingest.json"),
            opts,
            cfg,
            stable_since: HashMap::new(),
            bad_hash: HashMap::new(),
            checked: HashMap::new(),
            _lock: lock,
        })
    }

    /// Run until stopped (or one pass with `once`). Returns whether everything went well.
    pub fn run(&mut self) -> Result<bool> {
        println!(
            "cheval ingest: watching {} -> {} (verify {:?}, gap wait {}s, settle {}s)",
            self.opts.drop.display(),
            self.opts.dest.display(),
            self.opts.verify,
            self.opts.gap_wait.as_secs(),
            self.opts.settle.as_secs()
        );
        if self.opts.once {
            // Two looks a moment apart, so a file still being written is not taken.
            self.observe()?;
            std::thread::sleep(Duration::from_secs(2));
            let p = self.pass()?;
            for w in &p.waiting {
                println!("waiting: {w}");
            }
            return Ok(p.failed.is_empty() && p.verify_ok != Some(false));
        }
        loop {
            if let Err(e) = self.pass() {
                eprintln!("error: {e:#}");
            }
            std::thread::sleep(self.opts.interval);
        }
    }

    /// Note the size and time of every candidate (for the settle rule).
    fn observe(&mut self) -> Result<Vec<(PathBuf, String, Seen)>> {
        let mut out = Vec::new();
        let mut present = BTreeSet::new();
        for e in std::fs::read_dir(&self.opts.drop).with_context(|| format!("reading {}", self.opts.drop.display()))? {
            let e = e?;
            let name = e.file_name().to_string_lossy().into_owned();
            if ignored(&name) || !e.file_type()?.is_file() {
                continue;
            }
            let path = e.path();
            let Some(s) = seen(&path) else { continue };
            present.insert(path.clone());
            match self.stable_since.get(&path) {
                Some((prev, _)) if *prev == s => {}
                _ => {
                    self.stable_since.insert(path.clone(), (s, Instant::now()));
                }
            }
            out.push((path, name, s));
        }
        self.stable_since.retain(|p, _| present.contains(p));
        self.bad_hash.retain(|p, _| present.contains(p));
        self.checked.retain(|p, _| present.contains(p));
        Ok(out)
    }

    /// One look at the drop folder: take what has arrived, apply what is due.
    pub fn pass(&mut self) -> Result<Pass> {
        let mut rec = load_record(&self.record_path)?;
        let mut pass = Pass::default();
        let mut ready: Vec<Ready> = Vec::new();
        for (path, name, s) in self.observe()? {
            let unchanged_for = self.stable_since.get(&path).map(|(_, t)| t.elapsed()).unwrap_or_default();
            let sum = read_checksum(&bundle::checksum_path(&path));
            // Unchanged for `settle`. A single pass (`--once`) remembers nothing from earlier
            // runs, so there the modification time has to vouch for the time before this run.
            let mtime_age = s.mtime.elapsed().unwrap_or_default();
            let settled = unchanged_for >= self.opts.settle || (self.opts.once && mtime_age >= self.opts.settle);
            if sum.is_none() && (self.opts.require_checksum || !settled) {
                pass.waiting.push(format!(
                    "{name}: {}",
                    if self.opts.require_checksum { "no checksum file yet" } else { "still arriving or settling" }
                ));
                continue;
            }
            if let Some((prev, why)) = self.bad_hash.get(&path)
                && *prev == s
            {
                // Same bytes failed before; a file that fails for longer than `settle` is damaged.
                let why = why.clone();
                if settled {
                    self.fail(&mut rec, &mut pass, &path, &name, None, &why)?;
                } else {
                    pass.waiting.push(format!("{name}: {why} (may still be arriving)"));
                }
                continue;
            }
            let info = match self.checked.get(&path) {
                Some((prev, info)) if *prev == s => info.clone(),
                _ => {
                    let result = bundle::check_hashed(&path);
                    // The file changed while it was read: it is still arriving.
                    if seen(&path) != Some(s) {
                        pass.waiting.push(format!("{name}: still arriving"));
                        continue;
                    }
                    match result {
                        Ok((info, digest)) => {
                            if let Some(want) = &sum
                                && *want != digest
                            {
                                let why = "checksum does not match its .sha256 file".to_string();
                                if self.opts.once && settled {
                                    self.fail(&mut rec, &mut pass, &path, &name, None, &why)?;
                                } else {
                                    pass.waiting.push(format!("{name}: {why} (may still be arriving)"));
                                    self.bad_hash.insert(path.clone(), (s, why));
                                }
                                continue;
                            }
                            self.checked.insert(path.clone(), (s, info.clone()));
                            info
                        }
                        Err(e) => {
                            // With a checksum file the bundle may be a transfer that stalled:
                            // give it `settle` before calling it damaged. Without one, it has
                            // already settled to get here.
                            let why = format!("{e:#}");
                            if sum.is_some() && !(self.opts.once && settled) {
                                pass.waiting.push(format!("{name}: {why} (may still be arriving)"));
                                self.bad_hash.insert(path.clone(), (s, why));
                            } else {
                                self.fail(&mut rec, &mut pass, &path, &name, None, &why)?;
                            }
                            continue;
                        }
                    }
                }
            };
            ready.push(Ready { path, name, size: s.size, info });
        }
        self.schedule(&mut rec, &mut pass, ready)?;
        // Forget holds for bundles that are gone.
        let names: BTreeSet<String> = std::fs::read_dir(&self.opts.drop)?
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        rec.held.retain(|n, _| names.contains(n));
        save_record(&self.record_path, &mut rec)?;
        Ok(pass)
    }

    /// Decide what to apply, in which order, and do it.
    fn schedule(&mut self, rec: &mut Record, pass: &mut Pass, ready: Vec<Ready>) -> Result<()> {
        let mut chains: BTreeMap<String, Vec<Ready>> = BTreeMap::new();
        let mut unsequenced: Vec<Ready> = Vec::new();
        for r in ready {
            match (&r.info.chain, r.info.sequence) {
                (Some(c), Some(_)) => chains.entry(c.clone()).or_default().push(r),
                _ => unsequenced.push(r),
            }
        }
        let mut touched: BTreeSet<String> = BTreeSet::new();
        let mut whole_touched = false;
        for (chain, mut list) in chains {
            list.sort_by_key(|r| r.info.sequence);
            // The newest full bundle of the whole mirror makes everything before it redundant.
            let reset = list.iter().rev().find(|r| r.info.full && r.info.whole).and_then(|r| r.info.sequence);
            for r in list {
                let seq = r.info.sequence.unwrap_or(0);
                let applied = rec.chains.get(&chain).map(|c| c.applied).unwrap_or(0);
                if seq <= applied || reset.is_some_and(|s| seq < s) {
                    let why = if seq <= applied {
                        format!("sequence {seq} was already applied (chain {chain} is at {applied})")
                    } else {
                        format!("superseded by full bundle {} of chain {chain}", reset.unwrap_or(0))
                    };
                    self.set_aside(rec, pass, &r, &why)?;
                    continue;
                }
                let next = applied + 1;
                if seq > next && reset != Some(seq) {
                    let since = rec.held.entry(r.name.clone()).or_insert_with(now).clone();
                    let waited = chrono::DateTime::parse_from_rfc3339(&since)
                        .map(|t| (chrono::Utc::now() - t.to_utc()).to_std().unwrap_or_default())
                        .unwrap_or_default();
                    if waited < self.opts.gap_wait {
                        pass.waiting.push(format!(
                            "{}: sequence {seq} waits for {} (chain {chain}; {}s of {}s)",
                            r.name,
                            if seq == next + 1 { format!("{next}") } else { format!("{next}..{}", seq - 1) },
                            waited.as_secs(),
                            self.opts.gap_wait.as_secs()
                        ));
                        // Later bundles of this chain wait too.
                        break;
                    }
                    eprintln!(
                        "warning: chain {chain}: bundles {next}..{} never arrived; applying {} after waiting {}s. \
                         Send a full bundle (`bundle create --full`) to be sure nothing is missing.",
                        seq - 1,
                        r.name,
                        waited.as_secs()
                    );
                }
                if !self.apply_one(rec, pass, &r)? {
                    break; // failed or no space: later bundles of this chain must wait
                }
                let c = rec.chains.entry(chain.clone()).or_default();
                if seq > next && reset != Some(seq) {
                    c.missing.extend(next..seq);
                }
                if reset == Some(seq) {
                    c.missing.clear();
                }
                c.applied = seq;
                c.last_bundle = r.name.clone();
                c.at = now();
                rec.held.remove(&r.name);
                whole_touched |= r.info.whole;
                touched.extend(r.info.repos.iter().cloned());
            }
        }
        // Senders before 0.6.3: oldest first by creation time; never apply an older one after a newer.
        unsequenced.sort_by(|a, b| (&a.info.created, &a.name).cmp(&(&b.info.created, &b.name)));
        for r in unsequenced {
            let created = r.info.created.clone().unwrap_or_default();
            if rec.unsequenced.iter().any(|u| u.name == r.name && u.size == r.size && u.created == created) {
                self.set_aside(rec, pass, &r, "already applied")?;
                continue;
            }
            if let Some(newest) = rec.unsequenced.iter().map(|u| u.created.as_str()).max()
                && created.as_str() < newest
            {
                let reason = format!(
                    "made {created}, before a bundle already applied ({newest}); applying it would roll files back"
                );
                self.fail(rec, pass, &r.path, &r.name, Some(&r.info), &reason)?;
                continue;
            }
            if !self.apply_one(rec, pass, &r)? {
                break;
            }
            rec.unsequenced.push(Unsequenced { name: r.name.clone(), size: r.size, created });
            whole_touched |= r.info.whole;
            touched.extend(r.info.repos.iter().cloned());
        }
        if !pass.applied.is_empty() && self.opts.verify != VerifyAfter::Off {
            let cfg = self.cfg.as_ref().expect("checked in new()");
            let only: Vec<String> = if whole_touched { Vec::new() } else { touched.into_iter().collect() };
            let full = self.opts.verify == VerifyAfter::Full;
            println!("verifying {} ...", if only.is_empty() { "the mirror".to_string() } else { only.join(", ") });
            let ok = match crate::verify::run(cfg, &only, full) {
                Ok(ok) => ok,
                Err(e) => {
                    eprintln!("error: verify: {e:#}");
                    false
                }
            };
            if !ok {
                eprintln!("warning: verification after ingest found problems (see above)");
            }
            pass.verify_ok = Some(ok);
            rec.last_verify = Some(VerifyResult { ok, full, repos: only, at: now() });
        }
        Ok(())
    }

    /// Apply one bundle. Ok(false): not applied (failed, or waiting for space).
    fn apply_one(&mut self, rec: &mut Record, pass: &mut Pass, r: &Ready) -> Result<bool> {
        let need = r.info.bytes + (64 << 20);
        if let Some(free) = free_space(&self.opts.dest)
            && free < need
        {
            pass.waiting.push(format!(
                "{}: needs {} free in {}, {} available",
                r.name,
                human_bytes(need),
                self.opts.dest.display(),
                human_bytes(free)
            ));
            eprintln!(
                "warning: not enough space for {} ({} needed, {} free)",
                r.name,
                human_bytes(need),
                human_bytes(free)
            );
            return Ok(false);
        }
        let _mirror_lock = match &self.cfg {
            Some(c) if self.opts.dest == c.global.mirror_path() => match crate::sync::lock(&c.global) {
                Ok(l) => Some(l),
                Err(e) => {
                    pass.waiting.push(format!("{}: {e:#}", r.name));
                    return Ok(false);
                }
            },
            _ => None,
        };
        let label = match (&r.info.chain, r.info.sequence) {
            (Some(c), Some(s)) => format!(" (chain {c}, sequence {s})"),
            _ => String::new(),
        };
        println!("applying {}{label}", r.name);
        match bundle::apply(&r.path, &self.opts.dest, self.opts.keep_deleted) {
            Ok(report) => {
                rec.applied_total += 1;
                rec.last = Some(Event {
                    bundle: r.name.clone(),
                    outcome: "applied".into(),
                    detail: format!("{} files, {} removed", report.files, report.removed),
                    chain: r.info.chain.clone(),
                    sequence: r.info.sequence,
                    files: report.files,
                    bytes: report.bytes,
                    at: now(),
                });
                self.archive(rec, &r.path)?;
                pass.applied.push(r.name.clone());
                Ok(true)
            }
            Err(e) => {
                self.fail(rec, pass, &r.path, &r.name, Some(&r.info), &format!("apply: {e:#}"))?;
                Ok(false)
            }
        }
    }

    /// Move an applied bundle (and its checksum file) to done/, keeping the newest `keep_done`.
    fn archive(&mut self, rec: &mut Record, path: &Path) -> Result<()> {
        let sum = bundle::checksum_path(path);
        if self.opts.keep_done == 0 {
            std::fs::remove_file(path)?;
            let _ = std::fs::remove_file(&sum);
            return Ok(());
        }
        let moved = move_into(path, &self.opts.done)?;
        if sum.exists() {
            let _ = std::fs::rename(&sum, bundle::checksum_path(&moved));
        }
        rec.done_files.push(moved.to_string_lossy().into_owned());
        while rec.done_files.len() > self.opts.keep_done {
            let old = PathBuf::from(rec.done_files.remove(0));
            let _ = std::fs::remove_file(bundle::checksum_path(&old));
            let _ = std::fs::remove_file(&old);
        }
        Ok(())
    }

    /// A repeat or superseded bundle: nothing to do; out of the drop folder, into done/.
    fn set_aside(&mut self, rec: &mut Record, pass: &mut Pass, r: &Ready, why: &str) -> Result<()> {
        println!("skipping {}: {why}", r.name);
        rec.held.remove(&r.name);
        rec.last = Some(Event {
            bundle: r.name.clone(),
            outcome: "skipped".into(),
            detail: why.into(),
            chain: r.info.chain.clone(),
            sequence: r.info.sequence,
            at: now(),
            ..Default::default()
        });
        self.archive(rec, &r.path)?;
        pass.set_aside.push(r.name.clone());
        Ok(())
    }

    /// Move a bundle that cannot be applied to failed/, with the reason beside it.
    fn fail(
        &mut self,
        rec: &mut Record,
        pass: &mut Pass,
        path: &Path,
        name: &str,
        info: Option<&BundleInfo>,
        reason: &str,
    ) -> Result<()> {
        eprintln!("error: {name}: {reason}");
        let moved = move_into(path, &self.opts.failed)?;
        let sum = bundle::checksum_path(path);
        if sum.exists() {
            let _ = std::fs::rename(&sum, bundle::checksum_path(&moved));
        }
        let mut why = moved.as_os_str().to_owned();
        why.push(".reason");
        std::fs::write(PathBuf::from(why), format!("{}\n{reason}\n", now()))?;
        rec.failed_total += 1;
        rec.held.remove(name);
        rec.last = Some(Event {
            bundle: name.into(),
            outcome: "failed".into(),
            detail: reason.into(),
            chain: info.and_then(|i| i.chain.clone()),
            sequence: info.and_then(|i| i.sequence),
            at: now(),
            ..Default::default()
        });
        self.stable_since.remove(path);
        self.bad_hash.remove(path);
        self.checked.remove(path);
        pass.failed.push(name.into());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_names_are_ignored() {
        for n in [".hidden", "a.tar.partial", "a.tar.part", "a.tar.sha256", "a.tar~", "a.tar.filepart", "a.tar.tmp"] {
            assert!(ignored(n), "{n}");
        }
        for n in ["2026-11-16.tar", "debian.tar.zst", "bundle"] {
            assert!(!ignored(n), "{n}");
        }
    }

    #[test]
    fn checksum_lines_must_be_complete() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.sha256");
        let h = "a".repeat(64);
        std::fs::write(&p, format!("{h}  x")).unwrap();
        assert_eq!(read_checksum(&p), None, "no newline yet: still arriving");
        std::fs::write(&p, format!("{}  x\n", h.to_uppercase())).unwrap();
        assert_eq!(read_checksum(&p), Some(h));
        std::fs::write(&p, "abc  x\n").unwrap();
        assert_eq!(read_checksum(&p), None);
    }
}
