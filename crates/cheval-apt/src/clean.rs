//! Removal of files no longer referenced by any index.
//!
//! Safety rules: only directories where *every* configured repository finished
//! completely are touched; a sanity threshold stops mass deletion; symlinks and
//! recently superseded by-hash files are left alone.
use crate::config::{CleanMode, Global};
use crate::progress::{Phase, Progress};
use crate::util::human_bytes;
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use walkdir::WalkDir;

pub struct CleanInput {
    pub idx: usize,
    pub name: String,
    pub root: PathBuf,
    pub expected: HashSet<PathBuf>,
    pub complete: bool,
    pub mode: CleanMode,
}

struct Group {
    root: PathBuf,
    members: Vec<CleanInput>,
}

pub fn run(mut inputs: Vec<CleanInput>, g: &Global, p: &Progress, force: bool) -> (u64, u64) {
    // Repositories whose directories nest or coincide are judged together.
    inputs.retain(|i| !i.root.as_os_str().is_empty());
    inputs.sort_by(|a, b| a.root.cmp(&b.root));
    let mut groups: Vec<Group> = Vec::new();
    for i in inputs {
        match groups.last_mut() {
            Some(gr) if i.root.starts_with(&gr.root) => gr.members.push(i),
            _ => groups.push(Group { root: i.root.clone(), members: vec![i] }),
        }
    }
    let (mut files, mut bytes) = (0u64, 0u64);
    for gr in groups {
        let any_ran = gr.members.iter().any(|m| m.complete);
        let mode = gr.members.iter().map(|m| m.mode).fold(CleanMode::Delete, |a, b| match (a, b) {
            (CleanMode::Off, _) | (_, CleanMode::Off) => CleanMode::Off,
            (CleanMode::Report, _) | (_, CleanMode::Report) => CleanMode::Report,
            _ => CleanMode::Delete,
        });
        if mode == CleanMode::Off || !gr.root.is_dir() {
            continue;
        }
        if let Some(bad) = gr.members.iter().find(|m| !m.complete) {
            if any_ran {
                p.info(
                    Some(bad.idx),
                    format!(
                        "not cleaning {}: repository did not complete (or was skipped) this run",
                        gr.root.display()
                    ),
                );
            }
            continue;
        }
        let first = gr.members[0].idx;
        for m in &gr.members {
            p.repos[m.idx].set_phase(Phase::Cleaning);
        }
        let mut expected: HashSet<PathBuf> = HashSet::new();
        for m in &gr.members {
            expected.extend(m.expected.iter().cloned());
        }
        let now = SystemTime::now();
        let keep_byhash = Duration::from_secs(g.by_hash_keep_days * 86400);
        let mut total = 0u64;
        let mut cand: Vec<(PathBuf, u64)> = Vec::new();
        for e in WalkDir::new(&gr.root).follow_links(false).into_iter().filter_map(|e| e.ok()) {
            if !e.file_type().is_file() {
                continue;
            }
            total += 1;
            let path = e.path();
            if expected.contains(path) {
                continue;
            }
            let md = match e.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let age = md.modified().ok().and_then(|m| now.duration_since(m).ok()).unwrap_or_default();
            let name = e.file_name().to_string_lossy();
            if (name.ends_with(".cheval-part") || name.ends_with(".cheval-new")) && age < Duration::from_secs(86400) {
                continue;
            }
            if path.components().any(|c| c.as_os_str() == "by-hash") && age < keep_byhash {
                continue;
            }
            cand.push((path.to_path_buf(), md.len()));
        }
        if cand.is_empty() {
            continue;
        }
        let size: u64 = cand.iter().map(|c| c.1).sum();
        if !force && cand.len() > 50 && (cand.len() as u64) * 100 > total * g.clean_max_percent as u64 {
            p.warn(
                Some(first),
                format!(
                    "refusing to clean {}: {} of {} files ({}) would be removed, above clean_max_percent = {}. \
                     Review with clean = \"report\" or run with --force-clean",
                    gr.root.display(),
                    cand.len(),
                    total,
                    human_bytes(size),
                    g.clean_max_percent
                ),
            );
            continue;
        }
        if mode == CleanMode::Report {
            for (path, _) in cand.iter().take(20) {
                p.info(Some(first), format!("obsolete: {}", path.display()));
            }
            p.info(
                Some(first),
                format!(
                    "{} obsolete files ({}) in {} (clean = \"report\": nothing deleted)",
                    cand.len(),
                    human_bytes(size),
                    gr.root.display()
                ),
            );
            continue;
        }
        let (mut n, mut b) = (0u64, 0u64);
        for (path, len) in &cand {
            match std::fs::remove_file(path) {
                Ok(()) => {
                    n += 1;
                    b += len;
                }
                Err(e) => p.warn(Some(first), format!("cannot remove {}: {e}", path.display())),
            }
        }
        // Drop directories left empty (deepest first); the root itself stays.
        for e in WalkDir::new(&gr.root)
            .follow_links(false)
            .contents_first(true)
            .min_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if e.file_type().is_dir() {
                let _ = std::fs::remove_dir(e.path());
            }
        }
        p.info(Some(first), format!("cleaned {n} obsolete files ({}) from {}", human_bytes(b), gr.root.display()));
        files += n;
        bytes += b;
    }
    (files, bytes)
}
