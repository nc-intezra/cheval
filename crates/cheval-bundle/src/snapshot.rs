//! Point-in-time snapshots of the mirror using hard links.
//!
//! cheval never modifies a published file in place (every write is temp + rename),
//! so a hard-linked tree is a stable, space-free copy that can be served or shipped
//! to an offline network as an exact, repeatable state.
use crate::config::Global;
use anyhow::{Context, Result, bail};
use std::path::Path;
use walkdir::WalkDir;

fn valid_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        || name.starts_with('.')
    {
        bail!("snapshot name {name:?} must use only [A-Za-z0-9._-]");
    }
    Ok(())
}

pub fn link_tree(src: &Path, dst: &Path) -> Result<(u64, u64)> {
    let (mut files, mut bytes) = (0u64, 0u64);
    for e in WalkDir::new(src).follow_links(false) {
        let e = e?;
        let rel = e.path().strip_prefix(src).unwrap();
        let target = dst.join(rel);
        let ft = e.file_type();
        if ft.is_dir() {
            std::fs::create_dir_all(&target)?;
        } else if ft.is_symlink() {
            let link = std::fs::read_link(e.path())?;
            std::os::unix::fs::symlink(link, &target)?;
        } else if ft.is_file() {
            let name = e.file_name().to_string_lossy();
            if name.ends_with(".cheval-part") || name.ends_with(".cheval-new") {
                continue;
            }
            if std::fs::hard_link(e.path(), &target).is_err() {
                std::fs::copy(e.path(), &target).with_context(|| format!("copying {}", e.path().display()))?;
            }
            files += 1;
            bytes += e.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    Ok((files, bytes))
}

pub fn create(g: &Global, name: Option<String>) -> Result<String> {
    let name = name.unwrap_or_else(|| chrono::Local::now().format("%Y%m%d-%H%M%S").to_string());
    valid_name(&name)?;
    let _lock = crate::lock::lock(g)?; // never snapshot in the middle of a publish
    let src = g.mirror_path();
    if !src.is_dir() {
        bail!("mirror directory {} does not exist yet", src.display());
    }
    let dst = g.snapshot_path().join(&name);
    if dst.exists() {
        bail!("snapshot {name} already exists");
    }
    let tmp = g.snapshot_path().join(format!(".{name}.tmp"));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    let (files, bytes) = link_tree(&src, &tmp)?;
    std::fs::rename(&tmp, &dst)?;
    println!("snapshot {name}: {files} files, {} at {}", crate::util::human_bytes(bytes), dst.display());
    Ok(name)
}

pub fn list(g: &Global) -> Result<()> {
    let dir = g.snapshot_path();
    let mut names: Vec<String> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with('.'))
            .collect(),
        Err(_) => Vec::new(),
    };
    names.sort();
    if names.is_empty() {
        println!("no snapshots in {}", dir.display());
    }
    for n in names {
        println!("{n}\t{}", dir.join(&n).display());
    }
    Ok(())
}

pub fn delete(g: &Global, name: &str) -> Result<()> {
    valid_name(name)?;
    let dir = g.snapshot_path().join(name);
    if !dir.is_dir() {
        bail!("no such snapshot: {name}");
    }
    std::fs::remove_dir_all(&dir)?;
    println!("deleted snapshot {name}");
    Ok(())
}
