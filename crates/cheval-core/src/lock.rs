//! The run lock: one writer per mirror tree.
use crate::config::Global;
use anyhow::{Context, Result, bail};

/// Take the exclusive run lock so two instances never write the same tree.
pub fn lock(g: &Global) -> Result<std::fs::File> {
    let dir = g.state_path();
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join("cheval.lock");
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&path)?;
    // Retry briefly: a lock released a moment ago can still be held for an instant by
    // a process that was forked while the previous holder had the file open.
    for attempt in 0..40 {
        if f.try_lock().is_ok() {
            return Ok(f);
        }
        if attempt < 39 {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    bail!("another cheval instance is running (lock {})", path.display())
}
