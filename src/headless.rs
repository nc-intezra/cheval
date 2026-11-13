//! Plain-text progress for cron jobs, systemd units and pipes.
use crate::progress::Progress;
use crate::util::{human_bytes, human_duration};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// Periodically print a one-line status until the run finishes.
pub async fn report(progress: Arc<Progress>, every: Duration) {
    let mut last_bytes = 0u64;
    let mut tick = tokio::time::interval(every);
    tick.tick().await;
    loop {
        tick.tick().await;
        if progress.finished.load(Ordering::Relaxed) {
            break;
        }
        let t = progress.totals();
        let net = progress.net_bytes.load(Ordering::Relaxed);
        let speed = (net - last_bytes) as f64 / every.as_secs_f64();
        last_bytes = net;
        let pct = if t.bytes_total > 0 { t.bytes_done as f64 * 100.0 / t.bytes_total as f64 } else { 0.0 };
        let active = progress.active.lock().unwrap().len();
        eprintln!(
            "[{}] {:5.1}%  {} / {}  files {}+{}/{}  failed {}  {}/s  active {}",
            human_duration(progress.started.elapsed().as_secs()),
            pct.min(100.0),
            human_bytes(t.bytes_done),
            human_bytes(t.bytes_total),
            t.files_fetched,
            t.files_present,
            t.files_total,
            t.files_failed,
            human_bytes(speed as u64),
            active
        );
    }
}
