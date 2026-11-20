//! Progress for long bundle operations (apply, check): how much of the bundle has been read,
//! how many files are done, the rate and the time left.
//!
//! On a terminal it draws one line on stderr, redrawn four times a second and cleared when
//! done. Otherwise (a log, journald, a pipe) it prints a plain line every 30 seconds, so a
//! short operation logs nothing extra. Progress is measured in bytes of the bundle file read,
//! which is exact for compressed bundles too.
use crate::logo::{self, Charset};
use crate::util::{human_bytes, human_duration};
use std::io::{IsTerminal, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Whether to show progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Progress {
    /// A bar on a terminal, a line every 30 s otherwise.
    #[default]
    Auto,
    Off,
}

const BAR_EVERY: Duration = Duration::from_millis(250);
const LOG_EVERY: Duration = Duration::from_secs(30);
/// Rate over this window, so the time left follows the current speed.
const WINDOW: Duration = Duration::from_secs(10);

/// Counts bytes read through it into a shared counter.
pub struct Counting<R> {
    pub inner: R,
    pub count: Arc<AtomicU64>,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// The counters a running operation updates.
#[derive(Default)]
pub struct Counters {
    /// Bytes of the bundle file read so far.
    pub read: Arc<AtomicU64>,
    pub files: AtomicU64,
    pub total_files: AtomicU64,
}

pub struct Meter {
    counters: Arc<Counters>,
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Meter {
    /// Start showing progress of `verb` over a bundle of `total` bytes. `counters.read` must be
    /// the counter the bundle is read through.
    pub fn start(verb: &'static str, total: u64, counters: Arc<Counters>, mode: Progress) -> Meter {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let thread = (mode == Progress::Auto).then(|| {
            let (c, s) = (counters.clone(), stop.clone());
            let tty = std::io::stderr().is_terminal() && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true);
            let unicode = logo::resolve(None) == Charset::Unicode;
            std::thread::spawn(move || run(verb, total, &c, &s, tty, unicode))
        });
        Meter { counters, stop, thread }
    }

    pub fn file_done(&self) {
        self.counters.files.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_total_files(&self, n: u64) {
        self.counters.total_files.store(n, Ordering::Relaxed);
    }
}

impl Drop for Meter {
    fn drop(&mut self) {
        {
            let (lock, cv) = &*self.stop;
            *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
            cv.notify_all();
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// What one look at the counters says.
struct Snapshot {
    read: u64,
    files: u64,
    total_files: u64,
    /// Bytes per second over the recent window (None until there is enough to tell).
    rate: Option<f64>,
}

fn run(verb: &str, total: u64, c: &Counters, stop: &(Mutex<bool>, Condvar), tty: bool, unicode: bool) {
    let started = Instant::now();
    let mut samples: std::collections::VecDeque<(Instant, u64)> = std::collections::VecDeque::new();
    let mut drawn = false;
    let mut last_log = started;
    loop {
        let (lock, cv) = stop;
        let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        let (guard, _) = cv.wait_timeout(guard, BAR_EVERY).unwrap_or_else(|e| e.into_inner());
        let stopping = *guard;
        drop(guard);
        if stopping {
            if drawn {
                let mut err = std::io::stderr().lock();
                let _ = write!(err, "\r\x1b[2K");
                let _ = err.flush();
            }
            return;
        }
        let now = Instant::now();
        let read = c.read.load(Ordering::Relaxed);
        samples.push_back((now, read));
        while samples.len() > 2 && now.duration_since(samples[0].0) > WINDOW {
            samples.pop_front();
        }
        let (t0, b0) = samples[0];
        let span = now.duration_since(t0).as_secs_f64();
        let rate = (now.duration_since(started) >= Duration::from_secs(2) && span > 0.5)
            .then(|| (read.saturating_sub(b0)) as f64 / span);
        let snap = Snapshot {
            read,
            files: c.files.load(Ordering::Relaxed),
            total_files: c.total_files.load(Ordering::Relaxed),
            rate,
        };
        if tty {
            let line = bar_line(verb, total, &snap, unicode, terminal_width());
            let mut err = std::io::stderr().lock();
            let _ = write!(err, "\r\x1b[2K{line}");
            let _ = err.flush();
            drawn = true;
        } else if now.duration_since(last_log) >= LOG_EVERY {
            last_log = now;
            eprintln!("{}", log_line(verb, total, &snap));
        }
    }
}

fn percent(read: u64, total: u64) -> f64 {
    if total == 0 { 100.0 } else { (read.min(total) as f64 * 100.0) / total as f64 }
}

fn left(total: u64, s: &Snapshot) -> Option<String> {
    let rate = s.rate.filter(|r| *r > 0.0)?;
    Some(human_duration((total.saturating_sub(s.read) as f64 / rate).ceil() as u64))
}

fn files_part(s: &Snapshot) -> String {
    match (s.files, s.total_files) {
        (0, 0) => String::new(),
        (n, 0) => format!("{n} files"),
        (n, t) => format!("{}/{t} files", n.min(t)),
    }
}

/// `apply ████████░░░░░░░░  54%  3.1 GiB/5.7 GiB  1203/2210 files  92.0 MiB/s  00:28 left`,
/// dropping the least useful parts first when the terminal is narrow.
fn bar_line(verb: &str, total: u64, s: &Snapshot, unicode: bool, width: usize) -> String {
    let pct = percent(s.read, total);
    let (full, empty) = if unicode { ('█', '░') } else { ('#', '-') };
    let cells = 16usize;
    let filled = ((pct / 100.0) * cells as f64).floor() as usize;
    let bar: String = std::iter::repeat_n(full, filled).chain(std::iter::repeat_n(empty, cells - filled)).collect();
    let rate = s.rate.map(|r| format!("{}/s", human_bytes(r as u64))).unwrap_or_default();
    let eta = left(total, s).map(|t| format!("{t} left")).unwrap_or_default();
    let parts = [
        format!("{verb} {bar} {pct:>3.0}%"),
        format!("{}/{}", human_bytes(s.read.min(total)), human_bytes(total)),
        eta,
        files_part(s),
        rate,
    ];
    // The bar itself always shows; the rest only while it fits.
    let mut line = parts[0].clone();
    for p in parts[1..].iter().filter(|p| !p.is_empty()) {
        let next = format!("{line}  {p}");
        if next.chars().count() >= width {
            break;
        }
        line = next;
    }
    line
}

/// `apply: 54% of 5.7 GiB read, 1203/2210 files, 92.0 MiB/s, about 00:28 left`
fn log_line(verb: &str, total: u64, s: &Snapshot) -> String {
    let mut line = format!("{verb}: {:.0}% of {} read", percent(s.read, total), human_bytes(total));
    let files = files_part(s);
    if !files.is_empty() {
        line += &format!(", {files}");
    }
    if let Some(r) = s.rate {
        line += &format!(", {}/s", human_bytes(r as u64));
    }
    if let Some(t) = left(total, s) {
        line += &format!(", about {t} left");
    }
    line
}

#[cfg(unix)]
fn terminal_width() -> usize {
    // SAFETY: TIOCGWINSZ fills a winsize; on failure the zeroed value is ignored.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0;
    if ok && ws.ws_col > 0 { ws.ws_col as usize } else { 80 }
}

#[cfg(not(unix))]
fn terminal_width() -> usize {
    80
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(read: u64, files: u64, total_files: u64, rate: Option<f64>) -> Snapshot {
        Snapshot { read, files, total_files, rate }
    }

    #[test]
    fn bar_shows_everything_on_a_wide_terminal() {
        let gib = 1u64 << 30;
        let l = bar_line("apply", 10 * gib, &snap(5 * gib, 1203, 2210, Some(100.0 * 1048576.0)), true, 120);
        assert_eq!(l, "apply ████████░░░░░░░░  50%  5.0 GiB/10.0 GiB  00:52 left  1203/2210 files  100.0 MiB/s");
    }

    #[test]
    fn bar_drops_parts_to_fit_and_never_exceeds_the_width() {
        let gib = 1u64 << 30;
        let s = snap(5 * gib, 1203, 2210, Some(100.0 * 1048576.0));
        for w in [20, 40, 60, 79, 80] {
            let l = bar_line("apply", 10 * gib, &s, true, w);
            assert!(l.chars().count() < w.max(30), "{w}: {l}");
        }
        assert_eq!(
            bar_line("apply", 10 * gib, &s, false, 60),
            "apply ########--------  50%  5.0 GiB/10.0 GiB  00:52 left"
        );
    }

    #[test]
    fn no_time_left_until_there_is_a_rate() {
        let l = log_line("check", 1000, &snap(0, 0, 0, None));
        assert_eq!(l, "check: 0% of 1000 B read");
        let l = log_line("apply", 4 << 20, &snap(1 << 20, 3, 12, Some(1048576.0)));
        assert_eq!(l, "apply: 25% of 4.0 MiB read, 3/12 files, 1.0 MiB/s, about 00:03 left");
    }

    #[test]
    fn counts_bytes_read() {
        let count = Arc::new(AtomicU64::new(0));
        let mut r = Counting { inner: &b"hello world"[..], count: count.clone() };
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 11);
    }
}
