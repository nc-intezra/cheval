//! Progress for long operations outside `sync` (bundle create/apply, verify, snapshots).
//!
//! Three kinds of total:
//! * **bytes** known (applying or writing a bundle, `verify --full`): a bar, percentage and
//!   time left from bytes done;
//! * **files** known (quick `verify`): the same from files done;
//! * **none** (scanning, snapshots): running counts of files and bytes.
//!
//! On a terminal it draws one line on stderr, redrawn four times a second and cleared when
//! done. Otherwise (a log, journald, a pipe) it prints a plain line every 30 seconds, so a
//! short operation logs nothing extra. stdout is never touched.
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

impl Progress {
    /// `Off` when `--no-progress` was given.
    pub fn from_flag(no_progress: bool) -> Progress {
        if no_progress { Progress::Off } else { Progress::Auto }
    }
}

const BAR_EVERY: Duration = Duration::from_millis(250);
const LOG_EVERY: Duration = Duration::from_secs(30);
/// Rates over this window, so the time left follows the current speed.
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
    /// Bytes done so far (read, written or hashed).
    pub read: Arc<AtomicU64>,
    pub files: AtomicU64,
    pub total_files: AtomicU64,
}

impl Counters {
    pub fn add_bytes(&self, n: u64) {
        self.read.fetch_add(n, Ordering::Relaxed);
    }
    pub fn file_done(&self) {
        self.files.fetch_add(1, Ordering::Relaxed);
    }
}

pub struct Meter {
    counters: Arc<Counters>,
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Meter {
    /// Start showing progress of `verb`. `total_bytes`: the bytes the operation will do, if
    /// known; otherwise a file total set with [`Meter::set_total_files`] gives the
    /// percentage, and with neither the meter shows running counts.
    pub fn start(verb: &'static str, total_bytes: Option<u64>, counters: Arc<Counters>, mode: Progress) -> Meter {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let thread = (mode == Progress::Auto).then(|| {
            let (c, s) = (counters.clone(), stop.clone());
            let tty = std::io::stderr().is_terminal() && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true);
            let unicode = logo::resolve(None) == Charset::Unicode;
            std::thread::spawn(move || run(verb, total_bytes, &c, &s, tty, unicode))
        });
        Meter { counters, stop, thread }
    }

    pub fn file_done(&self) {
        self.counters.file_done();
    }

    pub fn set_total_files(&self, n: u64) {
        self.counters.total_files.store(n, Ordering::Relaxed);
    }

    pub fn counters(&self) -> &Arc<Counters> {
        &self.counters
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
    bytes: u64,
    total_bytes: Option<u64>,
    files: u64,
    total_files: u64,
    /// Bytes and files per second over the recent window (None until there is enough to tell).
    byte_rate: Option<f64>,
    file_rate: Option<f64>,
    /// Seconds left, when there is a total and a rate.
    left: Option<u64>,
}

impl Snapshot {
    /// Share done, 0..=1, when a total is known.
    fn fraction(&self) -> Option<f64> {
        match self.total_bytes {
            Some(0) => Some(1.0),
            Some(t) => Some(self.bytes.min(t) as f64 / t as f64),
            None if self.total_files > 0 => Some(self.files.min(self.total_files) as f64 / self.total_files as f64),
            None => None,
        }
    }
}

fn run(verb: &str, total_bytes: Option<u64>, c: &Counters, stop: &(Mutex<bool>, Condvar), tty: bool, unicode: bool) {
    let started = Instant::now();
    // (time, bytes, files, fraction)
    let mut samples: std::collections::VecDeque<(Instant, u64, u64, Option<f64>)> = std::collections::VecDeque::new();
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
        let mut snap = Snapshot {
            bytes: c.read.load(Ordering::Relaxed),
            total_bytes,
            files: c.files.load(Ordering::Relaxed),
            total_files: c.total_files.load(Ordering::Relaxed),
            byte_rate: None,
            file_rate: None,
            left: None,
        };
        let fraction = snap.fraction();
        samples.push_back((now, snap.bytes, snap.files, fraction));
        while samples.len() > 2 && now.duration_since(samples[0].0) > WINDOW {
            samples.pop_front();
        }
        let (t0, b0, f0, p0) = samples[0];
        let span = now.duration_since(t0).as_secs_f64();
        if now.duration_since(started) >= Duration::from_secs(2) && span > 0.5 {
            snap.byte_rate = Some(snap.bytes.saturating_sub(b0) as f64 / span);
            snap.file_rate = Some(snap.files.saturating_sub(f0) as f64 / span);
            if let (Some(p), Some(p0)) = (fraction, p0)
                && p > p0
            {
                snap.left = Some(((1.0 - p) * span / (p - p0)).ceil() as u64);
            }
        }
        if tty {
            let line = bar_line(verb, &snap, unicode, terminal_width());
            let mut err = std::io::stderr().lock();
            let _ = write!(err, "\r\x1b[2K{line}");
            let _ = err.flush();
            drawn = true;
        } else if now.duration_since(last_log) >= LOG_EVERY {
            last_log = now;
            eprintln!("{}", log_line(verb, &snap));
        }
    }
}

fn files_part(s: &Snapshot) -> String {
    match (s.files, s.total_files) {
        (0, 0) => String::new(),
        (n, 0) => format!("{n} files"),
        (n, t) => format!("{}/{t} files", n.min(t)),
    }
}

fn bytes_part(s: &Snapshot) -> String {
    match s.total_bytes {
        Some(t) => format!("{}/{}", human_bytes(s.bytes.min(t)), human_bytes(t)),
        None if s.bytes > 0 => human_bytes(s.bytes),
        None => String::new(),
    }
}

/// Bytes per second while bytes move, files per second otherwise.
fn rate_part(s: &Snapshot) -> String {
    match (s.byte_rate, s.file_rate) {
        (Some(b), _) if b >= 1.0 => format!("{}/s", human_bytes(b as u64)),
        (_, Some(f)) if f >= 1.0 => format!("{f:.0} files/s"),
        _ => String::new(),
    }
}

/// `apply ████████░░░░░░░░  54%  3.1 GiB/5.7 GiB  00:28 left  1203/2210 files  92.0 MiB/s`,
/// or without a total `scan  84213 files  1.2 GiB  35.0 MiB/s`; the least useful parts are
/// dropped first when the terminal is narrow.
fn bar_line(verb: &str, s: &Snapshot, unicode: bool, width: usize) -> String {
    let head = match s.fraction() {
        Some(p) => {
            let (full, empty) = if unicode { ('█', '░') } else { ('#', '-') };
            let cells = 16usize;
            let filled = (p * cells as f64).floor() as usize;
            let bar: String =
                std::iter::repeat_n(full, filled).chain(std::iter::repeat_n(empty, cells - filled)).collect();
            format!("{verb} {bar} {:>3.0}%", p * 100.0)
        }
        None => verb.to_string(),
    };
    let left = s.left.map(|t| format!("{} left", human_duration(t))).unwrap_or_default();
    let parts = [bytes_part(s), left, files_part(s), rate_part(s)];
    // The head always shows; the rest only while it fits.
    let mut line = head;
    for p in parts.iter().filter(|p| !p.is_empty()) {
        let next = format!("{line}  {p}");
        if next.chars().count() >= width {
            break;
        }
        line = next;
    }
    line
}

/// `apply: 54% of 5.7 GiB, 1203/2210 files, 92.0 MiB/s, about 00:28 left`, or without a
/// total `scan: 84213 files, 1.2 GiB so far, 35.0 MiB/s`.
fn log_line(verb: &str, s: &Snapshot) -> String {
    let mut parts: Vec<String> = Vec::new();
    match (s.fraction(), s.total_bytes) {
        (Some(p), Some(t)) => parts.push(format!("{:.0}% of {}", p * 100.0, human_bytes(t))),
        (Some(p), None) => parts.push(format!("{:.0}%", p * 100.0)),
        (None, _) => {}
    }
    parts.push(files_part(s));
    if s.total_bytes.is_none() && s.bytes > 0 {
        parts.push(format!("{} so far", human_bytes(s.bytes)));
    }
    parts.push(rate_part(s));
    if let Some(t) = s.left {
        parts.push(format!("about {} left", human_duration(t)));
    }
    let parts: Vec<String> = parts.into_iter().filter(|p| !p.is_empty()).collect();
    format!("{verb}: {}", if parts.is_empty() { "starting".to_string() } else { parts.join(", ") })
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

    const MIB: f64 = 1048576.0;

    fn snap(bytes: u64, total_bytes: Option<u64>, files: u64, total_files: u64) -> Snapshot {
        Snapshot { bytes, total_bytes, files, total_files, byte_rate: None, file_rate: None, left: None }
    }

    #[test]
    fn bar_shows_everything_on_a_wide_terminal() {
        let gib = 1u64 << 30;
        let s = Snapshot { byte_rate: Some(100.0 * MIB), left: Some(52), ..snap(5 * gib, Some(10 * gib), 1203, 2210) };
        let l = bar_line("apply", &s, true, 120);
        assert_eq!(l, "apply ████████░░░░░░░░  50%  5.0 GiB/10.0 GiB  00:52 left  1203/2210 files  100.0 MiB/s");
    }

    #[test]
    fn bar_drops_parts_to_fit() {
        let gib = 1u64 << 30;
        let s = Snapshot { byte_rate: Some(100.0 * MIB), left: Some(52), ..snap(5 * gib, Some(10 * gib), 1203, 2210) };
        for w in [20, 40, 60, 79, 80] {
            let l = bar_line("apply", &s, true, w);
            assert!(l.chars().count() < w.max(30), "{w}: {l}");
        }
        assert_eq!(bar_line("apply", &s, false, 60), "apply ########--------  50%  5.0 GiB/10.0 GiB  00:52 left");
    }

    #[test]
    fn file_totals_and_running_counts() {
        // quick verify: a file total, files per second
        let s =
            Snapshot { file_rate: Some(3000.0), byte_rate: Some(0.0), left: Some(70), ..snap(0, None, 90210, 220000) };
        assert_eq!(
            bar_line("verify", &s, true, 120),
            "verify ██████░░░░░░░░░░  41%  01:10 left  90210/220000 files  3000 files/s"
        );
        assert_eq!(log_line("verify", &s), "verify: 41%, 90210/220000 files, 3000 files/s, about 01:10 left");
        // scan or snapshot: no total at all
        let s = Snapshot { byte_rate: Some(35.0 * MIB), ..snap(1288490188, None, 84213, 0) };
        assert_eq!(bar_line("scan", &s, true, 120), "scan  1.2 GiB  84213 files  35.0 MiB/s");
        assert_eq!(log_line("scan", &s), "scan: 84213 files, 1.2 GiB so far, 35.0 MiB/s");
    }

    #[test]
    fn no_time_left_until_there_is_a_rate() {
        assert_eq!(log_line("check", &snap(0, Some(1000), 0, 0)), "check: 0% of 1000 B");
        assert_eq!(log_line("snapshot", &snap(0, None, 0, 0)), "snapshot: starting");
        let s = Snapshot { byte_rate: Some(MIB), left: Some(3), ..snap(1 << 20, Some(4 << 20), 3, 12) };
        assert_eq!(log_line("apply", &s), "apply: 25% of 4.0 MiB, 3/12 files, 1.0 MiB/s, about 00:03 left");
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
