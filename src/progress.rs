//! Shared progress state read by the TUI and the headless reporter.
use chrono::Local;
use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn tag(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO ",
            Level::Warn => "WARN ",
            Level::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogLine {
    pub time: String,
    pub level: Level,
    pub repo: String,
    pub msg: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    Queued = 0,
    Release = 1,
    Indices = 2,
    Scanning = 3,
    Downloading = 4,
    Publishing = 5,
    Cleaning = 6,
    Done = 7,
    Failed = 8,
    Partial = 9,
    Cancelled = 10,
    Skipped = 11,
}

impl Phase {
    pub fn from_u8(v: u8) -> Phase {
        use Phase::*;
        [
            Queued,
            Release,
            Indices,
            Scanning,
            Downloading,
            Publishing,
            Cleaning,
            Done,
            Failed,
            Partial,
            Cancelled,
            Skipped,
        ]
        .get(v as usize)
        .copied()
        .unwrap_or(Queued)
    }
    pub fn label(self) -> &'static str {
        match self {
            Phase::Queued => "queued",
            Phase::Release => "release",
            Phase::Indices => "indices",
            Phase::Scanning => "scanning",
            Phase::Downloading => "downloading",
            Phase::Publishing => "publishing",
            Phase::Cleaning => "cleaning",
            Phase::Done => "done",
            Phase::Failed => "FAILED",
            Phase::Partial => "PARTIAL",
            Phase::Cancelled => "cancelled",
            Phase::Skipped => "skipped",
        }
    }
    pub fn finished(self) -> bool {
        matches!(self, Phase::Done | Phase::Failed | Phase::Partial | Phase::Cancelled | Phase::Skipped)
    }
}

#[derive(Default)]
pub struct RepoProgress {
    pub name: String,
    phase: AtomicU8,
    /// Files this run needs (present + to download).
    pub files_total: AtomicU64,
    pub files_present: AtomicU64,
    pub files_fetched: AtomicU64,
    pub files_failed: AtomicU64,
    /// Bytes this run needs to transfer and has transferred.
    pub bytes_total: AtomicU64,
    pub bytes_done: AtomicU64,
    /// Bytes actually received from the network for this repository.
    pub net_bytes: AtomicU64,
    pub warnings: AtomicU64,
    pub errors: AtomicU64,
}

impl RepoProgress {
    pub fn phase(&self) -> Phase {
        Phase::from_u8(self.phase.load(Ordering::Relaxed))
    }
    pub fn set_phase(&self, p: Phase) {
        self.phase.store(p as u8, Ordering::Relaxed);
    }
}

pub struct ActiveDl {
    pub repo: usize,
    pub name: String,
    pub size: Option<u64>,
    pub done: Arc<AtomicU64>,
    pub started: Instant,
}

pub struct Progress {
    pub repos: Vec<RepoProgress>,
    pub active: Mutex<BTreeMap<u64, ActiveDl>>,
    next_id: AtomicU64,
    logs: Mutex<VecDeque<LogLine>>,
    pub log_seq: AtomicU64,
    /// Bytes received from the network in this session.
    pub net_bytes: AtomicU64,
    pub started: Instant,
    pub finished: AtomicBool,
    /// Print log lines to stderr as they happen (headless mode).
    pub echo: AtomicBool,
    pub verbose: AtomicBool,
    logfile: Mutex<Option<std::fs::File>>,
}

const LOG_CAP: usize = 5000;

impl Progress {
    pub fn new(names: &[String]) -> Arc<Progress> {
        Arc::new(Progress {
            repos: names.iter().map(|n| RepoProgress { name: n.clone(), ..Default::default() }).collect(),
            active: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            logs: Mutex::new(VecDeque::new()),
            log_seq: AtomicU64::new(0),
            net_bytes: AtomicU64::new(0),
            started: Instant::now(),
            finished: AtomicBool::new(false),
            echo: AtomicBool::new(false),
            verbose: AtomicBool::new(false),
            logfile: Mutex::new(None),
        })
    }

    pub fn set_logfile(&self, f: std::fs::File) {
        *self.logfile.lock().unwrap() = Some(f);
    }

    pub fn log(&self, level: Level, repo: Option<usize>, msg: impl Into<String>) {
        if level == Level::Debug && !self.verbose.load(Ordering::Relaxed) {
            return;
        }
        let repo_name = repo.map(|i| self.repos[i].name.clone()).unwrap_or_default();
        if let Some(i) = repo {
            match level {
                Level::Warn => {
                    self.repos[i].warnings.fetch_add(1, Ordering::Relaxed);
                }
                Level::Error => {
                    self.repos[i].errors.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
        let line = LogLine {
            time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            level,
            repo: repo_name,
            msg: msg.into(),
        };
        let text = format_line(&line);
        if let Some(f) = self.logfile.lock().unwrap().as_mut() {
            let _ = writeln!(f, "{text}");
        }
        if self.echo.load(Ordering::Relaxed) {
            eprintln!("{text}");
        }
        let mut logs = self.logs.lock().unwrap();
        if logs.len() >= LOG_CAP {
            logs.pop_front();
        }
        logs.push_back(line);
        self.log_seq.fetch_add(1, Ordering::Relaxed);
    }

    pub fn info(&self, repo: Option<usize>, msg: impl Into<String>) {
        self.log(Level::Info, repo, msg)
    }
    pub fn warn(&self, repo: Option<usize>, msg: impl Into<String>) {
        self.log(Level::Warn, repo, msg)
    }
    pub fn error(&self, repo: Option<usize>, msg: impl Into<String>) {
        self.log(Level::Error, repo, msg)
    }
    pub fn debug(&self, repo: Option<usize>, msg: impl Into<String>) {
        self.log(Level::Debug, repo, msg)
    }

    pub fn logs_snapshot(&self, min: Level) -> Vec<LogLine> {
        self.logs.lock().unwrap().iter().filter(|l| l.level >= min).cloned().collect()
    }

    pub fn begin(&self, repo: usize, name: String, size: Option<u64>) -> (u64, Arc<AtomicU64>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let done = Arc::new(AtomicU64::new(0));
        self.active
            .lock()
            .unwrap()
            .insert(id, ActiveDl { repo, name, size, done: done.clone(), started: Instant::now() });
        (id, done)
    }
    pub fn end(&self, id: u64) {
        self.active.lock().unwrap().remove(&id);
    }

    pub fn totals(&self) -> Totals {
        let mut t = Totals::default();
        for r in &self.repos {
            t.files_total += r.files_total.load(Ordering::Relaxed);
            t.files_present += r.files_present.load(Ordering::Relaxed);
            t.files_fetched += r.files_fetched.load(Ordering::Relaxed);
            t.files_failed += r.files_failed.load(Ordering::Relaxed);
            t.bytes_total += r.bytes_total.load(Ordering::Relaxed);
            t.bytes_done += r.bytes_done.load(Ordering::Relaxed);
            t.warnings += r.warnings.load(Ordering::Relaxed);
            t.errors += r.errors.load(Ordering::Relaxed);
        }
        t
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct Totals {
    pub files_total: u64,
    pub files_present: u64,
    pub files_fetched: u64,
    pub files_failed: u64,
    pub bytes_total: u64,
    pub bytes_done: u64,
    pub warnings: u64,
    pub errors: u64,
}

pub fn format_line(l: &LogLine) -> String {
    if l.repo.is_empty() {
        format!("{} {} {}", l.time, l.level.tag(), l.msg)
    } else {
        format!("{} {} [{}] {}", l.time, l.level.tag(), l.repo, l.msg)
    }
}
