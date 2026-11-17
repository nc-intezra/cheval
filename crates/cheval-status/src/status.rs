//! Status reporting: the message schema, the in-memory status store behind the HTTP API,
//! and the hub that feeds one-way sinks (see `sink`).
//!
//! Everything here is monitoring only. No mirror content is ever sent through it.
//!
//! Design rules, all of which follow from "the far side of a data diode cannot answer":
//! * every message is a complete snapshot, so a lost one is repaired by the next;
//! * every message fits one unfragmented datagram ([`MAX_DATAGRAM`] bytes);
//! * emitting never blocks the mirror: sinks are fed from bounded queues and drop when full.
use crate::config::{Sink, SinkFormat, Status};
use crate::progress::{Level, Phase, Progress};
use crate::summary::Summary;
use crate::util::{human_bytes, human_duration};
use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

pub const SCHEMA_VERSION: u32 = 1;
/// Largest datagram cheval sends (fits a 1280-byte IPv6 minimum MTU path).
pub const MAX_DATAGRAM: usize = 1200;
/// JSON budget before the optional `mac` field (10 + 64 bytes) is appended.
const MAX_BODY: usize = MAX_DATAGRAM - 80;
const EVENT_RING: usize = 500;
const MAX_REPOS: usize = 4096;
const SINK_QUEUE: usize = 512;

// ------------------------------------------------------------------------------- schema

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Message {
    /// Schema version.
    pub v: u32,
    /// Sender session: changes whenever the sending process restarts.
    pub sid: String,
    /// Run the message belongs to; absent between runs.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub run: String,
    /// Counts up by one per message within a session; gaps mean loss.
    pub seq: u64,
    /// Sender clock, UTC, RFC 3339.
    pub ts: String,
    pub host: String,
    #[serde(flatten)]
    pub body: Body,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Body {
    Run(RunMsg),
    Repo(RepoMsg),
    Event(EventMsg),
    End(EndMsg),
    Heartbeat(HeartbeatMsg),
}

impl Body {
    pub fn kind(&self) -> &'static str {
        match self {
            Body::Run(_) => "run",
            Body::Repo(_) => "repo",
            Body::Event(_) => "event",
            Body::End(_) => "end",
            Body::Heartbeat(_) => "heartbeat",
        }
    }
}

/// Overall progress of the run in flight.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct RunMsg {
    pub state: String,
    pub dry_run: bool,
    pub elapsed_s: u64,
    pub files_total: u64,
    pub files_present: u64,
    pub files_fetched: u64,
    pub files_failed: u64,
    pub bytes_total: u64,
    pub bytes_done: u64,
    pub speed_bps: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_s: Option<u64>,
    pub warnings: u64,
    pub errors: u64,
    /// Transfers in flight.
    pub active: u64,
    pub repos_total: u64,
    pub repos_done: u64,
    pub repos_failed: u64,
    /// Status messages this sender could not hand to a sink (queue full or link down).
    pub dropped: u64,
    /// Log events not sent because too many happened at once.
    pub events_suppressed: u64,
}

/// One repository.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct RepoMsg {
    pub name: String,
    pub phase: String,
    pub files_total: u64,
    pub files_present: u64,
    pub files_fetched: u64,
    pub files_failed: u64,
    pub bytes_total: u64,
    pub bytes_done: u64,
    pub warnings: u64,
    pub errors: u64,
    /// Known once the repository finished.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suites_ok: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suites_failed: Option<u64>,
    /// Age of the oldest published Release file of this repository on the mirror.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_age_s: Option<u64>,
}

/// Something that happened: a published or failed suite, a warning, an error.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct EventMsg {
    /// info | warning | error
    pub level: String,
    /// suite_ok | suite_failed | daemon | log
    pub kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub repo: String,
    pub text: String,
}

/// Final result of a run.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct EndMsg {
    /// finished | failed | cancelled | error
    pub state: String,
    /// What `cheval sync` exits with: 0 ok, 1 suites failed, 2 error, 130 interrupted.
    pub exit_code: i32,
    pub dry_run: bool,
    pub elapsed_s: u64,
    pub repos_ok: u64,
    pub repos_failed: u64,
    pub repos_skipped: u64,
    /// Names of failed repositories (shortened to fit, see `truncated`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<String>,
    pub files_fetched: u64,
    pub bytes_fetched: u64,
    pub files_failed: u64,
    pub cleaned_files: u64,
    pub cleaned_bytes: u64,
    pub warnings: u64,
    pub errors: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// The run a heartbeat refers back to.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct LastRun {
    pub run: String,
    pub state: String,
    pub exit_code: i32,
    pub finished_at: String,
    pub repos_ok: u64,
    pub repos_failed: u64,
}

/// "The daemon is alive and idle."
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct HeartbeatMsg {
    pub state: String,
    pub uptime_s: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_run: Option<LastRun>,
    /// Next scheduled run, RFC 3339 with the sender's UTC offset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run: Option<String>,
    /// Age of the oldest published Release file on the mirror.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_release_age_s: Option<u64>,
    pub repos_total: u64,
    pub dropped: u64,
}

/// Cut `s` to at most `max` bytes on a character boundary, marking the cut with `…`.
pub fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max.saturating_sub(3);
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Control characters would break syslog lines and terminals on the far side.
fn clean(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

pub fn now_ts() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

impl Message {
    /// Make a message from the network safe to print and store: no control characters (they
    /// could carry terminal escape sequences) and no oversized strings.
    pub fn sanitize(&mut self) {
        fn fix(s: &mut String, max: usize) {
            if s.len() > max || s.chars().any(|c| c.is_control()) {
                *s = clip(&clean(s), max);
            }
        }
        for s in [&mut self.sid, &mut self.run, &mut self.ts, &mut self.host] {
            fix(s, 64);
        }
        match &mut self.body {
            Body::Run(r) => fix(&mut r.state, 32),
            Body::Repo(r) => {
                fix(&mut r.name, 96);
                fix(&mut r.phase, 32);
            }
            Body::Event(e) => {
                fix(&mut e.level, 16);
                fix(&mut e.kind, 32);
                fix(&mut e.repo, 96);
                fix(&mut e.text, 1000);
            }
            Body::End(e) => {
                fix(&mut e.state, 32);
                fix(&mut e.error, 1000);
                e.failed.truncate(64);
                e.failed.iter_mut().for_each(|f| fix(f, 96));
            }
            Body::Heartbeat(h) => {
                fix(&mut h.state, 32);
                if let Some(n) = &mut h.next_run {
                    fix(n, 40);
                }
                if let Some(l) = &mut h.last_run {
                    fix(&mut l.run, 64);
                    fix(&mut l.state, 32);
                    fix(&mut l.finished_at, 40);
                }
            }
        }
    }

    /// Serialize to JSON no longer than the datagram budget, shortening free text if necessary.
    pub fn to_json(&self) -> String {
        let mut m = self.clone();
        m.host = clip(&clean(&m.host), 64);
        match &mut m.body {
            Body::Repo(r) => r.name = clip(&clean(&r.name), 96),
            Body::Event(e) => {
                e.repo = clip(&clean(&e.repo), 96);
                e.text = clip(&clean(&e.text), 700);
            }
            Body::End(e) => {
                e.error = clip(&clean(&e.error), 400);
                for f in &mut e.failed {
                    *f = clip(&clean(f), 96);
                }
            }
            Body::Run(_) | Body::Heartbeat(_) => {}
        }
        loop {
            let json = serde_json::to_string(&m).expect("status messages always serialize");
            if json.len() <= MAX_BODY {
                return json;
            }
            // JSON escaping can inflate text (quotes, non-ASCII): shrink and try again.
            let over = json.len() - MAX_BODY;
            let shrunk = match &mut m.body {
                Body::Event(e) if e.text.len() > 16 => {
                    e.text = clip(&e.text, e.text.len().saturating_sub(over + 8).max(16));
                    true
                }
                Body::End(e) if !e.failed.is_empty() => {
                    e.failed.pop();
                    e.truncated = true;
                    true
                }
                Body::End(e) if e.error.len() > 16 => {
                    e.error = clip(&e.error, e.error.len().saturating_sub(over + 8).max(16));
                    true
                }
                _ => false,
            };
            if !shrunk {
                return json;
            }
        }
    }

    /// One line for people: (syslog severity, message id, text). `None` for per-repository
    /// progress, which would only flood a log.
    pub fn human(&self) -> Option<(u8, &'static str, String)> {
        Some(match &self.body {
            Body::Repo(_) => return None,
            Body::Run(r) => {
                let pct = if r.bytes_total > 0 {
                    (r.bytes_done as f64 * 100.0 / r.bytes_total as f64).min(100.0)
                } else {
                    0.0
                };
                let eta = r.eta_s.map(human_duration).unwrap_or_else(|| "--:--".into());
                (
                    6,
                    "run",
                    format!(
                        "{} {} {pct:.1}% {} / {} {}/s ETA {eta} files {}/{} failed={}",
                        if r.dry_run { "dry run" } else { "sync" },
                        r.state,
                        human_bytes(r.bytes_done),
                        human_bytes(r.bytes_total),
                        human_bytes(r.speed_bps),
                        r.files_fetched.saturating_add(r.files_present),
                        r.files_total,
                        r.files_failed
                    ),
                )
            }
            Body::Event(e) => {
                let sev = match e.level.as_str() {
                    "error" => 3,
                    "warning" => 4,
                    _ => 6,
                };
                let text = if e.repo.is_empty() { e.text.clone() } else { format!("[{}] {}", e.repo, e.text) };
                (sev, "event", text)
            }
            Body::End(e) => {
                let what = if e.dry_run { "dry run" } else { "sync" };
                let took = human_duration(e.elapsed_s);
                let (sev, head) = match e.state.as_str() {
                    "finished" => (6, format!("{what} finished in {took}")),
                    "cancelled" => (4, format!("{what} CANCELLED after {took}")),
                    "error" => (3, format!("{what} could not run: {}", e.error)),
                    _ => (3, format!("{what} finished WITH ERRORS in {took}")),
                };
                (
                    sev,
                    "end",
                    format!(
                        "{head}: {} repos ok, {} failed, {} fetched ({} files), {} files failed",
                        e.repos_ok,
                        e.repos_failed,
                        human_bytes(e.bytes_fetched),
                        e.files_fetched,
                        e.files_failed
                    ),
                )
            }
            Body::Heartbeat(h) => {
                let last = match &h.last_run {
                    Some(l) if l.state == "finished" => format!("last run {} ok", l.finished_at),
                    Some(l) => format!(
                        "last run {} {} (repos failed: {})",
                        l.finished_at,
                        l.state.to_uppercase(),
                        l.repos_failed
                    ),
                    None => "no run yet".to_string(),
                };
                let next = h.next_run.as_ref().map(|n| format!(", next run {n}")).unwrap_or_default();
                (6, "heartbeat", format!("{}, {last}{next}", h.state))
            }
        })
    }

    /// RFC 5424 line (without transport framing), or `None` for message types not sent to syslog.
    pub fn syslog(&self, facility: u8, pid: u32) -> Option<String> {
        let (sev, msgid, text) = self.human()?;
        let host: String = self.host.chars().filter(|c| c.is_ascii_graphic()).take(64).collect();
        let host = if host.is_empty() { "-".to_string() } else { host };
        let pri = facility as u16 * 8 + sev as u16;
        let line = format!("<{pri}>1 {} {host} cheval {pid} {msgid} - {}", self.ts, clean(&text));
        Some(clip(&line, MAX_DATAGRAM))
    }
}

// --------------------------------------------------------------------------------- HMAC

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(data);
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

const MAC_FIELD: &str = ",\"mac\":\"";

/// Append `"mac":"<hex HMAC-SHA256 of the JSON without the field>"` as the last member.
pub fn sign(json: &str, key: &[u8]) -> String {
    let mac = hex::encode(hmac_sha256(key, json.as_bytes()));
    format!("{}{MAC_FIELD}{mac}\"}}", &json[..json.len() - 1])
}

/// Check the trailing `mac` member; returns the JSON that was signed.
pub fn verify(raw: &str, key: &[u8]) -> Option<String> {
    let raw = raw.trim_end();
    let at = raw.rfind(MAC_FIELD)?;
    let mac = raw[at + MAC_FIELD.len()..].strip_suffix("\"}")?;
    let json = format!("{}}}", &raw[..at]);
    let want = hex::encode(hmac_sha256(key, json.as_bytes()));
    constant_time_eq(mac.as_bytes(), want.as_bytes()).then_some(json)
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Read an HMAC key file: the first line, surrounding whitespace removed.
pub fn read_key(path: &std::path::Path) -> Result<Vec<u8>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read HMAC key file {}", path.display()))?;
    let key = text.lines().next().unwrap_or("").trim();
    if key.len() < 16 {
        anyhow::bail!("HMAC key file {}: the key must be at least 16 characters", path.display());
    }
    Ok(key.as_bytes().to_vec())
}

// -------------------------------------------------------------------------------- store

/// Counters a receiver keeps about the stream it is fed from.
#[derive(Default, Clone, Debug)]
pub struct RxStats {
    pub received: u64,
    pub accepted: u64,
    pub duplicates: u64,
    pub lost: u64,
    pub bad_mac: u64,
    pub malformed: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Ingest {
    Accepted,
    Duplicate,
    BadMac,
    Malformed,
}

/// Counters of one sink, shared with the HTTP API.
#[derive(Default)]
pub struct SinkStats {
    pub url: String,
    pub format: &'static str,
    pub sent: AtomicU64,
    pub dropped: AtomicU64,
    pub errors: AtomicU64,
    /// Messages queued or being written.
    pub pending: AtomicU64,
}

struct Inner {
    status: Option<(Message, Instant)>,
    end: Option<Message>,
    repos: BTreeMap<String, (Message, Instant)>,
    events: VecDeque<(u64, Message)>,
    next_event: u64,
    rx: RxStats,
    /// Highest sequence number seen per sender session.
    sessions: HashMap<String, (u64, Instant)>,
    last_rx: Option<Instant>,
    sinks: Vec<Arc<SinkStats>>,
}

/// Latest known state, on either side of the diode. The HTTP API reads from here.
pub struct Store {
    inner: Mutex<Inner>,
    /// Every accepted message as a JSON line, for `/v1/stream`.
    pub stream: broadcast::Sender<Arc<str>>,
    /// `Some` on a receiver: silence longer than this means the sender may be dead.
    pub stale_after: Option<Duration>,
    started: Instant,
}

impl Store {
    pub fn new(stale_after: Option<Duration>) -> Arc<Store> {
        Arc::new(Store {
            inner: Mutex::new(Inner {
                status: None,
                end: None,
                repos: BTreeMap::new(),
                events: VecDeque::new(),
                next_event: 1,
                rx: RxStats::default(),
                sessions: HashMap::new(),
                last_rx: None,
                sinks: Vec::new(),
            }),
            stream: broadcast::channel(1024).0,
            stale_after,
            started: Instant::now(),
        })
    }

    pub fn is_receiver(&self) -> bool {
        self.stale_after.is_some()
    }

    /// Fold one message into the state.
    pub fn apply(&self, msg: &Message, json: &str) {
        let now = Instant::now();
        let mut s = self.inner.lock().unwrap();
        match &msg.body {
            Body::Run(_) | Body::End(_) => s.status = Some((msg.clone(), now)),
            Body::Heartbeat(_) => {
                // A daemon idling next to a manual `cheval sync` must not hide the run in flight.
                let hidden_run = matches!(&s.status, Some((cur, at))
                    if matches!(cur.body, Body::Run(_)) && cur.sid != msg.sid && at.elapsed() < Duration::from_secs(15));
                if !hidden_run {
                    s.status = Some((msg.clone(), now));
                }
            }
            Body::Repo(r) => {
                // Bounded memory even if someone floods an unauthenticated receiver with names.
                if s.repos.len() >= MAX_REPOS && !s.repos.contains_key(&r.name) {
                    return;
                }
                s.repos.insert(r.name.clone(), (msg.clone(), now));
                // Repositories removed from the sender's configuration stop being refreshed.
                s.repos.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(86_400));
            }
            Body::Event(_) => {
                let id = s.next_event;
                s.next_event += 1;
                if s.events.len() >= EVENT_RING {
                    s.events.pop_front();
                }
                s.events.push_back((id, msg.clone()));
            }
        }
        if let Body::End(_) = &msg.body {
            s.end = Some(msg.clone());
        }
        drop(s);
        let _ = self.stream.send(Arc::from(json));
    }

    /// Receiver entry point: authenticate, de-duplicate, count gaps, then [`Store::apply`].
    pub fn ingest(&self, raw: &[u8], key: Option<&[u8]>) -> Ingest {
        let bump = |f: fn(&mut RxStats)| {
            let mut s = self.inner.lock().unwrap();
            s.rx.received += 1;
            f(&mut s.rx);
        };
        let Ok(text) = std::str::from_utf8(raw) else {
            bump(|r| r.malformed += 1);
            return Ingest::Malformed;
        };
        let text = text.trim();
        let json = match key {
            Some(k) => match verify(text, k) {
                Some(j) => j,
                None => {
                    bump(|r| r.bad_mac += 1);
                    return Ingest::BadMac;
                }
            },
            None => text.to_string(),
        };
        let mut msg: Message = match serde_json::from_str(&json) {
            Ok(m) => m,
            Err(_) => {
                bump(|r| r.malformed += 1);
                return Ingest::Malformed;
            }
        };
        msg.sanitize();
        {
            let mut s = self.inner.lock().unwrap();
            s.rx.received += 1;
            let now = Instant::now();
            match s.sessions.get(&msg.sid).copied() {
                Some((last, _)) if msg.seq <= last => {
                    s.rx.duplicates += 1;
                    return Ingest::Duplicate;
                }
                Some((last, _)) => s.rx.lost = s.rx.lost.saturating_add(msg.seq - last - 1),
                None => {
                    // Bounded memory: forget the session that has been silent longest.
                    if s.sessions.len() >= 32
                        && let Some(old) = s.sessions.iter().min_by_key(|(_, (_, at))| *at).map(|(k, _)| k.clone())
                    {
                        s.sessions.remove(&old);
                    }
                }
            }
            s.sessions.insert(msg.sid.clone(), (msg.seq, now));
            s.rx.accepted += 1;
            s.last_rx = Some(now);
        }
        self.apply(&msg, text);
        Ingest::Accepted
    }

    pub fn set_sinks(&self, sinks: Vec<Arc<SinkStats>>) {
        self.inner.lock().unwrap().sinks = sinks;
    }

    /// Forget repositories that are no longer configured (sender side).
    pub fn retain_repos(&self, names: &[String]) {
        self.inner.lock().unwrap().repos.retain(|k, _| names.contains(k));
    }

    pub fn status(&self) -> Option<Message> {
        self.inner.lock().unwrap().status.as_ref().map(|(m, _)| m.clone())
    }
    pub fn last_end(&self) -> Option<Message> {
        self.inner.lock().unwrap().end.clone()
    }
    pub fn repos(&self) -> Vec<Message> {
        self.inner.lock().unwrap().repos.values().map(|(m, _)| m.clone()).collect()
    }
    pub fn repo(&self, name: &str) -> Option<Message> {
        self.inner.lock().unwrap().repos.get(name).map(|(m, _)| m.clone())
    }
    /// Events with an id greater than `since`, oldest first.
    pub fn events(&self, since: u64) -> Vec<(u64, Message)> {
        self.inner.lock().unwrap().events.iter().filter(|(id, _)| *id > since).cloned().collect()
    }
    pub fn rx(&self) -> RxStats {
        self.inner.lock().unwrap().rx.clone()
    }
    /// Seconds since the last accepted message (receiver).
    pub fn age(&self) -> Option<Duration> {
        self.inner.lock().unwrap().last_rx.map(|t| t.elapsed())
    }
    /// A receiver that has heard nothing for `stale_after` cannot tell what the sender is doing.
    pub fn stale(&self) -> bool {
        match self.stale_after {
            Some(limit) => self.age().unwrap_or_else(|| self.started.elapsed()) > limit,
            None => false,
        }
    }

    /// The `sender` / `receiver` object of `/v1/status`.
    pub fn link_json(&self) -> (&'static str, serde_json::Value) {
        if self.is_receiver() {
            let rx = self.rx();
            (
                "receiver",
                serde_json::json!({
                    "stale": self.stale(),
                    "age_s": self.age().map(|a| a.as_secs()),
                    "stale_after_s": self.stale_after.map(|d| d.as_secs()),
                    "received": rx.received, "accepted": rx.accepted, "duplicates": rx.duplicates,
                    "lost": rx.lost, "bad_mac": rx.bad_mac, "malformed": rx.malformed,
                }),
            )
        } else {
            let s = self.inner.lock().unwrap();
            let sinks: Vec<_> = s
                .sinks
                .iter()
                .map(|k| {
                    serde_json::json!({
                        "url": k.url, "format": k.format,
                        "sent": k.sent.load(Ordering::Relaxed),
                        "dropped": k.dropped.load(Ordering::Relaxed),
                        "errors": k.errors.load(Ordering::Relaxed),
                    })
                })
                .collect();
            ("sender", serde_json::json!({ "sinks": sinks }))
        }
    }

    pub fn sink_stats(&self) -> Vec<Arc<SinkStats>> {
        self.inner.lock().unwrap().sinks.clone()
    }
}

// ---------------------------------------------------------------------------------- hub

/// A message as handed to the sinks.
pub struct Wire {
    pub msg: Message,
    pub json: String,
}

struct SinkHandle {
    tx: mpsc::Sender<Arc<Wire>>,
    stats: Arc<SinkStats>,
}

/// Stamps messages (session, sequence, time, host), records them in the store and offers
/// them to every sink without ever waiting for one.
pub struct Hub {
    pub host: String,
    pub sid: String,
    pub store: Arc<Store>,
    pub interval: Duration,
    pub heartbeat: Duration,
    seq: Mutex<u64>,
    run: Mutex<String>,
    sinks: Vec<SinkHandle>,
    started: Instant,
    stop: CancellationToken,
}

pub fn system_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "unknown".into())
}

fn session_id() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u32(std::process::id());
    h.write_i64(Utc::now().timestamp_nanos_opt().unwrap_or(0));
    format!("{:08x}", h.finish() as u32)
}

impl Hub {
    /// Start one task per configured sink. Must be called inside a tokio runtime.
    pub fn new(cfg: &Status) -> Result<Arc<Hub>> {
        let stop = CancellationToken::new();
        let mut sinks = Vec::new();
        for sc in &cfg.sinks {
            let key = match &sc.hmac_key_file {
                Some(f) => Some(read_key(f)?),
                None => None,
            };
            let stats = Arc::new(SinkStats {
                url: sc.url.clone(),
                format: if sc.format == SinkFormat::Json { "json" } else { "syslog" },
                ..Default::default()
            });
            let (tx, rx) = mpsc::channel(SINK_QUEUE);
            tokio::spawn(crate::sink::run(sink_spec(sc)?, key, rx, stats.clone(), stop.clone()));
            sinks.push(SinkHandle { tx, stats });
        }
        let store = Store::new(None);
        store.set_sinks(sinks.iter().map(|s| s.stats.clone()).collect());
        Ok(Arc::new(Hub {
            host: cfg.host.clone().unwrap_or_else(system_hostname),
            sid: session_id(),
            store,
            interval: Duration::from_millis(cfg.interval_ms),
            heartbeat: Duration::from_secs(cfg.heartbeat_secs),
            seq: Mutex::new(0),
            run: Mutex::new(String::new()),
            sinks,
            started: Instant::now(),
            stop,
        }))
    }

    pub fn has_sinks(&self) -> bool {
        !self.sinks.is_empty()
    }
    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    /// Open a run: messages carry its id until [`Hub::end_run`].
    pub fn begin_run(&self) -> String {
        let id = format!("r{}", Utc::now().format("%Y%m%dT%H%M%SZ"));
        *self.run.lock().unwrap() = id.clone();
        id
    }
    pub fn end_run(&self) {
        self.run.lock().unwrap().clear();
    }

    pub fn emit(&self, body: Body) -> Arc<Wire> {
        // Sequence numbers must reach the queues in order, hence one lock around both.
        let mut seq = self.seq.lock().unwrap();
        *seq += 1;
        let msg = Message {
            v: SCHEMA_VERSION,
            sid: self.sid.clone(),
            run: self.run.lock().unwrap().clone(),
            seq: *seq,
            ts: now_ts(),
            host: self.host.clone(),
            body,
        };
        let json = msg.to_json();
        self.store.apply(&msg, &json);
        let wire = Arc::new(Wire { msg, json });
        self.offer(&wire);
        wire
    }

    /// Send a message again unchanged (same sequence number); receivers drop the copies they
    /// do not need.
    pub fn resend(&self, wire: &Arc<Wire>) {
        let _order = self.seq.lock().unwrap();
        self.offer(wire);
    }

    fn offer(&self, wire: &Arc<Wire>) {
        for s in &self.sinks {
            s.stats.pending.fetch_add(1, Ordering::Relaxed);
            if s.tx.try_send(wire.clone()).is_err() {
                s.stats.pending.fetch_sub(1, Ordering::Relaxed);
                s.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Messages that never left this process.
    pub fn dropped(&self) -> u64 {
        self.sinks.iter().map(|s| s.stats.dropped.load(Ordering::Relaxed)).sum()
    }

    /// Give queued messages a moment to leave, then stop the sink tasks.
    pub async fn close(&self, wait: Duration) {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline && self.sinks.iter().any(|s| s.stats.pending.load(Ordering::Relaxed) > 0) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        self.stop.cancel();
    }
}

fn sink_spec(sc: &Sink) -> Result<crate::sink::Spec> {
    let (tcp, addr) = sc.target()?;
    Ok(crate::sink::Spec {
        tcp,
        addr,
        syslog: sc.format == SinkFormat::Syslog,
        repeat: sc.repeat.max(1),
        facility: sc.facility_code()?,
        progress_every: Duration::from_secs(sc.syslog_progress_secs),
    })
}

// ----------------------------------------------------------------------------- reporter

fn phase_name(p: Phase) -> String {
    p.label().to_ascii_lowercase()
}

pub fn repo_msg(p: &Progress, i: usize) -> RepoMsg {
    let r = &p.repos[i];
    let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
    RepoMsg {
        name: r.name.clone(),
        phase: phase_name(r.phase()),
        files_total: get(&r.files_total),
        files_present: get(&r.files_present),
        files_fetched: get(&r.files_fetched),
        files_failed: get(&r.files_failed),
        bytes_total: get(&r.bytes_total),
        bytes_done: get(&r.bytes_done),
        warnings: get(&r.warnings),
        errors: get(&r.errors),
        ..Default::default()
    }
}

fn classify(level: Level, text: &str) -> &'static str {
    if text.starts_with("suite ") && (text.contains(" published (") || text.ends_with(" is up to date")) {
        "suite_ok"
    } else if text.starts_with("suite ") && level == Level::Error {
        "suite_failed"
    } else {
        "log"
    }
}

/// Most log events sent per tick; a burst beyond this is counted, not sent.
const EVENTS_PER_TICK: usize = 20;
/// Changed repositories sent per tick (the rest follow on the next ticks).
const REPOS_PER_TICK: usize = 8;

/// Turns the engine's [`Progress`] into status messages while a run is in flight.
pub struct Reporter {
    hub: Arc<Hub>,
    progress: Arc<Progress>,
    dry_run: bool,
    last_net: u64,
    last_at: Instant,
    speed: f64,
    sent: Vec<Option<RepoMsg>>,
    cursor: usize,
    log_cursor: u64,
    suppressed: u64,
}

pub struct ReporterHandle {
    /// Id of the run this reporter opened.
    pub run: String,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<Reporter>,
}

impl Reporter {
    /// Open a run on the hub and start emitting every `hub.interval`.
    pub fn spawn(hub: Arc<Hub>, progress: Arc<Progress>, dry_run: bool) -> ReporterHandle {
        let run = hub.begin_run();
        let names: Vec<String> = progress.repos.iter().map(|r| r.name.clone()).collect();
        hub.store.retain_repos(&names);
        let mut rep = Reporter {
            sent: vec![None; progress.repos.len()],
            hub,
            progress,
            dry_run,
            last_net: 0,
            last_at: Instant::now(),
            speed: 0.0,
            cursor: 0,
            log_cursor: 0,
            suppressed: 0,
        };
        let stop = CancellationToken::new();
        let stopped = stop.clone();
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(rep.hub.interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = stopped.cancelled() => break,
                    _ = tick.tick() => rep.tick(),
                }
            }
            rep
        });
        ReporterHandle { run, stop, task }
    }

    fn run_msg(&mut self) -> RunMsg {
        let p = &self.progress;
        let t = p.totals();
        let net = p.net_bytes.load(Ordering::Relaxed);
        let dt = self.last_at.elapsed().as_secs_f64();
        if dt >= 0.2 {
            let inst = net.saturating_sub(self.last_net) as f64 / dt;
            self.speed = if self.speed == 0.0 { inst } else { self.speed * 0.6 + inst * 0.4 };
            self.last_net = net;
            self.last_at = Instant::now();
        }
        let remaining = t.bytes_total.saturating_sub(t.bytes_done);
        let phases: Vec<Phase> = p.repos.iter().map(|r| r.phase()).collect();
        RunMsg {
            state: "running".into(),
            dry_run: self.dry_run,
            elapsed_s: p.started.elapsed().as_secs(),
            files_total: t.files_total,
            files_present: t.files_present,
            files_fetched: t.files_fetched,
            files_failed: t.files_failed,
            bytes_total: t.bytes_total,
            bytes_done: t.bytes_done,
            speed_bps: self.speed as u64,
            eta_s: (self.speed > 1.0 && remaining > 0).then(|| (remaining as f64 / self.speed) as u64),
            warnings: t.warnings,
            errors: t.errors,
            active: p.active.lock().unwrap().len() as u64,
            repos_total: phases.len() as u64,
            repos_done: phases.iter().filter(|p| p.finished()).count() as u64,
            repos_failed: phases.iter().filter(|p| matches!(p, Phase::Failed | Phase::Partial)).count() as u64,
            dropped: self.hub.dropped(),
            events_suppressed: self.suppressed,
        }
    }

    fn events(&mut self) {
        let (lines, cursor) = self.progress.logs_since(self.log_cursor);
        self.log_cursor = cursor;
        let lines: Vec<_> = lines.into_iter().filter(|l| l.level >= Level::Info).collect();
        // In a burst, warnings and errors go first.
        let serious = lines.iter().filter(|l| l.level >= Level::Warn).count();
        let info_budget = EVENTS_PER_TICK.saturating_sub(serious);
        let (mut infos, mut sent) = (0, 0);
        for l in &lines {
            let take = if l.level >= Level::Warn {
                sent < EVENTS_PER_TICK
            } else {
                infos += 1;
                infos <= info_budget
            };
            if !take {
                self.suppressed += 1;
                continue;
            }
            sent += 1;
            self.hub.emit(Body::Event(EventMsg {
                level: match l.level {
                    Level::Error => "error",
                    Level::Warn => "warning",
                    _ => "info",
                }
                .into(),
                kind: classify(l.level, &l.msg).into(),
                repo: l.repo.clone(),
                text: l.msg.clone(),
            }));
        }
    }

    fn repos(&mut self) {
        let n = self.progress.repos.len();
        if n == 0 {
            return;
        }
        let mut budget = REPOS_PER_TICK;
        for i in 0..n {
            if budget == 0 {
                break;
            }
            let m = repo_msg(&self.progress, i);
            if self.sent[i].as_ref() != Some(&m) {
                self.hub.emit(Body::Repo(m.clone()));
                self.sent[i] = Some(m);
                budget -= 1;
            }
        }
        // One unchanged repository per tick as well, so a receiver that lost a message or
        // joined late still converges.
        self.cursor = (self.cursor + 1) % n;
        let m = repo_msg(&self.progress, self.cursor);
        if budget > 0 && self.sent[self.cursor].as_ref() == Some(&m) {
            self.hub.emit(Body::Repo(m));
        }
    }

    fn tick(&mut self) {
        let run = self.run_msg();
        self.hub.emit(Body::Run(run));
        self.repos();
        self.events();
    }
}

impl EndMsg {
    /// The run could not even start (configuration, lock, I/O).
    pub fn from_error(error: &str, p: &Progress) -> EndMsg {
        let t = p.totals();
        EndMsg {
            state: "error".into(),
            exit_code: 2,
            elapsed_s: p.started.elapsed().as_secs(),
            warnings: t.warnings,
            errors: t.errors.max(1),
            error: error.to_string(),
            ..Default::default()
        }
    }

    pub fn from_summary(s: &Summary, p: &Progress) -> EndMsg {
        let t = p.totals();
        let ran: Vec<_> = s.repos.iter().filter(|r| r.ran).collect();
        let bad =
            |r: &&crate::summary::RepoOutcome| !r.suites_failed.is_empty() || !(r.complete || s.dry_run) || r.cancelled;
        let failed: Vec<String> = ran.iter().filter(|r| bad(r)).map(|r| r.name.clone()).collect();
        let (state, exit_code) = if s.cancelled {
            ("cancelled", 130)
        } else if s.success() {
            ("finished", 0)
        } else {
            ("failed", 1)
        };
        EndMsg {
            state: state.into(),
            exit_code,
            dry_run: s.dry_run,
            elapsed_s: s.elapsed.as_secs(),
            repos_ok: (ran.len() - failed.len()) as u64,
            repos_failed: failed.len() as u64,
            repos_skipped: (s.repos.len() - ran.len()) as u64,
            failed,
            files_fetched: ran.iter().map(|r| r.files_fetched).sum(),
            bytes_fetched: ran.iter().map(|r| r.bytes_fetched).sum(),
            files_failed: ran.iter().map(|r| r.files_failed).sum(),
            cleaned_files: s.cleaned_files,
            cleaned_bytes: s.cleaned_bytes,
            warnings: t.warnings,
            errors: t.errors,
            ..Default::default()
        }
    }
}

impl ReporterHandle {
    /// Stop ticking and send the final state: remaining events, every repository once, and the
    /// `end` message three times.
    pub async fn finish(self, result: &Result<Summary, String>) -> EndMsg {
        match result {
            Ok(s) => self.finish_with(Some(s), None).await,
            Err(e) => self.finish_with(None, Some(e.clone())).await,
        }
    }

    /// As [`ReporterHandle::finish`], for callers holding the summary by reference.
    pub async fn finish_with(self, summary: Option<&Summary>, error: Option<String>) -> EndMsg {
        self.stop.cancel();
        let Ok(mut rep) = self.task.await else {
            return EndMsg { state: "error".into(), exit_code: 2, ..Default::default() };
        };
        rep.events();
        for i in 0..rep.progress.repos.len() {
            let mut m = repo_msg(&rep.progress, i);
            if let Some(o) = summary.and_then(|s| s.repos.get(i)).filter(|o| o.ran) {
                m.suites_ok = Some(o.suites_ok.len() as u64);
                m.suites_failed = Some(o.suites_failed.len() as u64);
            }
            rep.sent[i] = Some(m.clone());
            rep.hub.emit(Body::Repo(m));
        }
        let end = match summary {
            Some(s) => EndMsg::from_summary(s, &rep.progress),
            None => EndMsg::from_error(error.as_deref().unwrap_or("the run did not complete"), &rep.progress),
        };
        let wire = rep.hub.emit(Body::End(end.clone()));
        for _ in 0..2 {
            tokio::time::sleep(Duration::from_millis(150)).await;
            rep.hub.resend(&wire);
        }
        rep.hub.end_run();
        end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(body: Body) -> Message {
        Message {
            v: 1,
            sid: "ab12cd34".into(),
            run: "r20261112T031700Z".into(),
            seq: 7,
            ts: "2026-11-12T03:17:05Z".into(),
            host: "mirror01".into(),
            body,
        }
    }

    fn event(text: &str) -> Message {
        msg(Body::Event(EventMsg {
            level: "error".into(),
            kind: "log".into(),
            repo: "debian".into(),
            text: text.into(),
        }))
    }

    #[test]
    fn every_message_fits_one_datagram() {
        let nasty = "\"quoted\" \\ ünïcödé \u{1F40E} \n\t".repeat(400);
        let mut end = EndMsg { state: "failed".into(), error: nasty.clone(), ..Default::default() };
        end.failed = (0..500).map(|i| format!("repository-with-a-long-name-{i}")).collect();
        let big = u64::MAX;
        let run = RunMsg {
            state: "running".into(),
            eta_s: Some(big),
            files_total: big,
            files_present: big,
            files_fetched: big,
            files_failed: big,
            bytes_total: big,
            bytes_done: big,
            speed_bps: big,
            warnings: big,
            errors: big,
            active: big,
            repos_total: big,
            repos_done: big,
            repos_failed: big,
            dropped: big,
            events_suppressed: big,
            elapsed_s: big,
            dry_run: true,
        };
        let repo = RepoMsg {
            name: "n".repeat(5000),
            phase: "downloading".into(),
            suites_ok: Some(big),
            suites_failed: Some(big),
            release_age_s: Some(big),
            files_total: big,
            files_present: big,
            files_fetched: big,
            files_failed: big,
            bytes_total: big,
            bytes_done: big,
            warnings: big,
            errors: big,
        };
        let hb = HeartbeatMsg {
            state: "idle".into(),
            uptime_s: big,
            last_run: Some(LastRun {
                run: "r20261112T031700Z".into(),
                state: "cancelled".into(),
                exit_code: 130,
                finished_at: "2026-11-12T03:40:11Z".into(),
                repos_ok: big,
                repos_failed: big,
            }),
            next_run: Some("2026-11-13T03:17:00+01:00".into()),
            oldest_release_age_s: Some(big),
            repos_total: big,
            dropped: big,
        };
        let key = b"0123456789abcdef0123456789abcdef";
        for body in [
            Body::Event(EventMsg {
                level: "error".into(),
                kind: "log".into(),
                repo: nasty.clone(),
                text: nasty.clone(),
            }),
            Body::End(end),
            Body::Run(run),
            Body::Repo(repo),
            Body::Heartbeat(hb),
        ] {
            let mut m = msg(body);
            m.host = "h".repeat(300);
            m.seq = big;
            let json = m.to_json();
            let signed = sign(&json, key);
            assert!(signed.len() <= MAX_DATAGRAM, "{} is {} bytes", m.body.kind(), signed.len());
            let back: Message = serde_json::from_str(&json).expect("still valid JSON after shortening");
            assert_eq!(back.body.kind(), m.body.kind());
            assert_eq!(verify(&signed, key).as_deref(), Some(json.as_str()));
            if let Some(line) = m.syslog(16, 1) {
                assert!(line.len() <= MAX_DATAGRAM && !line.contains('\n'));
            }
        }
    }

    #[test]
    fn truncation_is_marked() {
        let m = event(&"x".repeat(5000));
        let back: Message = serde_json::from_str(&m.to_json()).unwrap();
        let Body::Event(e) = back.body else { panic!() };
        assert!(e.text.ends_with('…') && e.text.len() <= 700);
        let mut end = EndMsg::default();
        end.failed = (0..200).map(|i| format!("repo-{i}")).collect();
        let back: Message = serde_json::from_str(&msg(Body::End(end)).to_json()).unwrap();
        let Body::End(e) = back.body else { panic!() };
        assert!(e.truncated && !e.failed.is_empty() && e.failed.len() < 200);
    }

    #[test]
    fn json_round_trip_and_unknown_fields() {
        let m = msg(Body::Run(RunMsg { state: "running".into(), bytes_total: 10, ..Default::default() }));
        let json = m.to_json();
        assert!(json.contains("\"type\":\"run\"") && json.contains("\"v\":1"));
        assert_eq!(serde_json::from_str::<Message>(&json).unwrap(), m);
        // A newer sender may add fields; an older receiver must not choke on them.
        let newer = json.replacen('{', "{\"future\":{\"a\":1},", 1);
        assert_eq!(serde_json::from_str::<Message>(&newer).unwrap(), m);
        // Between runs the run id is left out.
        let mut idle = msg(Body::Heartbeat(HeartbeatMsg { state: "idle".into(), ..Default::default() }));
        idle.run.clear();
        assert!(!idle.to_json().contains("\"run\""));
        assert_eq!(serde_json::from_str::<Message>(&idle.to_json()).unwrap(), idle);
    }

    #[test]
    fn syslog_lines_are_rfc5424() {
        let line = event("suite trixie: 3 package file(s) could not be fetched").syslog(16, 2211).unwrap();
        assert_eq!(
            line,
            "<131>1 2026-11-12T03:17:05Z mirror01 cheval 2211 event - [debian] suite trixie: 3 package file(s) could not be fetched"
        );
        let run = msg(Body::Run(RunMsg {
            state: "running".into(),
            bytes_total: 1000,
            bytes_done: 423,
            speed_bps: 2048,
            eta_s: Some(532),
            files_total: 10,
            files_fetched: 3,
            files_present: 1,
            ..Default::default()
        }));
        let line = run.syslog(16, 1).unwrap();
        assert!(line.starts_with("<134>1 2026-11-12T03:17:05Z mirror01 cheval 1 run - sync running 42.3% "), "{line}");
        assert!(line.ends_with("ETA 08:52 files 4/10 failed=0"), "{line}");
        // local7.warning = 23 * 8 + 4
        let mut warn = event("careful");
        if let Body::Event(e) = &mut warn.body {
            e.level = "warning".into();
        }
        assert!(warn.syslog(23, 1).unwrap().starts_with("<188>1 "));
        // Per-repository progress is not logged; control characters never reach the line.
        assert!(msg(Body::Repo(RepoMsg::default())).syslog(16, 1).is_none());
        assert!(!event("a\nb\r\x1b[31m").syslog(16, 1).unwrap().contains(['\n', '\r', '\x1b']));
        let end = msg(Body::End(EndMsg {
            state: "failed".into(),
            elapsed_s: 1386,
            repos_ok: 4,
            repos_failed: 1,
            ..Default::default()
        }));
        let line = end.syslog(16, 1).unwrap();
        assert!(
            line.starts_with("<131>1 ") && line.contains("sync finished WITH ERRORS in 23:06: 4 repos ok, 1 failed")
        );
    }

    #[test]
    fn hmac_matches_rfc4231_and_detects_tampering() {
        // RFC 4231 test case 2.
        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // RFC 4231 test case 6: key longer than the block size.
        assert_eq!(
            hex::encode(hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        let key = b"correct horse battery staple";
        let json = event("hello").to_json();
        let signed = sign(&json, key);
        assert!(serde_json::from_str::<Message>(&signed).is_ok(), "a signed message is still plain JSON");
        assert_eq!(verify(&signed, key), Some(json.clone()));
        assert_eq!(verify(&signed, b"another key entirely"), None);
        assert_eq!(verify(&signed.replace("hello", "jello"), key), None);
        assert_eq!(verify(&json, key), None, "unsigned messages are rejected when a key is set");
    }

    #[test]
    fn receiver_counts_loss_duplicates_and_forgeries() {
        let store = Store::new(Some(Duration::from_secs(60)));
        let send = |seq: u64, sid: &str| {
            let mut m = event("e");
            m.seq = seq;
            m.sid = sid.into();
            store.ingest(m.to_json().as_bytes(), None)
        };
        assert_eq!(send(5, "a"), Ingest::Accepted); // joining mid-stream is not loss
        assert_eq!(send(6, "a"), Ingest::Accepted);
        assert_eq!(send(6, "a"), Ingest::Duplicate); // repeat = 2
        assert_eq!(send(9, "a"), Ingest::Accepted); // 7 and 8 never arrived
        assert_eq!(send(8, "a"), Ingest::Duplicate); // late or replayed
        assert_eq!(send(1, "b"), Ingest::Accepted); // sender restarted
        assert_eq!(store.ingest(b"not json", None), Ingest::Malformed);
        assert_eq!(store.ingest(&[0xff, 0xfe], None), Ingest::Malformed);
        let rx = store.rx();
        assert_eq!((rx.received, rx.accepted, rx.duplicates, rx.lost, rx.malformed), (8, 4, 2, 2, 2));
        assert_eq!(store.events(0).len(), 4);
        assert_eq!(store.events(3).len(), 1);

        let keyed = Store::new(Some(Duration::from_secs(60)));
        let key = b"0123456789abcdef";
        let json = event("e").to_json();
        assert_eq!(keyed.ingest(json.as_bytes(), Some(key)), Ingest::BadMac);
        assert_eq!(keyed.ingest(sign(&json, b"wrong-key-wrong-key").as_bytes(), Some(key)), Ingest::BadMac);
        assert_eq!(keyed.ingest(sign(&json, key).as_bytes(), Some(key)), Ingest::Accepted);
        assert_eq!(keyed.rx().bad_mac, 2);
    }

    #[test]
    fn store_tracks_latest_state_and_staleness() {
        let store = Store::new(Some(Duration::from_millis(40)));
        assert!(!store.stale(), "not stale before the first deadline");
        let run = msg(Body::Run(RunMsg { state: "running".into(), ..Default::default() }));
        store.ingest(run.to_json().as_bytes(), None);
        assert!(!store.stale());
        // An idle daemon's heartbeat does not hide another sender's run in flight.
        let mut hb = msg(Body::Heartbeat(HeartbeatMsg { state: "idle".into(), ..Default::default() }));
        hb.sid = "other".into();
        store.ingest(hb.to_json().as_bytes(), None);
        assert_eq!(store.status().unwrap().body.kind(), "run");
        let mut end = msg(Body::End(EndMsg { state: "finished".into(), ..Default::default() }));
        end.seq = 8;
        store.ingest(end.to_json().as_bytes(), None);
        assert_eq!(store.status().unwrap().body.kind(), "end");
        assert_eq!(store.last_end().unwrap().seq, 8);
        hb.seq = 9;
        store.ingest(hb.to_json().as_bytes(), None);
        assert_eq!(store.status().unwrap().body.kind(), "heartbeat");
        assert_eq!(store.last_end().unwrap().seq, 8, "the last result survives heartbeats");
        std::thread::sleep(Duration::from_millis(60));
        assert!(store.stale());
        assert!(!Store::new(None).stale(), "a sender is never stale");
    }

    #[test]
    fn hostile_input_is_defused_and_bounded() {
        let store = Store::new(Some(Duration::from_secs(60)));
        let evil = r#"{"v":1,"sid":"s","seq":1,"ts":"t","host":"h\u001b[2J","type":"event","level":"info","kind":"log","repo":"r\u0007","text":"\u001b]0;pwned\u0007 hello\r\n"}"#;
        assert_eq!(store.ingest(evil.as_bytes(), None), Ingest::Accepted);
        let (_, m) = store.events(0).pop().unwrap();
        let Body::Event(e) = &m.body else { panic!() };
        assert!(!format!("{}{}{}", m.host, e.repo, e.text).chars().any(|c| c.is_control()));
        assert!(e.text.contains("hello"));
        // Numbers at the limit do not panic anywhere on the way to a screen or a log line.
        let max = u64::MAX;
        let run = format!(
            r#"{{"v":1,"sid":"s","seq":2,"ts":"t","host":"h","type":"run","state":"running","bytes_total":{max},"bytes_done":{max},"files_fetched":{max},"files_present":{max},"eta_s":{max},"elapsed_s":{max},"speed_bps":{max}}}"#
        );
        assert_eq!(store.ingest(run.as_bytes(), None), Ingest::Accepted);
        assert!(store.status().unwrap().human().is_some());
        // A jump to the largest sequence number is counted as loss without overflowing.
        let far = format!(r#"{{"v":1,"sid":"s","seq":{max},"ts":"t","host":"h","type":"repo","name":"a"}}"#);
        assert_eq!(store.ingest(far.as_bytes(), None), Ingest::Accepted);
        assert_eq!(store.ingest(far.as_bytes(), None), Ingest::Duplicate);
        // Repository names cannot grow the store without limit.
        let flood = Store::new(Some(Duration::from_secs(60)));
        for i in 1..=(MAX_REPOS as u64 + 50) {
            let m = format!(r#"{{"v":1,"sid":"f","seq":{i},"ts":"t","host":"h","type":"repo","name":"n{i}"}}"#);
            flood.ingest(m.as_bytes(), None);
        }
        assert_eq!(flood.repos().len(), MAX_REPOS);
        // Wrong types and unknown message types are rejected, not guessed at.
        for bad in [
            r#"{"v":1,"sid":"s","seq":"x","ts":"t","host":"h","type":"run"}"#,
            r#"{"v":1,"sid":"s","seq":9,"ts":"t","host":"h","type":"nope"}"#,
            "[]",
            "{}",
        ] {
            assert_eq!(store.ingest(bad.as_bytes(), None), Ingest::Malformed, "{bad}");
        }
    }

    #[test]
    fn clip_respects_character_boundaries() {
        assert_eq!(clip("short", 10), "short");
        let c = clip("ééééééé", 6);
        assert!(c.len() <= 6 && c.ends_with('…'));
        assert_eq!(clip("abcdefghij", 6), "abc…");
    }
}
