//! Send-only status sinks: UDP datagrams (preferred across a diode) and write-only TCP.
//!
//! A sink never reads from its socket and never makes the caller wait. Whatever cannot be
//! delivered right now is dropped and counted; the next snapshot repairs it.
use crate::status::{Body, SinkStats, Wire, sign};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub struct Spec {
    pub tcp: bool,
    /// "host:port"
    pub addr: String,
    pub syslog: bool,
    pub repeat: u8,
    pub facility: u8,
    pub progress_every: Duration,
}

const RESOLVE_EVERY: Duration = Duration::from_secs(60);
const TCP_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_BACKOFF_MAX: Duration = Duration::from_secs(30);

struct Encoder {
    syslog: bool,
    facility: u8,
    key: Option<Vec<u8>>,
    progress_every: Duration,
    last_progress: Option<Instant>,
    last_seq: u64,
    pid: u32,
}

impl Encoder {
    /// The bytes to put on the wire, or `None` when this sink skips the message.
    fn encode(&mut self, w: &Wire) -> Option<String> {
        if !self.syslog {
            return Some(match &self.key {
                Some(k) => sign(&w.json, k),
                None => w.json.clone(),
            });
        }
        // Repeats exist for lossy datagram paths; in a log they would only be duplicate lines.
        if w.msg.seq <= self.last_seq {
            return None;
        }
        self.last_seq = w.msg.seq;
        if let Body::Run(_) = w.msg.body {
            // A log server wants a progress line now and then, not every two seconds.
            if self.last_progress.is_some_and(|t| t.elapsed() < self.progress_every) {
                return None;
            }
            self.last_progress = Some(Instant::now());
        }
        w.msg.syslog(self.facility, self.pid)
    }
}

pub async fn run(
    spec: Spec,
    key: Option<Vec<u8>>,
    mut rx: mpsc::Receiver<Arc<Wire>>,
    stats: Arc<SinkStats>,
    stop: CancellationToken,
) {
    let mut enc = Encoder {
        syslog: spec.syslog,
        facility: spec.facility,
        key,
        progress_every: spec.progress_every,
        last_progress: None,
        last_seq: 0,
        pid: std::process::id(),
    };
    let mut udp = Udp { addr: spec.addr.clone(), target: None, resolved: None, socket: None };
    let mut tcp = Tcp { addr: spec.addr.clone(), stream: None, retry_at: None, backoff: Duration::from_secs(1) };
    loop {
        let wire = tokio::select! {
            _ = stop.cancelled() => break,
            w = rx.recv() => match w { Some(w) => w, None => break },
        };
        match enc.encode(&wire) {
            None => {}
            Some(text) => {
                let ok = if spec.tcp {
                    // NDJSON for JSON; RFC 6587 octet counting for syslog.
                    let framed = if spec.syslog { format!("{} {text}", text.len()) } else { format!("{text}\n") };
                    tcp.send(framed.as_bytes()).await
                } else {
                    let mut ok = true;
                    for _ in 0..spec.repeat {
                        ok &= udp.send(text.as_bytes()).await;
                    }
                    ok
                };
                if ok {
                    stats.sent.fetch_add(1, Ordering::Relaxed);
                } else {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        stats.pending.fetch_sub(1, Ordering::Relaxed);
    }
}

struct Udp {
    addr: String,
    target: Option<SocketAddr>,
    resolved: Option<Instant>,
    socket: Option<UdpSocket>,
}

impl Udp {
    async fn send(&mut self, data: &[u8]) -> bool {
        // Re-resolve now and then so a changed DNS record is picked up without a restart.
        // A name that does not resolve is retried every few seconds, not once per message.
        let every = if self.target.is_none() { Duration::from_secs(5) } else { RESOLVE_EVERY };
        if self.resolved.is_none_or(|t| t.elapsed() > every) {
            self.resolved = Some(Instant::now());
            if let Ok(Ok(mut addrs)) = tokio::time::timeout(TCP_TIMEOUT, tokio::net::lookup_host(&self.addr)).await
                && let Some(a) = addrs.next()
                && self.target != Some(a)
            {
                self.target = Some(a);
                self.socket = None;
            }
        }
        let Some(target) = self.target else { return false };
        if self.socket.is_none() {
            let bind = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            self.socket = UdpSocket::bind(bind).await.ok();
        }
        let Some(sock) = &self.socket else { return false };
        // Unconnected on purpose: nothing is ever read, and ICMP errors from a dead peer
        // are not reported back to us.
        match sock.send_to(data, target).await {
            Ok(n) => n == data.len(),
            Err(_) => {
                self.socket = None;
                false
            }
        }
    }
}

struct Tcp {
    addr: String,
    stream: Option<TcpStream>,
    retry_at: Option<Instant>,
    backoff: Duration,
}

impl Tcp {
    async fn send(&mut self, data: &[u8]) -> bool {
        if self.stream.is_none() {
            if self.retry_at.is_some_and(|t| Instant::now() < t) {
                return false; // link is down: drop instead of queueing behind a dead peer
            }
            match tokio::time::timeout(TCP_TIMEOUT, TcpStream::connect(&self.addr)).await {
                Ok(Ok(s)) => {
                    let _ = s.set_nodelay(true);
                    self.stream = Some(s);
                    self.backoff = Duration::from_secs(1);
                    self.retry_at = None;
                }
                _ => {
                    self.retry_at = Some(Instant::now() + self.backoff);
                    self.backoff = (self.backoff * 2).min(TCP_BACKOFF_MAX);
                    return false;
                }
            }
        }
        let s = self.stream.as_mut().expect("connected above");
        match tokio::time::timeout(TCP_TIMEOUT, s.write_all(data)).await {
            Ok(Ok(())) => true,
            _ => {
                self.stream = None;
                self.retry_at = Some(Instant::now() + self.backoff);
                false
            }
        }
    }
}
