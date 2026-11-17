//! Read-only HTTP API over the status [`Store`]. Served by `cheval daemon` on the sending
//! side and by `cheval status listen` on the receiving side; the endpoints are the same.
//!
//! Deliberately tiny: GET and HEAD only, one request per connection, no request bodies.
use crate::status::{Body, Message, Store, constant_time_eq, now_ts};
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

const MAX_REQUEST: usize = 8192;
const MAX_CONNECTIONS: usize = 64;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

pub enum Reply {
    Json(u16, Value),
    Text(u16, &'static str, String),
    /// Live NDJSON until the client goes away.
    Stream,
}

fn not_found(what: &str) -> Reply {
    Reply::Json(404, json!({ "error": what }))
}

fn msg_json(m: &Message) -> Value {
    serde_json::to_value(m).unwrap_or(Value::Null)
}

/// Answer one request path (with optional query string).
pub fn route(store: &Store, target: &str) -> Reply {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let path = if path.len() > 1 { path.trim_end_matches('/') } else { path };
    match path {
        "/" => Reply::Json(
            200,
            json!({
                "service": "cheval", "version": env!("CARGO_PKG_VERSION"),
                "role": if store.is_receiver() { "receiver" } else { "sender" },
                "endpoints": ["/v1/status", "/v1/repos", "/v1/repos/{name}", "/v1/events?since=ID", "/v1/stream", "/healthz", "/metrics"],
            }),
        ),
        "/healthz" => Reply::Text(200, "text/plain; charset=utf-8", "ok\n".into()),
        "/v1/status" => {
            let (role, link) = store.link_json();
            let mut v = json!({
                "now": now_ts(),
                "version": env!("CARGO_PKG_VERSION"),
                "role": role,
                "status": store.status().as_ref().map(msg_json),
                "last_end": store.last_end().as_ref().map(msg_json),
            });
            v[role] = link;
            Reply::Json(200, v)
        }
        "/v1/repos" => Reply::Json(200, json!({ "repos": store.repos().iter().map(msg_json).collect::<Vec<_>>() })),
        "/v1/events" => {
            let since =
                query.split('&').find_map(|kv| kv.strip_prefix("since=")).map(|v| v.parse::<u64>()).unwrap_or(Ok(0));
            let Ok(since) = since else {
                return Reply::Json(400, json!({ "error": "since must be a number" }));
            };
            let events = store.events(since);
            let next = events.last().map(|(id, _)| *id).unwrap_or(since);
            let list: Vec<Value> = events
                .iter()
                .map(|(id, m)| {
                    let mut v = msg_json(m);
                    v["id"] = json!(id);
                    v
                })
                .collect();
            Reply::Json(200, json!({ "events": list, "next": next }))
        }
        "/v1/stream" => Reply::Stream,
        "/metrics" => Reply::Text(200, "text/plain; version=0.0.4; charset=utf-8", metrics(store)),
        p => match p.strip_prefix("/v1/repos/") {
            Some(name) => match store.repo(name) {
                Some(m) => Reply::Json(200, msg_json(&m)),
                None => not_found("no such repository"),
            },
            None => not_found("no such endpoint"),
        },
    }
}

fn label(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', " ")
}

/// Prometheus text exposition of the current state.
pub fn metrics(store: &Store) -> String {
    let mut o = String::new();
    let mut gauge = |name: &str, help: &str, value: String| {
        let _ = writeln!(o, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}");
    };
    gauge("cheval_up", "1 while the process serving this endpoint runs.", "1".into());
    let status = store.status();
    let running = matches!(status.as_ref().map(|m| &m.body), Some(Body::Run(_)));
    gauge("cheval_run_active", "1 while a mirror run is in flight.", (running as u8).to_string());
    if let Some(Body::Run(r)) = status.as_ref().map(|m| &m.body) {
        gauge("cheval_run_bytes_total", "Bytes the run in flight has to transfer.", r.bytes_total.to_string());
        gauge("cheval_run_bytes_done", "Bytes the run in flight has transferred.", r.bytes_done.to_string());
        gauge("cheval_run_files_total", "Files the run in flight needs.", r.files_total.to_string());
        gauge("cheval_run_files_failed", "Files that could not be fetched so far.", r.files_failed.to_string());
        gauge("cheval_run_speed_bytes_per_second", "Current download speed.", r.speed_bps.to_string());
    }
    if let Some(Body::Heartbeat(h)) = status.as_ref().map(|m| &m.body)
        && let Some(age) = h.oldest_release_age_s
    {
        gauge("cheval_oldest_release_age_seconds", "Age of the oldest published Release file.", age.to_string());
    }
    if let Some(end) = store.last_end()
        && let Body::End(e) = &end.body
    {
        gauge(
            "cheval_last_run_success",
            "1 when the last run finished without errors.",
            ((e.exit_code == 0) as u8).to_string(),
        );
        gauge("cheval_last_run_exit_code", "Exit code of the last run.", e.exit_code.to_string());
        gauge("cheval_last_run_repos_failed", "Repositories that failed in the last run.", e.repos_failed.to_string());
        gauge("cheval_last_run_bytes_fetched", "Bytes fetched by the last run.", e.bytes_fetched.to_string());
        gauge("cheval_last_run_duration_seconds", "Duration of the last run.", e.elapsed_s.to_string());
        if let Ok(t) = chrono::DateTime::parse_from_rfc3339(&end.ts) {
            gauge("cheval_last_run_finished_timestamp_seconds", "When the last run ended.", t.timestamp().to_string());
        }
    }
    let repos = store.repos();
    if !repos.is_empty() {
        for (name, help, get) in [
            (
                "cheval_repo_bytes_done",
                "Bytes transferred for the repository.",
                (|r| r.bytes_done) as fn(&crate::status::RepoMsg) -> u64,
            ),
            ("cheval_repo_bytes_total", "Bytes the repository needs.", |r| r.bytes_total),
            ("cheval_repo_files_failed", "Files that could not be fetched.", |r| r.files_failed),
            ("cheval_repo_failed", "1 when the repository failed or is partial.", |r| {
                matches!(r.phase.as_str(), "failed" | "partial") as u64
            }),
        ] {
            let _ = writeln!(o, "# HELP {name} {help}\n# TYPE {name} gauge");
            for m in &repos {
                if let Body::Repo(r) = &m.body {
                    let _ = writeln!(o, "{name}{{repo=\"{}\"}} {}", label(&r.name), get(r));
                }
            }
        }
    }
    if store.is_receiver() {
        let rx = store.rx();
        let _ = writeln!(
            o,
            "# HELP cheval_status_stale 1 when nothing arrived from the sender for too long.\n# TYPE cheval_status_stale gauge\ncheval_status_stale {}",
            store.stale() as u8
        );
        if let Some(age) = store.age() {
            let _ = writeln!(
                o,
                "# HELP cheval_status_age_seconds Seconds since the last accepted status message.\n# TYPE cheval_status_age_seconds gauge\ncheval_status_age_seconds {}",
                age.as_secs()
            );
        }
        for (name, help, v) in [
            ("cheval_status_received_total", "Status messages received.", rx.received),
            ("cheval_status_lost_total", "Status messages known to be lost (sequence gaps).", rx.lost),
            ("cheval_status_duplicates_total", "Repeated or replayed status messages ignored.", rx.duplicates),
            ("cheval_status_bad_mac_total", "Status messages rejected by the HMAC check.", rx.bad_mac),
            ("cheval_status_malformed_total", "Status messages that could not be parsed.", rx.malformed),
        ] {
            let _ = writeln!(o, "# HELP {name} {help}\n# TYPE {name} counter\n{name} {v}");
        }
    } else {
        let sinks = store.sink_stats();
        if !sinks.is_empty() {
            for (name, help, get) in [
                (
                    "cheval_sink_sent_total",
                    "Status messages written to the sink.",
                    (|s| s.sent.load(Ordering::Relaxed)) as fn(&crate::status::SinkStats) -> u64,
                ),
                ("cheval_sink_dropped_total", "Status messages dropped (queue full or link down).", |s| {
                    s.dropped.load(Ordering::Relaxed)
                }),
            ] {
                let _ = writeln!(o, "# HELP {name} {help}\n# TYPE {name} counter");
                for s in &sinks {
                    let _ = writeln!(o, "{name}{{sink=\"{}\",format=\"{}\"}} {}", label(&s.url), s.format, get(s));
                }
            }
        }
    }
    o
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    }
}

fn head(code: u16, ctype: &str, len: Option<usize>, extra: &str) -> String {
    let len = len.map(|n| format!("Content-Length: {n}\r\n")).unwrap_or_default();
    format!(
        "HTTP/1.1 {code} {}\r\nContent-Type: {ctype}\r\n{len}Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n{extra}\r\n",
        reason(code)
    )
}

async fn handle(mut sock: TcpStream, store: Arc<Store>, token: Option<Arc<str>>, stop: CancellationToken) {
    let mut buf = Vec::with_capacity(1024);
    let read = async {
        let mut chunk = [0u8; 1024];
        loop {
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                return true;
            }
            if buf.len() > MAX_REQUEST {
                return false;
            }
            match sock.read(&mut chunk).await {
                Ok(0) | Err(_) => return false,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    };
    let complete = matches!(tokio::time::timeout(IO_TIMEOUT, read).await, Ok(true));
    let send = |sock: TcpStream, code: u16, body: Value, extra: &'static str| async move {
        let mut sock = sock;
        let body = format!("{body}\n");
        let out = format!("{}{body}", head(code, "application/json", Some(body.len()), extra));
        let _ = tokio::time::timeout(IO_TIMEOUT, sock.write_all(out.as_bytes())).await;
        let _ = sock.shutdown().await;
    };
    if !complete {
        if buf.len() > MAX_REQUEST {
            send(sock, 431, json!({ "error": "request too large" }), "").await;
        }
        return;
    }
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let (method, target) = (first.next().unwrap_or(""), first.next().unwrap_or(""));
    if method != "GET" && method != "HEAD" {
        return send(sock, 405, json!({ "error": "read-only API: GET and HEAD only" }), "Allow: GET, HEAD\r\n").await;
    }
    if !target.starts_with('/') {
        return send(sock, 400, json!({ "error": "bad request" }), "").await;
    }
    // /healthz stays open so a local supervisor can probe without the token.
    if let Some(want) = &token
        && target != "/healthz"
    {
        let got = lines
            .take_while(|l| !l.is_empty())
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .and_then(|(_, v)| v.trim().strip_prefix("Bearer ").map(str::trim));
        if !got.is_some_and(|g| constant_time_eq(g.as_bytes(), want.as_bytes())) {
            return send(
                sock,
                401,
                json!({ "error": "missing or wrong bearer token" }),
                "WWW-Authenticate: Bearer\r\n",
            )
            .await;
        }
    }
    let head_only = method == "HEAD";
    match route(&store, target) {
        Reply::Json(code, v) => {
            let body = format!("{v}\n");
            let mut out = head(code, "application/json", Some(body.len()), "");
            if !head_only {
                out.push_str(&body);
            }
            let _ = tokio::time::timeout(IO_TIMEOUT, sock.write_all(out.as_bytes())).await;
        }
        Reply::Text(code, ctype, body) => {
            let mut out = head(code, ctype, Some(body.len()), "");
            if !head_only {
                out.push_str(&body);
            }
            let _ = tokio::time::timeout(IO_TIMEOUT, sock.write_all(out.as_bytes())).await;
        }
        Reply::Stream => {
            let mut rx = store.stream.subscribe();
            if sock.write_all(head(200, "application/x-ndjson", None, "").as_bytes()).await.is_err() || head_only {
                return;
            }
            loop {
                let line = tokio::select! {
                    _ = stop.cancelled() => break,
                    m = rx.recv() => match m {
                        Ok(l) => l,
                        // A slow client skips messages; the next snapshot catches it up.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => break,
                    },
                };
                let out = format!("{line}\n");
                if !matches!(tokio::time::timeout(IO_TIMEOUT, sock.write_all(out.as_bytes())).await, Ok(Ok(()))) {
                    break;
                }
            }
        }
    }
    let _ = sock.shutdown().await;
}

/// Serve until `stop` is cancelled.
pub async fn serve(listener: TcpListener, store: Arc<Store>, token: Option<String>, stop: CancellationToken) {
    let token: Option<Arc<str>> = token.map(Arc::from);
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let sock = tokio::select! {
            _ = stop.cancelled() => return,
            a = listener.accept() => match a {
                Ok((s, _)) => s,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        // Over the limit: close at once instead of queueing strangers.
        let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
        let (store, token, stop) = (store.clone(), token.clone(), stop.clone());
        tokio::spawn(async move {
            handle(sock, store, token, stop).await;
            drop(permit);
        });
    }
}
