//! `cheval status listen`: the receiving end of the status stream, for the far side of a
//! data diode. It needs no mirror configuration: everything it knows arrives in the stream.
use crate::config::parse_stream_url;
use crate::logo::{self, Charset};
use crate::status::{Body, Ingest, Message, Store};
use crate::util::{human_bytes, human_duration};
use anyhow::{Context, Result, bail};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;

pub struct Options {
    /// `udp://ADDR:PORT` (datagrams) or `tcp://ADDR:PORT` (NDJSON from a diode's TCP proxy).
    pub listen: String,
    pub http: Option<SocketAddr>,
    pub token: Option<String>,
    /// `udp://host:port` targets that get a copy of every accepted message.
    pub forward: Vec<String>,
    pub hmac_key: Option<Vec<u8>>,
    pub stale_after: Duration,
    /// Print events and periodic status lines to stderr (headless mode).
    pub print: bool,
}

/// Sockets bound and ready; created up front so configuration errors surface before any UI.
pub struct Listener {
    pub store: Arc<Store>,
    /// Where the status stream is received (useful when port 0 was requested).
    pub local: SocketAddr,
    pub http_local: Option<SocketAddr>,
    input: Input,
    http: Option<(TcpListener, Option<String>)>,
    forward: Vec<(UdpSocket, String)>,
    key: Option<Vec<u8>>,
    print: bool,
}

enum Input {
    Udp(UdpSocket),
    Tcp(TcpListener),
}

/// Longest NDJSON line accepted over TCP; anything longer is not a cheval message.
const MAX_LINE: usize = 4096;

pub async fn bind(o: Options) -> Result<Listener> {
    let (tcp, addr) = parse_stream_url(&o.listen)?;
    let (input, local) = if tcp {
        let l = TcpListener::bind(&addr).await.with_context(|| format!("cannot listen on {}", o.listen))?;
        let a = l.local_addr()?;
        (Input::Tcp(l), a)
    } else {
        let s = UdpSocket::bind(&addr).await.with_context(|| format!("cannot listen on {}", o.listen))?;
        let a = s.local_addr()?;
        (Input::Udp(s), a)
    };
    let mut forward = Vec::new();
    for f in &o.forward {
        let (tcp, target) = parse_stream_url(f)?;
        if tcp {
            bail!("--forward {f}: only udp:// targets are supported");
        }
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        forward.push((sock, target));
    }
    let (http, http_local) = match o.http {
        Some(addr) => {
            if !addr.ip().is_loopback() && o.token.is_none() {
                bail!("--http {addr} is not a loopback address: add --token-file");
            }
            let l = TcpListener::bind(addr).await.with_context(|| format!("cannot serve HTTP on {addr}"))?;
            let a = l.local_addr()?;
            (Some((l, o.token)), Some(a))
        }
        None => (None, None),
    };
    Ok(Listener {
        store: Store::new(Some(o.stale_after)),
        local,
        http_local,
        input,
        http,
        forward,
        key: o.hmac_key,
        print: o.print,
    })
}

struct Printer {
    on: bool,
    last_status: Option<std::time::Instant>,
}

impl Printer {
    fn line(&mut self, raw: &str) {
        if !self.on {
            return;
        }
        let Ok(m) = serde_json::from_str::<Message>(raw) else { return };
        // Progress and heartbeats every 30 s at most; events and results always.
        if matches!(m.body, Body::Run(_) | Body::Heartbeat(_)) {
            if self.last_status.is_some_and(|t| t.elapsed() < Duration::from_secs(30)) {
                return;
            }
            self.last_status = Some(std::time::Instant::now());
        }
        if let Some((_, _, text)) = m.human() {
            eprintln!("{} {} {}", m.ts, m.host, text);
        }
    }
}

impl Listener {
    async fn take(&self, raw: &[u8], printer: &mut Printer) {
        if self.store.ingest(raw, self.key.as_deref()) != Ingest::Accepted {
            return;
        }
        // Forward exactly what arrived (signature included), and only what passed the checks.
        for (sock, target) in &self.forward {
            let _ = sock.send_to(raw, target.as_str()).await;
        }
        if let Ok(text) = std::str::from_utf8(raw) {
            printer.line(text.trim());
        }
    }

    /// Receive until `stop` is cancelled.
    pub async fn run(mut self, stop: CancellationToken) {
        if let Some((l, token)) = self.http.take() {
            tokio::spawn(crate::api::serve(l, self.store.clone(), token, stop.clone()));
        }
        let mut printer = Printer { on: self.print, last_status: None };
        let mut was_stale = false;
        let mut check = tokio::time::interval(Duration::from_secs(1));
        match &self.input {
            Input::Udp(sock) => {
                let mut buf = vec![0u8; 65_536];
                loop {
                    tokio::select! {
                        _ = stop.cancelled() => return,
                        _ = check.tick() => self.note_stale(&mut was_stale),
                        r = sock.recv_from(&mut buf) => if let Ok((n, _)) = r {
                            self.take(&buf[..n], &mut printer).await;
                        },
                    }
                }
            }
            Input::Tcp(listener) => {
                // One upstream at a time: a diode proxy holds a single connection.
                loop {
                    let conn = tokio::select! {
                        _ = stop.cancelled() => return,
                        _ = check.tick() => { self.note_stale(&mut was_stale); continue }
                        c = listener.accept() => c,
                    };
                    let Ok((sock, _)) = conn else { continue };
                    let mut lines = BufReader::new(sock);
                    let mut line = Vec::new();
                    loop {
                        // `line` keeps a partly read line across timer ticks.
                        let read = tokio::select! {
                            _ = stop.cancelled() => return,
                            _ = check.tick() => { self.note_stale(&mut was_stale); continue }
                            r = read_line(&mut lines, &mut line) => r,
                        };
                        match read {
                            Ok(true) => {
                                self.take(&line, &mut printer).await;
                                line.clear();
                            }
                            _ => break,
                        }
                    }
                }
            }
        }
    }

    fn note_stale(&self, was: &mut bool) {
        let stale = self.store.stale();
        if self.print && stale != *was {
            let age = self.store.age().map(|a| human_duration(a.as_secs())).unwrap_or_else(|| "ever".into());
            if stale {
                eprintln!("cheval status: STALE - nothing received for {age}; the sender or the link may be down");
            } else {
                eprintln!("cheval status: receiving again");
            }
        }
        *was = stale;
    }
}

/// Read one `\n`-terminated line of at most [`MAX_LINE`] bytes. `Ok(false)` at end of stream.
async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R, out: &mut Vec<u8>) -> std::io::Result<bool> {
    loop {
        let chunk = r.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(false);
        }
        let (take, done) = match chunk.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        out.extend_from_slice(&chunk[..take]);
        r.consume(take);
        if out.len() > MAX_LINE {
            return Err(std::io::Error::other("line too long"));
        }
        if done {
            return Ok(true);
        }
    }
}

// ----------------------------------------------------------------------------------- TUI

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Gauge, Paragraph, Row, Table};

/// Read-only progress screen fed from the store. Returns when the user quits.
pub fn tui(store: Arc<Store>, source: &str, cs: Charset) -> std::io::Result<()> {
    let mut term = ratatui::try_init()?;
    let compact = logo::compact(cs);
    let res = (|| {
        loop {
            term.draw(|f| draw(f, &store, source, compact.as_deref()))?;
            if event::poll(Duration::from_millis(250))?
                && let Event::Key(k) = event::read()?
                && k.kind == KeyEventKind::Press
            {
                let ctrl_c = k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL);
                if ctrl_c || matches!(k.code, KeyCode::Char('q') | KeyCode::Esc) {
                    return Ok(());
                }
            }
        }
    })();
    ratatui::restore();
    res
}

fn bar(pct: f64, width: usize) -> String {
    let filled = (((pct / 100.0) * width as f64).round() as usize).min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

fn phase_style(p: &str) -> Style {
    match p {
        "done" => Style::new().fg(Color::Green),
        "failed" => Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        "partial" | "cancelled" => Style::new().fg(Color::Yellow),
        "queued" | "skipped" | "unknown" => Style::new().fg(Color::DarkGray),
        _ => Style::new().fg(Color::Cyan),
    }
}

pub(crate) fn draw(f: &mut ratatui::Frame, store: &Store, source: &str, compact: Option<&[String]>) {
    let area = f.area();
    let logo_rows = match compact {
        Some(c) if area.height >= 26 + c.len() as u16 && area.width as usize >= logo::width(&c[0]) => c.len() as u16,
        _ => 0,
    };
    let repos = store.repos();
    let repo_h = (repos.len() as u16 + 3).min(area.height / 3).max(4);
    let [logo_a, head, repo_a, log_a, foot] = Layout::vertical([
        Constraint::Length(logo_rows),
        Constraint::Length(5),
        Constraint::Length(repo_h),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(area);
    if logo_rows > 0
        && let Some(c) = compact
    {
        let fill = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);
        f.render_widget(Paragraph::new(c.iter().map(|l| Line::styled(l.clone(), fill)).collect::<Vec<_>>()), logo_a);
    }

    // ---- header: what the sender last said, and how much that can be trusted -------------
    let status = store.status();
    let stale = store.stale();
    let rx = store.rx();
    let age = store.age();
    let badge = |text: &str, bg: Color, fg: Color| Span::styled(format!(" {text} "), Style::new().bg(bg).fg(fg));
    let state = match status.as_ref().map(|m| &m.body) {
        _ if stale => badge("STALE - NO SIGNAL", Color::Red, Color::White),
        None => badge("WAITING", Color::DarkGray, Color::White),
        Some(Body::Run(_)) => badge("RUNNING", Color::Blue, Color::White),
        Some(Body::Heartbeat(_)) => badge("IDLE", Color::Green, Color::Black),
        Some(Body::End(e)) if e.exit_code == 0 => badge("FINISHED", Color::Green, Color::Black),
        Some(Body::End(e)) if e.state == "cancelled" => badge("CANCELLED", Color::Yellow, Color::Black),
        Some(Body::End(_)) => badge("FINISHED WITH ERRORS", Color::Red, Color::White),
        Some(_) => badge("?", Color::DarkGray, Color::White),
    };
    let host = status.as_ref().map(|m| m.host.clone()).unwrap_or_else(|| "no sender yet".into());
    let block = Block::bordered().title(Line::from(vec![
        Span::styled(format!(" cheval status · {host} "), Style::new().add_modifier(Modifier::BOLD)),
        state,
        Span::raw(format!(" via {source} ")),
    ]));
    let inner = block.inner(head);
    f.render_widget(block, head);
    let [g_a, l1, l2] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1), Constraint::Length(1)]).areas(inner);
    let (pct, label, line) = match status.as_ref().map(|m| &m.body) {
        Some(Body::Run(r)) => {
            let pct =
                if r.bytes_total > 0 { (r.bytes_done as f64 * 100.0 / r.bytes_total as f64).min(100.0) } else { 0.0 };
            (
                pct,
                format!("{pct:.1}%  {} / {}", human_bytes(r.bytes_done), human_bytes(r.bytes_total)),
                format!(
                    "↓ {}/s   ETA {}   elapsed {}   files {} fetched · {} present · {} total   {} failed   {} warnings · {} errors",
                    human_bytes(r.speed_bps),
                    r.eta_s.map(human_duration).unwrap_or_else(|| "--:--".into()),
                    human_duration(r.elapsed_s),
                    r.files_fetched,
                    r.files_present,
                    r.files_total,
                    r.files_failed,
                    r.warnings,
                    r.errors
                ),
            )
        }
        Some(Body::End(e)) => (
            100.0,
            e.state.clone(),
            format!(
                "took {}   {} repos ok · {} failed   fetched {} in {} files   {} files failed",
                human_duration(e.elapsed_s),
                e.repos_ok,
                e.repos_failed,
                human_bytes(e.bytes_fetched),
                e.files_fetched,
                e.files_failed
            ),
        ),
        Some(Body::Heartbeat(h)) => {
            let last = match &h.last_run {
                Some(l) => {
                    format!("last run {} {} ({} ok, {} failed)", l.finished_at, l.state, l.repos_ok, l.repos_failed)
                }
                None => "no run yet".into(),
            };
            let next = h.next_run.as_ref().map(|n| format!("   next run {n}")).unwrap_or_default();
            let rel = h.oldest_release_age_s.map(|a| format!("   oldest Release {}", human_age(a))).unwrap_or_default();
            (0.0, "idle".into(), format!("{last}{next}{rel}"))
        }
        _ => (0.0, "no data".into(), "waiting for the first status message".into()),
    };
    f.render_widget(
        Gauge::default()
            .gauge_style(Style::new().fg(if stale { Color::DarkGray } else { Color::Green }).bg(Color::DarkGray))
            .ratio(pct / 100.0)
            .label(label),
        g_a,
    );
    f.render_widget(Paragraph::new(line), l1);
    let link = Line::from(vec![
        Span::styled(
            match age {
                Some(a) => format!("last message {} ago", human_duration(a.as_secs())),
                None => "nothing received yet".into(),
            },
            if stale { Style::new().fg(Color::Red).add_modifier(Modifier::BOLD) } else { Style::new() },
        ),
        Span::raw(format!("   received {}   ", rx.accepted)),
        Span::styled(
            format!("lost {}", rx.lost),
            if rx.lost > 0 { Style::new().fg(Color::Yellow) } else { Style::new() },
        ),
        Span::raw(format!("   repeats {}   ", rx.duplicates)),
        Span::styled(
            format!("rejected {}", rx.bad_mac + rx.malformed),
            if rx.bad_mac + rx.malformed > 0 { Style::new().fg(Color::Red) } else { Style::new() },
        ),
    ]);
    f.render_widget(Paragraph::new(link), l2);

    // ---- repositories ---------------------------------------------------------------------
    let rows: Vec<Row> = repos
        .iter()
        .filter_map(|m| match &m.body {
            Body::Repo(r) => Some(r),
            _ => None,
        })
        .map(|r| {
            let pct = if r.bytes_total > 0 {
                (r.bytes_done as f64 * 100.0 / r.bytes_total as f64).min(100.0)
            } else if r.phase == "done" {
                100.0
            } else {
                0.0
            };
            Row::new(vec![
                Cell::from(r.name.clone()),
                Cell::from(r.phase.clone()).style(phase_style(&r.phase)),
                Cell::from(format!("{} {pct:5.1}%", bar(pct, 16))),
                Cell::from(format!("{}/{}", r.files_present.saturating_add(r.files_fetched), r.files_total)),
                Cell::from(format!("{} / {}", human_bytes(r.bytes_done), human_bytes(r.bytes_total))),
                Cell::from(r.release_age_s.map(human_age).unwrap_or_default()),
                Cell::from(if r.files_failed > 0 { format!("{} failed", r.files_failed) } else { String::new() })
                    .style(Style::new().fg(Color::Red)),
            ])
        })
        .collect();
    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Min(14),
                Constraint::Length(12),
                Constraint::Length(24),
                Constraint::Length(13),
                Constraint::Length(24),
                Constraint::Length(10),
                Constraint::Length(12),
            ],
        )
        .header(
            Row::new(["repository", "phase", "progress", "files", "transferred", "Release", ""])
                .style(Style::new().add_modifier(Modifier::DIM)),
        )
        .block(Block::bordered().title(format!(" Repositories ({}) ", repos.len()))),
        repo_a,
    );

    // ---- events ---------------------------------------------------------------------------
    let events = store.events(0);
    let h = log_a.height.saturating_sub(2) as usize;
    let width = log_a.width.saturating_sub(2) as usize;
    let lines: Vec<Line> = events
        .iter()
        .rev()
        .take(h)
        .rev()
        .filter_map(|(_, m)| match &m.body {
            Body::Event(e) => Some((m, e)),
            _ => None,
        })
        .map(|(m, e)| {
            let style = match e.level.as_str() {
                "error" => Style::new().fg(Color::Red),
                "warning" => Style::new().fg(Color::Yellow),
                _ => Style::new(),
            };
            let time = m.ts.get(11..19).unwrap_or("");
            let mut spans = vec![Span::styled(format!("{time} "), Style::new().fg(Color::DarkGray))];
            let mut used = 9;
            if !e.repo.is_empty() {
                used += e.repo.chars().count() + 3;
                spans.push(Span::styled(format!("[{}] ", e.repo), Style::new().fg(Color::Cyan)));
            }
            let text: String = e.text.chars().take(width.saturating_sub(used)).collect();
            spans.push(Span::styled(text, style));
            Line::from(spans)
        })
        .collect();
    f.render_widget(Paragraph::new(lines).block(Block::bordered().title(" Events (sender time, UTC) ")), log_a);

    let bar_style = Style::new().fg(Color::Black).bg(Color::Gray);
    let help = " q: quit · read-only view of the sending side ";
    let ver = format!(" cheval {} ", logo::VERSION);
    if foot.width as usize >= logo::width(help) + logo::width(&ver) {
        let [a, b] = Layout::horizontal([Constraint::Min(0), Constraint::Length(logo::width(&ver) as u16)]).areas(foot);
        f.render_widget(Paragraph::new(help).style(bar_style), a);
        f.render_widget(Paragraph::new(ver).style(bar_style.add_modifier(Modifier::BOLD)), b);
    } else {
        f.render_widget(Paragraph::new(help).style(bar_style), foot);
    }
}

/// "3h 12m", "2d 4h": ages of Release files, where seconds do not matter.
pub fn human_age(secs: u64) -> String {
    match secs {
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h {}m", s / 3600, s % 3600 / 60),
        s => format!("{}d {}h", s / 86_400, s % 86_400 / 3600),
    }
}
