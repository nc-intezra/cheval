//! Terminal user interface (ratatui).
use crate::progress::{Level, Phase, Progress};
use crate::util::{human_bytes, human_duration};
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Gauge, Paragraph, Row, Sparkline, Table};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

struct State {
    speeds: VecDeque<u64>,
    last_bytes: u64,
    last_sample: Instant,
    speed: f64,
    /// Lines scrolled up from the bottom of the log (0 = follow).
    scroll: usize,
    min_level: Level,
    quit_presses: u8,
    final_elapsed: Option<Duration>,
}

/// Run the UI until the engine finished and the user leaves, or the user aborts.
/// `exit_when_done` closes the UI automatically once the run completes.
pub fn run(
    progress: Arc<Progress>,
    cancel: CancellationToken,
    title: &str,
    exit_when_done: bool,
) -> std::io::Result<()> {
    let mut term = ratatui::try_init()?;
    let res = ui_loop(&mut term, &progress, &cancel, title, exit_when_done);
    ratatui::restore();
    res
}

fn ui_loop(
    term: &mut DefaultTerminal,
    progress: &Arc<Progress>,
    cancel: &CancellationToken,
    title: &str,
    exit_when_done: bool,
) -> std::io::Result<()> {
    let mut st = State {
        speeds: VecDeque::from(vec![0; 120]),
        last_bytes: 0,
        last_sample: Instant::now(),
        speed: 0.0,
        scroll: 0,
        min_level: Level::Info,
        quit_presses: 0,
        final_elapsed: None,
    };
    loop {
        let finished = progress.finished.load(Ordering::Relaxed);
        if finished && st.final_elapsed.is_none() {
            st.final_elapsed = Some(progress.started.elapsed());
        }
        if st.last_sample.elapsed() >= Duration::from_millis(500) {
            let now = progress.net_bytes.load(Ordering::Relaxed);
            let dt = st.last_sample.elapsed().as_secs_f64();
            let inst = (now - st.last_bytes) as f64 / dt;
            st.speed = if st.speed == 0.0 { inst } else { st.speed * 0.6 + inst * 0.4 };
            st.speeds.push_back(inst as u64);
            if st.speeds.len() > 240 {
                st.speeds.pop_front();
            }
            st.last_bytes = now;
            st.last_sample = Instant::now();
        }
        term.draw(|f| draw(f, progress, &st, title, finished, cancel.is_cancelled()))?;
        if finished && (exit_when_done || cancel.is_cancelled()) {
            return Ok(());
        }
        if event::poll(Duration::from_millis(100))?
            && let Event::Key(k) = event::read()?
            && k.kind == KeyEventKind::Press
        {
            let ctrl_c = k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL);
            match k.code {
                KeyCode::Char('q') | KeyCode::Esc if finished => return Ok(()),
                KeyCode::Enter if finished => return Ok(()),
                _ if ctrl_c && finished => return Ok(()),
                KeyCode::Char('q') | KeyCode::Esc => {
                    st.quit_presses += 1;
                    if st.quit_presses >= 2 {
                        progress.warn(
                            None,
                            "stop requested — finishing cleanly (indices are not published for interrupted suites)",
                        );
                        cancel.cancel();
                    }
                }
                _ if ctrl_c => {
                    progress.warn(None, "interrupt — stopping");
                    cancel.cancel();
                }
                KeyCode::Up | KeyCode::Char('k') => st.scroll = st.scroll.saturating_add(1),
                KeyCode::Down | KeyCode::Char('j') => st.scroll = st.scroll.saturating_sub(1),
                KeyCode::PageUp => st.scroll = st.scroll.saturating_add(10),
                KeyCode::PageDown => st.scroll = st.scroll.saturating_sub(10),
                KeyCode::End | KeyCode::Char('f') => st.scroll = 0,
                KeyCode::Home => st.scroll = usize::MAX / 2,
                KeyCode::Char('e') => {
                    st.min_level = if st.min_level == Level::Warn { Level::Info } else { Level::Warn };
                    st.scroll = 0;
                }
                KeyCode::Char('v') => {
                    let v = !progress.verbose.load(Ordering::Relaxed);
                    progress.verbose.store(v, Ordering::Relaxed);
                    st.min_level = if v { Level::Debug } else { Level::Info };
                }
                _ => st.quit_presses = 0,
            }
        }
    }
}

fn phase_style(p: Phase) -> Style {
    match p {
        Phase::Done => Style::new().fg(Color::Green),
        Phase::Failed => Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        Phase::Partial | Phase::Cancelled => Style::new().fg(Color::Yellow),
        Phase::Queued | Phase::Skipped => Style::new().fg(Color::DarkGray),
        _ => Style::new().fg(Color::Cyan),
    }
}

fn bar(pct: f64, width: usize) -> String {
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    format!("{}{}", "█".repeat(filled.min(width)), "░".repeat(width - filled.min(width)))
}

fn trunc_left(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        s.to_string()
    } else {
        let tail: String = s.chars().skip(n - max.saturating_sub(1)).collect();
        format!("…{tail}")
    }
}

fn draw(f: &mut ratatui::Frame, p: &Progress, st: &State, title: &str, finished: bool, cancelling: bool) {
    let area = f.area();
    let repo_h = (p.repos.len() as u16 + 3).min(area.height / 3).max(4);
    let active_n = p.active.lock().unwrap().len() as u16;
    let active_h = (active_n + 2).clamp(3, (area.height / 4).max(3));
    let [head, repos, active, logs, foot] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Length(repo_h),
        Constraint::Length(active_h),
        Constraint::Min(4),
        Constraint::Length(1),
    ])
    .areas(area);

    // ---- header ---------------------------------------------------------------------
    let t = p.totals();
    let elapsed = st.final_elapsed.unwrap_or_else(|| p.started.elapsed());
    let pct = if t.bytes_total > 0 {
        (t.bytes_done as f64 * 100.0 / t.bytes_total as f64).min(100.0)
    } else if finished {
        100.0
    } else {
        0.0
    };
    let remaining = t.bytes_total.saturating_sub(t.bytes_done);
    let eta = if finished {
        "done".to_string()
    } else if st.speed > 1.0 && remaining > 0 {
        human_duration((remaining as f64 / st.speed) as u64)
    } else {
        "--:--".to_string()
    };
    let status = if cancelling && !finished {
        Span::styled(" STOPPING ", Style::new().bg(Color::Yellow).fg(Color::Black))
    } else if finished && (t.errors > 0 || t.files_failed > 0) {
        Span::styled(" FINISHED WITH ERRORS ", Style::new().bg(Color::Red).fg(Color::White))
    } else if finished {
        Span::styled(" FINISHED ", Style::new().bg(Color::Green).fg(Color::Black))
    } else {
        Span::styled(" RUNNING ", Style::new().bg(Color::Blue).fg(Color::White))
    };
    let block = Block::bordered().title(Line::from(vec![
        Span::styled(format!(" cheval · {title} "), Style::new().add_modifier(Modifier::BOLD)),
        status,
        Span::raw(format!(" elapsed {} ", human_duration(elapsed.as_secs()))),
    ]));
    let inner = block.inner(head);
    f.render_widget(block, head);
    let [g_area, s_area] = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(inner);
    let [gauge_a, spark_a] = Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)]).areas(g_area);
    f.render_widget(
        Gauge::default()
            .gauge_style(
                Style::new().fg(if t.files_failed > 0 { Color::Yellow } else { Color::Green }).bg(Color::DarkGray),
            )
            .ratio(pct / 100.0)
            .label(format!("{pct:.1}%  {} / {}", human_bytes(t.bytes_done), human_bytes(t.bytes_total))),
        gauge_a,
    );
    let data: Vec<u64> = st.speeds.iter().rev().take(spark_a.width as usize).rev().copied().collect();
    f.render_widget(Sparkline::default().data(&data).style(Style::new().fg(Color::Cyan)), spark_a);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw(format!(
                "↓ {}/s   ETA {}   files {} fetched · {} present · {} total   ",
                human_bytes(if finished { 0 } else { st.speed as u64 }),
                eta,
                t.files_fetched,
                t.files_present,
                t.files_total
            )),
            Span::styled(
                format!("{} failed", t.files_failed),
                if t.files_failed > 0 { Style::new().fg(Color::Red) } else { Style::new() },
            ),
            Span::raw(format!("   {} warnings · {} errors", t.warnings, t.errors)),
        ])),
        s_area,
    );

    // ---- repositories ---------------------------------------------------------------
    let rows: Vec<Row> = p
        .repos
        .iter()
        .map(|r| {
            let phase = r.phase();
            let (bt, bd) = (r.bytes_total.load(Ordering::Relaxed), r.bytes_done.load(Ordering::Relaxed));
            let (ft, fp, ff, fx) = (
                r.files_total.load(Ordering::Relaxed),
                r.files_present.load(Ordering::Relaxed),
                r.files_fetched.load(Ordering::Relaxed),
                r.files_failed.load(Ordering::Relaxed),
            );
            let pct = if bt > 0 {
                (bd as f64 * 100.0 / bt as f64).min(100.0)
            } else if matches!(phase, Phase::Done | Phase::Cleaning | Phase::Publishing) {
                100.0
            } else {
                0.0
            };
            Row::new(vec![
                Cell::from(r.name.clone()),
                Cell::from(phase.label()).style(phase_style(phase)),
                Cell::from(format!("{} {pct:5.1}%", bar(pct, 16))),
                Cell::from(format!("{}/{}", fp + ff, ft)),
                Cell::from(format!("{} / {}", human_bytes(bd), human_bytes(bt))),
                Cell::from(if fx > 0 { format!("{fx} failed") } else { String::new() })
                    .style(Style::new().fg(Color::Red)),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Min(14),
            Constraint::Length(12),
            Constraint::Length(24),
            Constraint::Length(15),
            Constraint::Length(24),
            Constraint::Length(12),
        ],
    )
    .header(
        Row::new(["repository", "phase", "progress", "files", "transferred", ""])
            .style(Style::new().add_modifier(Modifier::DIM)),
    )
    .block(Block::bordered().title(format!(" Repositories ({}) ", p.repos.len())));
    f.render_widget(table, repos);

    // ---- active downloads -------------------------------------------------------------
    let name_w = active.width.saturating_sub(48) as usize;
    let rows: Vec<Row> = {
        let act = p.active.lock().unwrap();
        act.values()
            .take(active.height.saturating_sub(2) as usize)
            .map(|a| {
                let d = a.done.load(Ordering::Relaxed);
                let secs = a.started.elapsed().as_secs_f64().max(0.2);
                let pct = a.size.filter(|s| *s > 0).map(|s| d as f64 * 100.0 / s as f64);
                Row::new(vec![
                    Cell::from(p.repos[a.repo].name.clone()).style(Style::new().fg(Color::DarkGray)),
                    Cell::from(trunc_left(&a.name, name_w.max(10))),
                    Cell::from(match pct {
                        Some(v) => format!("{} {:3.0}%", bar(v.min(100.0), 8), v.min(100.0)),
                        None => "     …".to_string(),
                    }),
                    Cell::from(a.size.map(human_bytes).unwrap_or_default()),
                    Cell::from(format!("{}/s", human_bytes((d as f64 / secs) as u64))),
                ])
            })
            .collect()
    };
    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(14),
                Constraint::Min(10),
                Constraint::Length(13),
                Constraint::Length(10),
                Constraint::Length(12),
            ],
        )
        .block(Block::bordered().title(format!(" Active transfers ({active_n}) "))),
        active,
    );

    // ---- log ---------------------------------------------------------------------------
    draw_log(f, p, st, logs);

    let help = if finished {
        " q/Enter: exit · ↑↓ PgUp PgDn: scroll log · e: warnings only · v: verbose "
    } else if st.quit_presses == 1 {
        " press q again to stop the run "
    } else {
        " q q: stop · ↑↓ PgUp PgDn: scroll log · f: follow · e: warnings only · v: verbose "
    };
    f.render_widget(Paragraph::new(help).style(Style::new().fg(Color::Black).bg(Color::Gray)), foot);
}

fn draw_log(f: &mut ratatui::Frame, p: &Progress, st: &State, area: Rect) {
    let lines = p.logs_snapshot(st.min_level);
    let h = area.height.saturating_sub(2) as usize;
    let max_scroll = lines.len().saturating_sub(h);
    let scroll = st.scroll.min(max_scroll);
    let end = lines.len() - scroll;
    let start = end.saturating_sub(h);
    // Wrap long messages by hand so nothing is cut off and scrolling stays exact.
    let width = area.width.saturating_sub(2).max(20) as usize;
    let mut text: Vec<Line> = Vec::new();
    for l in &lines[start..end] {
        let style = match l.level {
            Level::Error => Style::new().fg(Color::Red),
            Level::Warn => Style::new().fg(Color::Yellow),
            Level::Debug => Style::new().fg(Color::DarkGray),
            Level::Info => Style::new(),
        };
        let mut spans = vec![Span::styled(format!("{} ", &l.time[11..]), Style::new().fg(Color::DarkGray))];
        let mut used = 9;
        if !l.repo.is_empty() {
            used += l.repo.chars().count() + 3;
            spans.push(Span::styled(format!("[{}] ", l.repo), Style::new().fg(Color::Cyan)));
        }
        let chars: Vec<char> = l.msg.chars().collect();
        let first = width.saturating_sub(used).max(10).min(chars.len());
        spans.push(Span::styled(chars[..first].iter().collect::<String>(), style));
        text.push(Line::from(spans));
        for chunk in chars[first..].chunks(width.saturating_sub(9).max(10)) {
            text.push(Line::from(Span::styled(format!("         {}", chunk.iter().collect::<String>()), style)));
        }
    }
    let skip = text.len().saturating_sub(h);
    let text: Vec<Line> = text.into_iter().skip(skip).collect();
    let title = format!(
        " Log{}{} ",
        if st.min_level == Level::Warn { " · warnings+errors" } else { "" },
        if scroll > 0 { format!(" · scrolled {scroll}") } else { String::new() }
    );
    f.render_widget(Paragraph::new(text).block(Block::bordered().title(title)), area);
}
