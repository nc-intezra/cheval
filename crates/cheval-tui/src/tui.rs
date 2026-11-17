//! Terminal user interface (ratatui).
use crate::logo::{self, Charset};
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
    /// Logo 1 (header) and logo 3 (title bar) in the chosen character set.
    banner: Vec<String>,
    compact: Option<Vec<String>>,
}

/// Rows the rest of the screen needs before a logo may take any.
const BODY_MIN_ROWS: u16 = 22;

#[derive(Debug, PartialEq, Eq)]
enum Header {
    Full,
    Compact,
    None,
}

/// Pick the biggest logo that still leaves room for the progress screen.
/// `banner` and `compact` are (rows, columns) of the available renderings.
fn choose_header(rows: u16, cols: u16, banner: (u16, u16), compact: Option<(u16, u16)>) -> Header {
    if banner.0 > 0 && rows >= banner.0 + BODY_MIN_ROWS && cols >= banner.1 {
        Header::Full
    } else if let Some((h, w)) = compact
        && rows >= h + BODY_MIN_ROWS
        && cols >= w
    {
        Header::Compact
    } else {
        Header::None
    }
}

fn logo_size(lines: &[String]) -> (u16, u16) {
    (lines.len() as u16, lines.first().map_or(0, |l| logo::width(l)) as u16)
}

/// Colour a logo: fill characters bright, extrusion and frame dim.
fn logo_lines(lines: &[String]) -> Vec<Line<'static>> {
    let fill = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);
    let dim = Style::new().fg(Color::DarkGray);
    lines
        .iter()
        .map(|l| {
            let mut spans: Vec<Span> = Vec::new();
            let mut run = String::new();
            let mut cur = Style::new();
            for c in l.chars() {
                // Blanks continue whatever run they are in, so lines are not split into many spans.
                let st = match c {
                    '█' | '▀' | '▄' | '#' => fill,
                    ' ' => cur,
                    _ => dim,
                };
                if st != cur && !run.is_empty() {
                    spans.push(Span::styled(std::mem::take(&mut run), cur));
                }
                cur = st;
                run.push(c);
            }
            if !run.is_empty() {
                spans.push(Span::styled(run, cur));
            }
            Line::from(spans)
        })
        .collect()
}

/// Run the UI until the engine finished and the user leaves, or the user aborts.
/// `exit_when_done` closes the UI automatically once the run completes.
pub fn run(
    progress: Arc<Progress>,
    cancel: CancellationToken,
    title: &str,
    exit_when_done: bool,
    logo: Charset,
) -> std::io::Result<()> {
    let mut term = ratatui::try_init()?;
    let res = ui_loop(&mut term, &progress, &cancel, title, exit_when_done, logo);
    ratatui::restore();
    res
}

fn ui_loop(
    term: &mut DefaultTerminal,
    progress: &Arc<Progress>,
    cancel: &CancellationToken,
    title: &str,
    exit_when_done: bool,
    logo: Charset,
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
        banner: logo::banner(logo),
        compact: logo::compact(logo),
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
    let kind = choose_header(area.height, area.width, logo_size(&st.banner), st.compact.as_deref().map(logo_size));
    let logo_rows = match kind {
        Header::Full => st.banner.len() as u16,
        Header::Compact => st.compact.as_ref().map_or(0, |c| c.len() as u16),
        Header::None => 0,
    };
    let [logo_a, area] = Layout::vertical([Constraint::Length(logo_rows), Constraint::Min(0)]).areas(area);
    match kind {
        Header::Full => draw_logo(f, logo_a, &st.banner, 3, title),
        Header::Compact => draw_logo(f, logo_a, st.compact.as_deref().unwrap_or_default(), 1, title),
        Header::None => {}
    }
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
    let bar_style = Style::new().fg(Color::Black).bg(Color::Gray);
    // Version notifier: right-aligned in the footer whenever it fits beside the key help.
    let ver = format!(" cheval {} ", logo::VERSION);
    if foot.width as usize >= logo::width(help) + logo::width(&ver) {
        let [help_a, ver_a] =
            Layout::horizontal([Constraint::Min(0), Constraint::Length(logo::width(&ver) as u16)]).areas(foot);
        f.render_widget(Paragraph::new(help).style(bar_style), help_a);
        f.render_widget(Paragraph::new(ver).style(bar_style.add_modifier(Modifier::BOLD)), ver_a);
    } else {
        f.render_widget(Paragraph::new(help).style(bar_style), foot);
    }
}

/// Draw a logo at the left of `area`, with the version and run title beside it when there is room.
fn draw_logo(f: &mut ratatui::Frame, area: Rect, lines: &[String], info_row: u16, title: &str) {
    let (_, w) = logo_size(lines);
    f.render_widget(Paragraph::new(logo_lines(lines)), Rect { width: w.min(area.width), ..area });
    const INFO_W: u16 = 26;
    if area.width >= w + 2 + INFO_W {
        let info = Rect {
            x: area.x + w + 2,
            y: area.y + info_row.min(area.height.saturating_sub(3)),
            width: area.width - w - 2,
            height: 3.min(area.height),
        };
        f.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    format!("cheval {}", logo::VERSION),
                    Style::new().add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::raw(title.to_string())),
                Line::from(Span::styled(logo::TAGLINE, Style::new().add_modifier(Modifier::DIM))),
            ]),
            info,
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_follows_the_terminal_size() {
        let full = (12, 56);
        let compact = Some((4, 64));
        // Big terminal: the framed block logo.
        assert_eq!(choose_header(50, 120, full, compact), Header::Full);
        assert_eq!(choose_header(34, 56, full, compact), Header::Full);
        // Not tall enough for the block logo, but the title bar fits.
        assert_eq!(choose_header(33, 120, full, compact), Header::Compact);
        assert_eq!(choose_header(26, 64, full, compact), Header::Compact);
        // The classic 80x24 terminal keeps the whole screen for progress.
        assert_eq!(choose_header(24, 80, full, compact), Header::None);
        // Too narrow for the block logo falls through to the next size, then to nothing.
        assert_eq!(choose_header(50, 55, full, compact), Header::None);
        // ASCII fallback has no title bar; logo off has neither.
        assert_eq!(choose_header(30, 120, full, None), Header::None);
        assert_eq!(choose_header(50, 120, (0, 0), None), Header::None);
    }

    #[test]
    fn logo_colouring_keeps_every_character() {
        for cs in [Charset::Unicode, Charset::Ascii] {
            let lines = logo::banner(cs);
            let styled = logo_lines(&lines);
            for (plain, line) in lines.iter().zip(&styled) {
                let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
                assert_eq!(&text, plain);
            }
        }
    }

    fn state(cs: Charset) -> State {
        State {
            speeds: VecDeque::from(vec![0; 120]),
            last_bytes: 0,
            last_sample: Instant::now(),
            speed: 0.0,
            scroll: 0,
            min_level: Level::Info,
            quit_presses: 0,
            final_elapsed: None,
            banner: logo::banner(cs),
            compact: logo::compact(cs),
        }
    }

    fn render(cols: u16, rows: u16, cs: Charset) -> String {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let p = Progress::new(&["ubuntu".to_string(), "debian".to_string()]);
        let st = state(cs);
        let mut term = Terminal::new(TestBackend::new(cols, rows)).unwrap();
        term.draw(|f| draw(f, &p, &st, "/srv/cheval -> /srv/cheval/mirror", false, false)).unwrap();
        let buf = term.backend().buffer().clone();
        (0..rows)
            .map(|y| (0..cols).map(|x| buf[(x, y)].symbol().to_string()).collect::<String>().trim_end().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn screens_at_three_sizes() {
        let big = render(120, 50, Charset::Unicode);
        println!("{big}\n");
        assert!(big.contains("██╗"), "block logo missing");
        assert!(
            big.contains(&format!("cheval {}", logo::VERSION)) && big.contains("apt mirroring"),
            "info column missing"
        );
        assert!(big.lines().last().unwrap().contains(&format!("cheval {}", logo::VERSION)), "footer version missing");

        let mid = render(110, 30, Charset::Unicode);
        println!("{mid}\n");
        assert!(mid.contains("▀▀") && !mid.contains("██╗"), "title bar expected");

        let small = render(80, 24, Charset::Unicode);
        println!("{small}\n");
        assert!(!small.contains("▀▀") && !small.contains("██╗"), "no logo expected at 80x24");
        assert!(small.contains("Repositories"));

        let ascii = render(120, 50, Charset::Ascii);
        println!("{ascii}\n");
        assert!(ascii.contains("##+") && !ascii.contains("██╗"));
    }
}
