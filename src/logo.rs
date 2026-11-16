//! The cheval logo, rendered for the terminal.
//!
//! One mark, three renderings:
//!
//! * [`banner`] — extruded block letters in a double-line frame (README, TUI header)
//! * [`compact`] — a four-row half-block stencil (TUI title bar)
//! * [`about`] — the stencil framed with the name spelled out (`cheval version`)
//!
//! When the terminal cannot be trusted with Unicode, [`Charset::Ascii`] swaps in a
//! 7-bit ASCII banner of the same size, so layouts never change.
use clap::ValueEnum;

/// What the user asked for (`--logo`, `CHEVAL_LOGO`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum LogoMode {
    /// Unicode when the locale is UTF-8, ASCII otherwise
    Auto,
    Unicode,
    Ascii,
    /// No logo anywhere
    Off,
}

/// What is actually drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charset {
    Unicode,
    Ascii,
    Off,
}

pub const TAGLINE: &str = "apt mirroring, done right";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Extruded block letters, 48 columns.
const BLOCK: [&str; 8] = [
    "         ██╗                                 ██╗",
    "         ██║                                 ██║",
    " ██████╗ ██████╗   ██████╗ ██╗   ██╗ █████╗  ██║",
    "██╔════╝ ██╔══██╗ ██╔═══██╗██║   ██║██╔══██╗ ██║",
    "██║      ██║  ██║ ████████║██║   ██║███████║ ██║",
    "██║      ██║  ██║ ██╔═════╝╚██╗ ██╔╝██╔══██║ ██║",
    "╚██████╗ ██║  ██║ ╚███████╗ ╚████╔╝ ██║  ██║ ██║",
    " ╚═════╝ ╚═╝  ╚═╝  ╚══════╝  ╚═══╝  ╚═╝  ╚═╝ ╚═╝",
];

/// The same lettering in 7-bit ASCII.
const ASCII: [&str; 8] = [
    "         ##+                                 ##+",
    "         ##|                                 ##|",
    " ######+ ######+   ######+ ##+   ##+ #####+  ##|",
    "##+====+ ##+==##+ ##+===##+##|   ##|##+==##+ ##|",
    "##|      ##|  ##| ########|##|   ##|#######| ##|",
    "##|      ##|  ##| ##+=====++##+ ##++##+==##| ##|",
    "+######+ ##|  ##| +#######+ +####++ ##|  ##| ##|",
    " +=====+ +=+  +=+  +======+  +===+  +=+  +=+ +=+",
];

/// Half-block stencil, 64 columns by 4 rows.
const STENCIL: [&str; 4] = [
    "            ██                                              ▀▀██",
    "▄▄▀▀▀▀▀▀▄▄  ██▀▀▀▀▀▀▄▄  ▄▄▀▀▀▀▀▀▄▄  ██      ██    ▀▀▀▀▀▀▄▄    ██",
    "██      ▄▄  ██      ██  ██▀▀▀▀▀▀▀▀  ▀▀▄▄  ▄▄▀▀  ▄▄▀▀▀▀▀▀██    ██",
    "  ▀▀▀▀▀▀    ▀▀      ▀▀    ▀▀▀▀▀▀        ▀▀        ▀▀▀▀▀▀▀▀    ▀▀",
];

#[derive(Clone, Copy)]
struct Frame {
    tl: char,
    tr: char,
    bl: char,
    br: char,
    h: char,
    v: char,
}

const DOUBLE: Frame = Frame { tl: '╔', tr: '╗', bl: '╚', br: '╝', h: '═', v: '║' };
const ROUNDED: Frame = Frame { tl: '╭', tr: '╮', bl: '╰', br: '╯', h: '─', v: '│' };
const PLAIN: Frame = Frame { tl: '+', tr: '+', bl: '+', br: '+', h: '-', v: '|' };

/// Number of terminal columns of `s` (every character used here is one column wide).
pub fn width(s: &str) -> usize {
    s.chars().count()
}

fn center(s: &str, w: usize) -> String {
    let pad = w.saturating_sub(width(s));
    format!("{}{}{}", " ".repeat(pad / 2), s, " ".repeat(pad - pad / 2))
}

fn framed(lines: &[String], f: Frame, pad: usize) -> Vec<String> {
    let inner = lines.iter().map(|l| width(l)).max().unwrap_or(0) + pad * 2;
    let rule = f.h.to_string().repeat(inner);
    let mut out = Vec::with_capacity(lines.len() + 2);
    out.push(format!("{}{}{}", f.tl, rule, f.tr));
    for l in lines {
        let fill = " ".repeat(inner - pad - width(l));
        out.push(format!("{}{}{}{}{}", f.v, " ".repeat(pad), l, fill, f.v));
    }
    out.push(format!("{}{}{}", f.bl, rule, f.br));
    out
}

fn owned(rows: &[&str]) -> Vec<String> {
    rows.iter().map(|r| r.to_string()).collect()
}

/// Logo 1: the extruded block lettering in a double frame (ASCII frame and lettering as fallback).
pub fn banner(cs: Charset) -> Vec<String> {
    let (rows, frame) = match cs {
        Charset::Unicode => (&BLOCK, DOUBLE),
        Charset::Ascii => (&ASCII, PLAIN),
        Charset::Off => return Vec::new(),
    };
    let mut lines = vec![String::new()];
    lines.extend(owned(rows));
    lines.push(String::new());
    framed(&lines, frame, 3)
}

/// Logo 3 without its frame: four rows, for a title bar. There is no ASCII equivalent.
pub fn compact(cs: Charset) -> Option<Vec<String>> {
    (cs == Charset::Unicode).then(|| owned(&STENCIL))
}

/// Logo 3 as shown by `cheval version`: the stencil, framed, with the name spelled out.
/// The ASCII fallback is the ASCII banner.
pub fn about(cs: Charset) -> Vec<String> {
    match cs {
        Charset::Unicode => {
            let w = width(STENCIL[0]);
            let mut lines = vec![String::new()];
            lines.extend(owned(&STENCIL));
            lines.push(String::new());
            lines.push(center("c h e v a l", w));
            lines.push(String::new());
            framed(&lines, ROUNDED, 3)
        }
        Charset::Ascii => banner(Charset::Ascii),
        Charset::Off => Vec::new(),
    }
}

/// Decide what to draw from `--logo` (if given), then `CHEVAL_LOGO`, then the locale.
pub fn resolve(flag: Option<LogoMode>) -> Charset {
    resolve_with(flag, |k| std::env::var(k).ok())
}

pub fn resolve_with(flag: Option<LogoMode>, env: impl Fn(&str) -> Option<String>) -> Charset {
    let mode = flag
        .or_else(|| env("CHEVAL_LOGO").and_then(|v| LogoMode::from_str(v.trim(), true).ok()))
        .unwrap_or(LogoMode::Auto);
    match mode {
        LogoMode::Unicode => Charset::Unicode,
        LogoMode::Ascii => Charset::Ascii,
        LogoMode::Off => Charset::Off,
        LogoMode::Auto => {
            if unicode_terminal(&env) {
                Charset::Unicode
            } else {
                Charset::Ascii
            }
        }
    }
}

/// UTF-8 locale and not a dumb terminal. An unset or `C`/`POSIX` locale counts as "not Unicode":
/// the ASCII banner is the safe answer over a serial console or a bare `ssh` session.
fn unicode_terminal(env: &impl Fn(&str) -> Option<String>) -> bool {
    if env("TERM").as_deref() == Some("dumb") {
        return false;
    }
    let locale = ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .filter_map(|k| env(k))
        .find(|v| !v.is_empty())
        .unwrap_or_default()
        .to_ascii_lowercase();
    locale.contains("utf-8") || locale.contains("utf8")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    }

    fn all_renderings() -> Vec<(&'static str, Vec<String>)> {
        vec![
            ("banner", banner(Charset::Unicode)),
            ("banner-ascii", banner(Charset::Ascii)),
            ("compact", compact(Charset::Unicode).unwrap()),
            ("about", about(Charset::Unicode)),
            ("about-ascii", about(Charset::Ascii)),
        ]
    }

    #[test]
    fn every_rendering_fits_80_columns_and_is_rectangular() {
        for (name, lines) in all_renderings() {
            let w = width(&lines[0]);
            assert!(w < 80, "{name} is {w} columns wide");
            assert!(lines.iter().all(|l| width(l) == w), "{name} is ragged");
        }
    }

    #[test]
    fn ascii_fallback_is_pure_ascii_and_the_same_size() {
        let (u, a) = (banner(Charset::Unicode), banner(Charset::Ascii));
        assert!(a.iter().all(|l| l.is_ascii()));
        assert!(u.iter().any(|l| !l.is_ascii()));
        assert_eq!((u.len(), width(&u[0])), (a.len(), width(&a[0])));
        assert_eq!(about(Charset::Ascii), a);
    }

    #[test]
    fn man_page_names_the_current_version_and_every_command() {
        let man = include_str!("../man/cheval.1");
        assert!(man.contains(&format!("\"cheval {VERSION}\"")), "man/cheval.1: update the version in .TH");
        for cmd in [
            "sync",
            "daemon",
            "verify",
            "check",
            "example",
            "probe",
            "import",
            "sources",
            "snapshot create",
            "bundle create",
            "bundle apply",
            "ingest",
            "status listen",
            "version",
        ] {
            assert!(man.contains(&format!(".B {cmd}")) || man.contains(&format!(".BR {cmd}")), "man page lacks {cmd}");
        }
    }

    #[test]
    fn off_draws_nothing() {
        assert!(banner(Charset::Off).is_empty());
        assert!(about(Charset::Off).is_empty());
        assert!(compact(Charset::Off).is_none());
        assert!(compact(Charset::Ascii).is_none());
    }

    #[test]
    fn automatic_choice_follows_the_locale() {
        let auto = |p: &[(&str, &str)]| resolve_with(None, env(p));
        assert_eq!(auto(&[("LANG", "en_US.UTF-8")]), Charset::Unicode);
        assert_eq!(auto(&[("LANG", "de_DE.utf8")]), Charset::Unicode);
        assert_eq!(auto(&[("LANG", "C")]), Charset::Ascii);
        assert_eq!(auto(&[]), Charset::Ascii);
        // LC_ALL beats LANG, and an empty value is skipped.
        assert_eq!(auto(&[("LC_ALL", "C"), ("LANG", "en_US.UTF-8")]), Charset::Ascii);
        assert_eq!(auto(&[("LC_ALL", ""), ("LANG", "en_US.UTF-8")]), Charset::Unicode);
        assert_eq!(auto(&[("TERM", "dumb"), ("LANG", "en_US.UTF-8")]), Charset::Ascii);
    }

    #[test]
    fn flag_beats_environment_beats_locale() {
        let utf8 = [("LANG", "en_US.UTF-8")];
        assert_eq!(resolve_with(Some(LogoMode::Ascii), env(&utf8)), Charset::Ascii);
        assert_eq!(resolve_with(None, env(&[("LANG", "C"), ("CHEVAL_LOGO", "unicode")])), Charset::Unicode);
        assert_eq!(resolve_with(None, env(&[("CHEVAL_LOGO", "OFF")])), Charset::Off);
        assert_eq!(resolve_with(Some(LogoMode::Unicode), env(&[("CHEVAL_LOGO", "off")])), Charset::Unicode);
        // Unknown values fall back to automatic detection instead of failing.
        assert_eq!(resolve_with(None, env(&[("CHEVAL_LOGO", "fancy"), ("LANG", "C")])), Charset::Ascii);
    }
}
