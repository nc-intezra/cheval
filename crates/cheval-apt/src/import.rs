//! Convert existing apt configuration into a cheval config:
//! one-line `sources.list`, deb822 `.sources`, apt-mirror `mirror.list` and Refrapt configs.
use crate::deb822::Paragraphs;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Default, Clone)]
struct Entry {
    uri: String,
    suites: Vec<String>,
    components: Vec<String>,
    archs: Vec<String>,
    binary: bool,
    source: bool,
    signed_by: Option<String>,
}

#[derive(Debug, Default)]
pub struct Imported {
    entries: Vec<Entry>,
    settings: BTreeMap<String, String>,
    pub notes: Vec<String>,
}

fn push_unique(v: &mut Vec<String>, s: &str) {
    if !s.is_empty() && !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

impl Imported {
    fn add(&mut self, e: Entry) {
        // Flat suites and classic suites of the same URL stay separate entries.
        let flat = e.suites.iter().any(|s| s.ends_with('/'));
        if let Some(x) = self.entries.iter_mut().find(|x| {
            x.uri == e.uri
                && x.components == e.components
                && x.signed_by == e.signed_by
                && x.suites.iter().any(|s| s.ends_with('/')) == flat
        }) {
            for s in &e.suites {
                push_unique(&mut x.suites, s);
            }
            for a in &e.archs {
                push_unique(&mut x.archs, a);
            }
            x.binary |= e.binary;
            x.source |= e.source;
        } else {
            self.entries.push(e);
        }
    }

    fn parse_line(&mut self, line: &str) {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            return;
        }
        let mut rest = line;
        let (kind, r) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        rest = r.trim_start();
        if kind == "set" {
            if let Some((k, v)) = rest.split_once(char::is_whitespace) {
                self.settings.insert(k.to_string(), v.trim().trim_matches('"').to_string());
            }
            return;
        }
        let mut e = Entry::default();
        match kind {
            "deb" => e.binary = true,
            "deb-src" => e.source = true,
            k if k.starts_with("deb-") => {
                e.binary = true;
                e.archs.push(k[4..].to_string());
            }
            _ => return, // clean, skip-clean, mirror_additional_gzipped_lists, ...
        }
        if rest.starts_with('[')
            && let Some(end) = rest.find(']')
        {
            for opt in rest[1..end].split_whitespace() {
                if let Some((k, v)) = opt.split_once('=') {
                    match k.trim_end_matches('+') {
                        "arch" => v.split(',').for_each(|a| push_unique(&mut e.archs, a)),
                        "signed-by" => e.signed_by = Some(v.to_string()),
                        _ => {}
                    }
                }
            }
            rest = rest[end + 1..].trim_start();
        }
        let mut it = rest.split_whitespace();
        let (Some(uri), Some(suite)) = (it.next(), it.next()) else {
            self.notes.push(format!("ignored malformed line: {line}"));
            return;
        };
        e.uri = uri.trim_end_matches('/').to_string();
        e.suites.push(suite.to_string());
        e.components = it.map(str::to_string).collect();
        self.add(e);
    }

    fn parse_deb822(&mut self, text: &str) {
        for para in Paragraphs::new(text.as_bytes()).flatten() {
            if para.get("Enabled").is_some_and(|v| v.eq_ignore_ascii_case("no")) {
                continue;
            }
            let words = |k: &str| -> Vec<String> {
                para.get(k).map(|v| v.split_whitespace().map(str::to_string).collect()).unwrap_or_default()
            };
            let types = words("Types");
            let signed_by = para.get("Signed-By").and_then(|v| {
                if v.contains("BEGIN PGP") {
                    self.notes.push("an inline Signed-By key was found: save it to a file and set `keyring`".into());
                    None
                } else {
                    v.split_whitespace().next().map(str::to_string)
                }
            });
            for uri in words("URIs") {
                self.add(Entry {
                    uri: uri.trim_end_matches('/').to_string(),
                    suites: words("Suites"),
                    components: words("Components"),
                    archs: words("Architectures"),
                    binary: types.iter().any(|t| t == "deb"),
                    source: types.iter().any(|t| t == "deb-src"),
                    signed_by: signed_by.clone(),
                });
            }
        }
    }

    pub fn parse_file(&mut self, path: &Path) -> Result<()> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        self.parse_text(&text, path.extension().and_then(|e| e.to_str()) == Some("sources"));
        Ok(())
    }

    pub fn parse_text(&mut self, text: &str, force_deb822: bool) {
        let looks_822 = force_deb822
            || text.lines().any(|l| {
                let l = l.trim_start();
                l.starts_with("Types:") || l.starts_with("URIs:")
            });
        if looks_822 {
            self.parse_deb822(text);
        } else {
            text.lines().for_each(|l| self.parse_line(l));
        }
    }

    pub fn to_toml(&self, base_path: Option<&str>, default_arch: &str) -> String {
        let q = |s: &str| format!("{:?}", s);
        let list = |v: &[String]| format!("[{}]", v.iter().map(|s| q(s)).collect::<Vec<_>>().join(", "));
        let mut out = String::from("# Generated by `cheval import` — review before use.\n");
        for n in &self.notes {
            out.push_str(&format!("# NOTE: {n}\n"));
        }
        let base = base_path
            .map(str::to_string)
            .or_else(|| self.settings.get("base_path").cloned())
            .or_else(|| self.settings.get("root").cloned())
            .unwrap_or_else(|| "/var/spool/cheval".into());
        out.push_str(&format!("\n[global]\nbase_path = {}\n", q(&base)));
        if let Some(n) =
            self.settings.get("nthreads").or(self.settings.get("threads")).and_then(|v| v.parse::<usize>().ok())
        {
            out.push_str(&format!("threads = {}\n", n.max(1)));
        }
        let arch = self
            .settings
            .get("defaultarch")
            .or(self.settings.get("architecture"))
            .cloned()
            .unwrap_or_else(|| default_arch.to_string());
        out.push_str(&format!("architectures = [{}]\n", q(&arch)));
        let mut names: Vec<String> = Vec::new();
        for e in &self.entries {
            let mut name: String = e
                .uri
                .split("://")
                .last()
                .unwrap_or(&e.uri)
                .rsplit('@')
                .next()
                .unwrap_or("")
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() || c == '.' { c } else { '-' })
                .collect();
            name = name.trim_matches('-').to_string();
            let base_name = name.clone();
            let mut n = 2;
            while names.contains(&name) {
                name = format!("{base_name}-{n}");
                n += 1;
            }
            names.push(name.clone());
            out.push_str(&format!(
                "\n[[repo]]\nname = {}\nurl = {}\nsuites = {}\n",
                q(&name),
                q(&e.uri),
                list(&e.suites)
            ));
            if !e.components.is_empty() {
                out.push_str(&format!("components = {}\n", list(&e.components)));
            }
            if !e.binary {
                out.push_str("architectures = []\n");
            } else if !e.archs.is_empty() {
                out.push_str(&format!("architectures = {}\n", list(&e.archs)));
            }
            if e.source {
                out.push_str("source = true\n");
            }
            match &e.signed_by {
                Some(k) => out.push_str(&format!("keyring = {}\n", q(k))),
                None => out.push_str(
                    "# keyring = \"/usr/share/keyrings/<archive>-keyring.gpg\"   # enables signature verification\n",
                ),
            }
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_line_and_mirror_list() {
        let mut i = Imported::default();
        i.parse_text(
            "set base_path /srv/m\nset nthreads 20\ndeb [arch=amd64,arm64 signed-by=/k.gpg] http://deb.debian.org/debian bookworm main contrib\ndeb [arch=amd64,arm64 signed-by=/k.gpg] http://deb.debian.org/debian bookworm-updates main contrib # c\ndeb-src [signed-by=/k.gpg] http://deb.debian.org/debian bookworm main contrib\ndeb-i386 http://x.example/ubuntu noble main\nclean http://deb.debian.org/debian\ndeb https://nvidia.example/repo /\n",
            false,
        );
        let t = i.to_toml(None, "amd64");
        let cfg: toml::Value = toml::from_str(&t).unwrap();
        let repos = cfg["repo"].as_array().unwrap();
        assert_eq!(repos.len(), 3);
        assert_eq!(repos[0]["suites"].as_array().unwrap().len(), 2);
        assert_eq!(repos[0]["source"].as_bool(), Some(true));
        assert_eq!(repos[1]["architectures"][0].as_str(), Some("i386"));
        assert_eq!(repos[2]["suites"][0].as_str(), Some("/"));
        assert_eq!(cfg["global"]["threads"].as_integer(), Some(20));
    }
    #[test]
    fn deb822() {
        let mut i = Imported::default();
        i.parse_text("Types: deb deb-src\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: noble noble-updates\nComponents: main universe\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n", false);
        let t = i.to_toml(Some("/data"), "amd64");
        assert!(t.contains("suites = [\"noble\", \"noble-updates\"]"));
        assert!(t.contains("keyring = \"/usr/share/keyrings/ubuntu-archive-keyring.gpg\""));
        toml::from_str::<toml::Value>(&t).unwrap();
    }
}
