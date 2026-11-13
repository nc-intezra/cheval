//! Decide which index files of a suite to mirror, and extract pool files from them.
use crate::config::Filters;
use crate::deb822::Paragraphs;
use crate::release::{FileEntry, Release};
use crate::util::{Checksum, HashAlgo, open_decoded, safe_rel_path, split_compression};
use anyhow::{Context, Result};
use regex::Regex;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexKind {
    Packages,
    Sources,
    Other,
}

pub struct Selection<'a> {
    pub components: &'a [String],
    pub architectures: &'a [String],
    pub source: bool,
    pub installer: bool,
    pub pdiffs: bool,
    pub languages: Option<&'a [String]>,
    pub flat: bool,
}

fn arch_re() -> &'static [Regex] {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        [
            r"(?:^|/)(?:binary|installer)-([a-z0-9][a-z0-9-]*)(?:/|$)",
            r"(?:^|/)Contents-(?:udeb-)?([a-z0-9][a-z0-9-]*?)(?:\.[a-z0-9]+)?(?:\.diff/.*)?$",
            r"(?:^|/)Components-([a-z0-9][a-z0-9-]*?)\.yml",
            r"(?:^|/)Commands-([a-z0-9][a-z0-9-]*?)(?:\.[a-z0-9]+)?$",
        ]
        .iter()
        .map(|p| Regex::new(p).unwrap())
        .collect()
    })
}

/// Architecture a Release path belongs to, if any.
pub fn path_arch(path: &str) -> Option<&str> {
    arch_re().iter().find_map(|r| r.captures(path).and_then(|c| c.get(1)).map(|m| m.as_str()))
}

pub fn index_kind(path: &str) -> IndexKind {
    let (stem, _) = split_compression(path);
    match stem.rsplit('/').next().unwrap_or(stem) {
        "Packages" => IndexKind::Packages,
        "Sources" => IndexKind::Sources,
        _ => IndexKind::Other,
    }
}

/// Component a path belongs to: the longest known component that prefixes it.
fn path_component<'a>(path: &str, known: &'a [String]) -> Option<&'a str> {
    known
        .iter()
        .filter(|c| path.len() > c.len() && path.starts_with(c.as_str()) && path.as_bytes()[c.len()] == b'/')
        .max_by_key(|c| c.len())
        .map(|c| c.as_str())
}

/// Select the Release entries worth mirroring. Everything listed is taken unless it
/// belongs to an unselected component/architecture or an optional class that is
/// switched off — so i18n, dep11 (AppStream), cnf, Contents and friends come along.
pub fn select<'r>(release: &'r Release, sel: &Selection, filters: &Filters) -> Vec<(&'r str, &'r FileEntry)> {
    // Known components: what Release declares (also by basename, for layouts like
    // `updates/main`) plus what the user asked for.
    let mut known: Vec<String> = Vec::new();
    for c in release.components.iter().chain(sel.components.iter()) {
        known.push(c.clone());
        if let Some(b) = c.rsplit('/').next() {
            known.push(b.to_string());
        }
    }
    // Releases without a Components field: infer components from the index paths so
    // that unselected ones are still recognised (and skipped).
    static COMP: OnceLock<Regex> = OnceLock::new();
    let comp_re = COMP.get_or_init(|| {
        Regex::new(
            r"^(.+?)/(?:binary-[^/]+|source|i18n|dep11|cnf|debian-installer|installer-[^/]+|Contents-[^/]+)(?:/|$)",
        )
        .unwrap()
    });
    if !sel.flat {
        for path in release.files.keys() {
            if let Some(c) = comp_re.captures(path) {
                known.push(c[1].to_string());
            }
        }
    }
    known.sort();
    known.dedup();
    let wanted_comp = |c: &str| {
        sel.components
            .iter()
            .any(|w| w == c || w.rsplit('/').next() == Some(c) || c.rsplit('/').next() == Some(w.as_str()))
    };
    let mut out = Vec::new();
    for (path, entry) in &release.files {
        let p = path.as_str();
        if safe_rel_path(p).is_err() || filters.path_excluded(p) {
            continue;
        }
        if !sel.flat
            && let Some(c) = path_component(p, &known)
            && !wanted_comp(c)
        {
            continue;
        }
        if let Some(a) = path_arch(p) {
            let ok = a == "all" || (a == "source" && sel.source) || sel.architectures.iter().any(|w| w == a);
            if !ok {
                continue;
            }
        }
        let segs: Vec<&str> = p.split('/').collect();
        if !sel.source && (segs.contains(&"source") || index_kind(p) == IndexKind::Sources) {
            continue;
        }
        if !sel.installer && segs.iter().any(|s| *s == "debian-installer" || s.starts_with("installer-")) {
            continue;
        }
        if !sel.installer && p.contains("Contents-udeb") {
            continue;
        }
        if !sel.pdiffs && segs.iter().any(|s| s.ends_with(".diff")) {
            continue;
        }
        if let Some(langs) = sel.languages
            && let Some(file) = segs.last()
            && let Some(rest) = file.strip_prefix("Translation-")
        {
            let lang = rest.split('.').next().unwrap_or(rest);
            if !langs.iter().any(|l| l == lang) {
                continue;
            }
        }
        out.push((p, entry));
    }
    out
}

#[derive(Debug, Clone)]
pub struct PoolFile {
    pub path: String,
    pub size: u64,
    pub sum: Option<Checksum>,
}

fn pick_sum(get: impl Fn(HashAlgo) -> Option<String>) -> Option<Checksum> {
    [HashAlgo::Sha256, HashAlgo::Sha512, HashAlgo::Sha1, HashAlgo::Md5]
        .into_iter()
        .find_map(|a| get(a).map(|hex| Checksum { algo: a, hex: hex.to_ascii_lowercase() }))
}

#[derive(Default, Debug)]
pub struct ParseStats {
    pub packages: u64,
    pub filtered: u64,
    pub skipped: Vec<String>,
}

/// Parse a Packages index (any supported compression) into pool files.
pub fn parse_packages(path: &Path, filters: &Filters, out: &mut Vec<PoolFile>) -> Result<ParseStats> {
    let rd = open_decoded(path)?;
    let mut st = ParseStats::default();
    for para in Paragraphs::new(rd) {
        let para = para.with_context(|| format!("reading {}", path.display()))?;
        let Some(filename) = para.get("Filename") else { continue };
        st.packages += 1;
        let name = para.get("Package").unwrap_or("");
        if !filters.package_wanted(name) || filters.path_excluded(filename) {
            st.filtered += 1;
            continue;
        }
        if safe_rel_path(filename).is_err() {
            st.skipped.push(format!("unsafe Filename {filename:?} (package {name})"));
            continue;
        }
        let Some(size) = para.get("Size").and_then(|s| s.trim().parse::<u64>().ok()) else {
            st.skipped.push(format!("{filename}: missing Size"));
            continue;
        };
        let sum = pick_sum(|a| {
            let f = match a {
                HashAlgo::Md5 => "MD5sum",
                HashAlgo::Sha1 => "SHA1",
                HashAlgo::Sha256 => "SHA256",
                HashAlgo::Sha512 => "SHA512",
            };
            para.get(f).map(|s| s.trim().to_string()).filter(|s| s.len() == a.hex_len())
        });
        out.push(PoolFile { path: filename.trim_start_matches("./").to_string(), size, sum });
    }
    Ok(st)
}

/// Parse a Sources index into pool files (.dsc, tarballs, diffs).
pub fn parse_sources(path: &Path, filters: &Filters, out: &mut Vec<PoolFile>) -> Result<ParseStats> {
    let rd = open_decoded(path)?;
    let mut st = ParseStats::default();
    for para in Paragraphs::new(rd) {
        let para = para.with_context(|| format!("reading {}", path.display()))?;
        let name = para.get("Package").unwrap_or("");
        let dir = para.get("Directory").unwrap_or("").trim_matches('/').to_string();
        st.packages += 1;
        if !filters.package_wanted(name) {
            st.filtered += 1;
            continue;
        }
        // file name -> (size, best checksum)
        let mut files: BTreeMap<String, (u64, Option<Checksum>)> = BTreeMap::new();
        for (field, algo) in [
            ("Files", HashAlgo::Md5),
            ("Checksums-Sha1", HashAlgo::Sha1),
            ("Checksums-Sha512", HashAlgo::Sha512),
            ("Checksums-Sha256", HashAlgo::Sha256),
        ] {
            let Some(block) = para.get(field) else { continue };
            for line in block.lines() {
                let mut it = line.split_whitespace();
                let (Some(hex), Some(size), Some(file)) = (it.next(), it.next(), it.next()) else { continue };
                let Ok(size) = size.parse::<u64>() else { continue };
                if hex.len() != algo.hex_len() {
                    continue;
                }
                // Later (stronger) fields overwrite weaker ones; SHA-256 wins.
                files.insert(file.to_string(), (size, Some(Checksum { algo, hex: hex.to_ascii_lowercase() })));
            }
        }
        for (file, (size, sum)) in files {
            let rel = if dir.is_empty() || dir == "." { file } else { format!("{dir}/{file}") };
            if filters.path_excluded(&rel) {
                st.filtered += 1;
                continue;
            }
            if safe_rel_path(&rel).is_err() {
                st.skipped.push(format!("unsafe source path {rel:?}"));
                continue;
            }
            out.push(PoolFile { path: rel, size, sum });
        }
    }
    Ok(st)
}

/// Merge pool files by path. Returns paths that appear with conflicting contents
/// ("duplicate packages": same file name, different bytes).
pub fn dedupe(files: Vec<PoolFile>) -> (Vec<PoolFile>, Vec<String>) {
    let mut map: HashMap<String, PoolFile> = HashMap::with_capacity(files.len());
    let mut conflicts = Vec::new();
    for f in files {
        match map.get(&f.path) {
            Some(prev) => {
                let differs = prev.size != f.size
                    || matches!((&prev.sum, &f.sum), (Some(a), Some(b)) if a.algo == b.algo && a.hex != b.hex);
                if differs {
                    conflicts.push(f.path.clone());
                }
            }
            None => {
                map.insert(f.path.clone(), f);
            }
        }
    }
    let mut v: Vec<PoolFile> = map.into_values().collect();
    v.sort_by(|a, b| a.path.cmp(&b.path));
    conflicts.sort();
    conflicts.dedup();
    (v, conflicts)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arches() {
        assert_eq!(path_arch("main/binary-amd64/Packages.xz"), Some("amd64"));
        assert_eq!(path_arch("main/Contents-arm64.gz"), Some("arm64"));
        assert_eq!(path_arch("Contents-i386"), Some("i386"));
        assert_eq!(path_arch("main/Contents-udeb-amd64.gz"), Some("amd64"));
        assert_eq!(path_arch("main/dep11/Components-amd64.yml.gz"), Some("amd64"));
        assert_eq!(path_arch("main/cnf/Commands-riscv64.xz"), Some("riscv64"));
        assert_eq!(path_arch("main/debian-installer/binary-kfreebsd-amd64/Packages"), Some("kfreebsd-amd64"));
        assert_eq!(path_arch("main/i18n/Translation-en.bz2"), None);
        assert_eq!(path_arch("main/dep11/icons-64x64.tar.gz"), None);
        assert_eq!(path_arch("main/source/Sources.xz"), None);
        assert_eq!(path_arch("main/Contents-source.gz"), Some("source"));
    }

    #[test]
    fn selection() {
        let h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let mut t = String::from("Origin: x\nSHA256:\n");
        for p in [
            "main/binary-amd64/Packages.xz",
            "main/binary-arm64/Packages.xz",
            "main/binary-all/Packages.xz",
            "main/source/Sources.xz",
            "main/i18n/Translation-en.xz",
            "main/i18n/Translation-de.xz",
            "main/dep11/Components-amd64.yml.gz",
            "main/dep11/Components-arm64.yml.gz",
            "main/dep11/icons-64x64.tar.gz",
            "main/Contents-amd64.gz",
            "main/Contents-udeb-amd64.gz",
            "main/binary-amd64/Packages.diff/Index",
            "main/debian-installer/binary-amd64/Packages.xz",
            "extra/binary-amd64/Packages.xz",
            "updates/non-free/binary-amd64/Packages.xz",
            "Contents-amd64.gz",
            "Contents-arm64.gz",
        ] {
            t.push_str(&format!(" {h} 1 {p}\n"));
        }
        // No Components field on purpose: components are inferred from paths.
        let r = Release::parse(&t).unwrap();
        let f = Filters {
            include_packages: vec![],
            exclude_packages: vec![],
            exclude_paths: vec![],
            ignore_missing: vec![],
        };
        let comps = vec!["main".to_string()];
        let archs = vec!["amd64".to_string()];
        let langs = vec!["en".to_string()];
        let mut sel = Selection {
            components: &comps,
            architectures: &archs,
            source: false,
            installer: false,
            pdiffs: false,
            languages: Some(&langs),
            flat: false,
        };
        let got: Vec<&str> = select(&r, &sel, &f).into_iter().map(|(p, _)| p).collect();
        assert_eq!(
            got,
            vec![
                "Contents-amd64.gz",
                "main/Contents-amd64.gz",
                "main/binary-all/Packages.xz",
                "main/binary-amd64/Packages.xz",
                "main/dep11/Components-amd64.yml.gz",
                "main/dep11/icons-64x64.tar.gz",
                "main/i18n/Translation-en.xz",
            ]
        );
        sel.source = true;
        sel.installer = true;
        sel.pdiffs = true;
        sel.languages = None;
        let got: Vec<&str> = select(&r, &sel, &f).into_iter().map(|(p, _)| p).collect();
        assert_eq!(got.len(), 12);
        assert!(!got.iter().any(|p| p.starts_with("extra/") || p.starts_with("updates/") || p.contains("arm64")));
        let comps = vec!["non-free".to_string()];
        sel.components = &comps;
        let got: Vec<&str> = select(&r, &sel, &f).into_iter().map(|(p, _)| p).collect();
        assert_eq!(got, vec!["Contents-amd64.gz", "updates/non-free/binary-amd64/Packages.xz"]);
    }
}
