//! Release / InRelease parsing.
use crate::deb822::{Paragraph, parse_one};
use crate::util::{Checksum, HashAlgo};
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct FileEntry {
    pub size: u64,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub sha512: Option<String>,
}

impl FileEntry {
    pub fn get(&self, algo: HashAlgo) -> Option<&str> {
        match algo {
            HashAlgo::Md5 => self.md5.as_deref(),
            HashAlgo::Sha1 => self.sha1.as_deref(),
            HashAlgo::Sha256 => self.sha256.as_deref(),
            HashAlgo::Sha512 => self.sha512.as_deref(),
        }
    }
    fn set(&mut self, algo: HashAlgo, hex: String) {
        match algo {
            HashAlgo::Md5 => self.md5 = Some(hex),
            HashAlgo::Sha1 => self.sha1 = Some(hex),
            HashAlgo::Sha256 => self.sha256 = Some(hex),
            HashAlgo::Sha512 => self.sha512 = Some(hex),
        }
    }
    /// Checksum we verify with. SHA-256 is preferred (hardware accelerated and what
    /// apt itself requires); SHA-512 next; weak algorithms only as a last resort.
    pub fn best(&self) -> Option<Checksum> {
        for algo in [HashAlgo::Sha256, HashAlgo::Sha512, HashAlgo::Sha1, HashAlgo::Md5] {
            if let Some(h) = self.get(algo) {
                return Some(Checksum { algo, hex: h.to_string() });
            }
        }
        None
    }
    pub fn all(&self) -> Vec<Checksum> {
        [HashAlgo::Sha512, HashAlgo::Sha256, HashAlgo::Sha1, HashAlgo::Md5]
            .into_iter()
            .filter_map(|a| self.get(a).map(|h| Checksum { algo: a, hex: h.to_string() }))
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Release {
    pub para: Paragraph,
    pub files: BTreeMap<String, FileEntry>,
    pub acquire_by_hash: bool,
    pub date: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
    pub architectures: Vec<String>,
    pub components: Vec<String>,
}

/// Parse dates as found in Release files (`Sat, 14 Nov 2026 20:12:01 UTC`).
pub fn parse_date(s: &str) -> Option<DateTime<Utc>> {
    let n = s.trim().replace(" UTC", " +0000").replace(" GMT", " +0000").replace(" Z", " +0000");
    if let Ok(d) = DateTime::parse_from_rfc2822(&n) {
        return Some(d.with_timezone(&Utc));
    }
    // Some generators omit the weekday or use single-digit days.
    for fmt in ["%a, %d %b %Y %H:%M:%S %z", "%d %b %Y %H:%M:%S %z", "%a, %e %b %Y %H:%M:%S %z"] {
        if let Ok(d) = DateTime::parse_from_str(&n, fmt) {
            return Some(d.with_timezone(&Utc));
        }
    }
    None
}

impl Release {
    pub fn parse(text: &str) -> Result<Release> {
        let para = parse_one(text);
        if para.is_empty() {
            bail!("Release file is empty or not a control file");
        }
        let mut files: BTreeMap<String, FileEntry> = BTreeMap::new();
        for algo in [HashAlgo::Md5, HashAlgo::Sha1, HashAlgo::Sha256, HashAlgo::Sha512] {
            let Some(block) = para.get(algo.release_field()) else { continue };
            for line in block.lines() {
                let mut it = line.split_whitespace();
                let (Some(hex), Some(size), Some(path)) = (it.next(), it.next(), it.next()) else {
                    continue;
                };
                if hex.len() != algo.hex_len() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    continue;
                }
                let Ok(size) = size.parse::<u64>() else { continue };
                let e = files.entry(path.to_string()).or_default();
                e.size = size;
                e.set(algo, hex.to_ascii_lowercase());
            }
        }
        let list = |name: &str| -> Vec<String> {
            para.get(name).map(|v| v.split_whitespace().map(str::to_string).collect()).unwrap_or_default()
        };
        Ok(Release {
            acquire_by_hash: para.get("Acquire-By-Hash").is_some_and(|v| v.eq_ignore_ascii_case("yes")),
            date: para.get("Date").and_then(parse_date),
            valid_until: para.get("Valid-Until").and_then(parse_date),
            architectures: list("Architectures"),
            components: list("Components"),
            files,
            para,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_release() {
        let t = "Origin: T\nSuite: stable\nDate: Sat, 14 Nov 2026 20:12:01 UTC\nValid-Until: Sat, 21 Nov 2026 20:12:01 UTC\nAcquire-By-Hash: yes\nArchitectures: amd64 arm64\nComponents: main contrib\nSHA256: \n e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 main/binary-amd64/Packages\n e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855       12 main/binary-amd64/Packages.gz\nMD5Sum:\n d41d8cd98f00b204e9800998ecf8427e 0 main/binary-amd64/Packages\n";
        let r = Release::parse(t).unwrap();
        assert!(r.acquire_by_hash);
        assert_eq!(r.files.len(), 2);
        assert_eq!(r.files["main/binary-amd64/Packages.gz"].size, 12);
        assert!(r.files["main/binary-amd64/Packages"].md5.is_some());
        assert_eq!(r.components, vec!["main", "contrib"]);
        assert!(r.date.unwrap() < r.valid_until.unwrap());
        assert_eq!(r.files["main/binary-amd64/Packages"].best().unwrap().algo, HashAlgo::Sha256);
    }
}
