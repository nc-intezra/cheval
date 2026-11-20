//! Checksum lists of file folders (`format = "files"`): `CHECKSUM`, `SHA256SUM`,
//! `sha256sum.txt` and the like, as published next to installer ISOs.
//!
//! Both common styles are read, and a list may mix them:
//! * GNU (`sha256sum`): `<hex>  <name>` or `<hex> *<name>`; the algorithm follows from the
//!   length of the hex string;
//! * BSD (`sha256sum --tag`): `SHA256 (<name>) = <hex>`.
//!
//! Lines such as `# CentOS-Stream-9-…-dvd1.iso: 15918825472 bytes` (Rocky, CentOS Stream)
//! give the size in advance. A clear-signed list is unwrapped first. Names must be plain
//! file names in the folder.
use crate::util::{Checksum, HashAlgo};
use anyhow::{Result, bail};
use std::collections::BTreeMap;

/// What a list says about one file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listed {
    pub sums: Vec<Checksum>,
    pub size: Option<u64>,
}

impl Listed {
    /// The strongest checksum given.
    pub fn best(&self) -> Option<&Checksum> {
        self.sums.iter().max_by_key(|c| c.algo)
    }
}

fn algo_by_name(name: &str) -> Option<HashAlgo> {
    match name.to_ascii_uppercase().replace('-', "").as_str() {
        "SHA256" => Some(HashAlgo::Sha256),
        "SHA512" => Some(HashAlgo::Sha512),
        "SHA1" => Some(HashAlgo::Sha1),
        "MD5" => Some(HashAlgo::Md5),
        _ => None,
    }
}

fn algo_by_len(len: usize) -> Option<HashAlgo> {
    [HashAlgo::Md5, HashAlgo::Sha1, HashAlgo::Sha256, HashAlgo::Sha512].into_iter().find(|a| a.hex_len() == len)
}

fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && name != "."
        && name != ".."
        && !name.chars().any(char::is_control)
}

/// Parse one checksum list into `out` (several lists can be merged). Returns how many
/// entries it held.
pub fn parse_into(text: &str, out: &mut BTreeMap<String, Listed>) -> Result<usize> {
    let text = if text.trim_start().starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
        crate::sig::strip_cleartext(text)
    } else {
        text.to_string()
    };
    let mut n = 0;
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(c) = t.strip_prefix('#') {
            // "# NAME: 123 bytes"
            if let Some((name, rest)) = c.trim().rsplit_once(':')
                && let Some(num) = rest.trim().strip_suffix("bytes")
                && let Ok(size) = num.trim().parse::<u64>()
                && plain_name(name.trim())
            {
                out.entry(name.trim().to_string()).or_default().size = Some(size);
            }
            continue;
        }
        // BSD: ALGO (name) = hex
        if let Some((head, hex)) = t.rsplit_once(") = ")
            && let Some((algo, name)) = head.split_once(" (")
            && let Some(algo) = algo_by_name(algo.trim())
        {
            let hex = hex.trim().to_ascii_lowercase();
            if hex.len() == algo.hex_len() && hex.bytes().all(|b| b.is_ascii_hexdigit()) && plain_name(name) {
                out.entry(name.to_string()).or_default().sums.push(Checksum { algo, hex });
                n += 1;
            }
            continue;
        }
        // GNU: hex␠␠name or hex␠*name
        if let Some((hex, name)) = t.split_once(char::is_whitespace) {
            let name = name.trim_start();
            let name = name.strip_prefix('*').unwrap_or(name);
            if let Some(algo) = algo_by_len(hex.len())
                && hex.bytes().all(|b| b.is_ascii_hexdigit())
                && plain_name(name)
            {
                out.entry(name.to_string()).or_default().sums.push(Checksum { algo, hex: hex.to_ascii_lowercase() });
                n += 1;
            }
        }
    }
    Ok(n)
}

/// Parse a single list.
pub fn parse(text: &str) -> Result<BTreeMap<String, Listed>> {
    let mut out = BTreeMap::new();
    if parse_into(text, &mut out)? == 0 {
        bail!("no checksums found (expected `<hash>  <file>` or `SHA256 (<file>) = <hash>` lines)");
    }
    out.retain(|_, l| !l.sums.is_empty());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const H1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn bsd_style_with_size_comments_as_rocky_and_stream_publish() {
        let text = format!(
            "# Rocky-9-latest-x86_64-dvd.iso: 15918825472 bytes\nSHA256 (Rocky-9-latest-x86_64-dvd.iso) = {H1}\n\
             # Rocky-9.9-x86_64-boot.iso: 1563197440 bytes\nSHA256 (Rocky-9.9-x86_64-boot.iso) = {H2}\n"
        );
        let l = parse(&text).unwrap();
        assert_eq!(l.len(), 2);
        let dvd = &l["Rocky-9-latest-x86_64-dvd.iso"];
        assert_eq!(dvd.size, Some(15918825472));
        assert_eq!(dvd.best().unwrap(), &Checksum { algo: HashAlgo::Sha256, hex: H1.into() });
    }

    #[test]
    fn gnu_style_as_centos_vault_publishes_with_binary_marker() {
        let text = format!(
            "{H1}  CentOS-7-x86_64-DVD-2207-02.iso\n{}  *CentOS-7-x86_64-Minimal-2009.iso\n",
            H2.to_uppercase()
        );
        let l = parse(&text).unwrap();
        assert_eq!(l["CentOS-7-x86_64-DVD-2207-02.iso"].best().unwrap().hex, H1);
        assert_eq!(l["CentOS-7-x86_64-Minimal-2009.iso"].best().unwrap().hex, H2, "lower-cased");
        assert_eq!(l["CentOS-7-x86_64-Minimal-2009.iso"].size, None);
    }

    #[test]
    fn clear_signed_lists_are_unwrapped_and_strongest_hash_wins() {
        let text = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{}  a.iso\n{H1}  a.iso\n-----BEGIN PGP SIGNATURE-----\n\nxyz\n-----END PGP SIGNATURE-----\n",
            "0".repeat(40)
        );
        let l = parse(&text).unwrap();
        assert_eq!(l["a.iso"].sums.len(), 2);
        assert_eq!(l["a.iso"].best().unwrap().algo, HashAlgo::Sha256);
    }

    #[test]
    fn paths_and_junk_are_ignored_and_empty_lists_refused() {
        let text = format!("{H1}  ../etc/passwd\n{H1}  sub/dir.iso\nnot a checksum line\n{H2}  ok.iso\n");
        let l = parse(&text).unwrap();
        assert_eq!(l.keys().collect::<Vec<_>>(), vec!["ok.iso"]);
        assert!(parse("# nothing here\n").is_err());
    }
}
