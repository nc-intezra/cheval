//! Small shared helpers: hashing, decompression, formatting, path safety.
use anyhow::{Context, Result, bail};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashAlgo {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl HashAlgo {
    /// Directory name used below `by-hash/` and field name in Release files.
    pub fn release_field(self) -> &'static str {
        match self {
            HashAlgo::Md5 => "MD5Sum",
            HashAlgo::Sha1 => "SHA1",
            HashAlgo::Sha256 => "SHA256",
            HashAlgo::Sha512 => "SHA512",
        }
    }
    pub fn hex_len(self) -> usize {
        match self {
            HashAlgo::Md5 => 32,
            HashAlgo::Sha1 => 40,
            HashAlgo::Sha256 => 64,
            HashAlgo::Sha512 => 128,
        }
    }
    pub fn is_weak(self) -> bool {
        matches!(self, HashAlgo::Md5 | HashAlgo::Sha1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Checksum {
    pub algo: HashAlgo,
    pub hex: String,
}

pub enum Hasher {
    Md5(Md5),
    Sha1(Sha1),
    Sha256(Sha256),
    Sha512(Sha512),
}

impl Hasher {
    pub fn new(algo: HashAlgo) -> Self {
        match algo {
            HashAlgo::Md5 => Hasher::Md5(Md5::new()),
            HashAlgo::Sha1 => Hasher::Sha1(Sha1::new()),
            HashAlgo::Sha256 => Hasher::Sha256(Sha256::new()),
            HashAlgo::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Md5(h) => h.update(data),
            Hasher::Sha1(h) => h.update(data),
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
        }
    }
    pub fn finish(self) -> String {
        match self {
            Hasher::Md5(h) => hex::encode(h.finalize()),
            Hasher::Sha1(h) => hex::encode(h.finalize()),
            Hasher::Sha256(h) => hex::encode(h.finalize()),
            Hasher::Sha512(h) => hex::encode(h.finalize()),
        }
    }
}

/// Hash a whole file (blocking).
pub fn hash_file(path: &Path, algo: HashAlgo) -> std::io::Result<String> {
    let mut f = File::open(path)?;
    let mut h = Hasher::new(algo);
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finish())
}

/// True when `path` exists with the expected size and (optionally) checksum.
pub fn file_matches(path: &Path, size: Option<u64>, sum: Option<&Checksum>) -> bool {
    let Ok(md) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !md.is_file() {
        return false;
    }
    if let Some(s) = size
        && md.len() != s
    {
        return false;
    }
    match sum {
        Some(c) => hash_file(path, c.algo).map(|h| h.eq_ignore_ascii_case(&c.hex)).unwrap_or(false),
        None => true,
    }
}

/// Compression suffixes we recognise on index files.
pub const COMPRESSION_EXTS: &[&str] = &[".xz", ".gz", ".bz2", ".zst", ".lzma", ".lz4"];

/// Split `main/binary-amd64/Packages.xz` into (`main/binary-amd64/Packages`, `.xz`).
pub fn split_compression(path: &str) -> (&str, &str) {
    for ext in COMPRESSION_EXTS {
        if let Some(stem) = path.strip_suffix(ext) {
            return (stem, ext);
        }
    }
    (path, "")
}

/// Whether we can decode a file with the given compression suffix.
pub fn can_decode(ext: &str) -> bool {
    matches!(ext, "" | ".xz" | ".gz" | ".bz2" | ".zst" | ".lzma")
}

/// Open an index file, transparently decompressing by suffix.
pub fn open_decoded(path: &Path) -> Result<Box<dyn BufRead + Send>> {
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let name = path.to_string_lossy();
    let (_, ext) = split_compression(&name);
    let r: Box<dyn Read + Send> = match ext {
        "" => Box::new(f),
        ".gz" => Box::new(flate2::read::MultiGzDecoder::new(f)),
        ".xz" | ".lzma" => Box::new(liblzma::read::XzDecoder::new_multi_decoder(f)),
        ".bz2" => Box::new(bzip2::read::MultiBzDecoder::new(f)),
        ".zst" => Box::new(zstd::stream::read::Decoder::new(f)?),
        other => bail!("unsupported compression {other}"),
    };
    Ok(Box::new(BufReader::with_capacity(1 << 16, r)))
}

/// Validate a repository-relative path taken from untrusted metadata.
/// Rejects absolute paths, `..`, empty paths and control characters, so a hostile
/// index can never make us write outside the repository root.
pub fn safe_rel_path(p: &str) -> Result<PathBuf> {
    let trimmed = p.trim_start_matches("./");
    if trimmed.is_empty() {
        bail!("empty path");
    }
    if trimmed.chars().any(|c| c.is_control()) || trimmed.contains('\\') {
        bail!("path contains illegal characters: {p:?}");
    }
    let path = Path::new(trimmed);
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            _ => bail!("unsafe path in repository metadata: {p:?}"),
        }
    }
    if out.as_os_str().is_empty() {
        bail!("empty path");
    }
    Ok(out)
}

pub fn human_bytes(n: u64) -> String {
    const U: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n} B") } else { format!("{v:.1} {}", U[i]) }
}

pub fn human_duration(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs / 60) % 60, secs % 60);
    if h > 0 { format!("{h}:{m:02}:{s:02}") } else { format!("{m:02}:{s:02}") }
}

/// Parse sizes such as `500K`, `10M`, `1.5G` or plain bytes (per second for rate limits).
pub fn parse_size(s: &str) -> Result<u64> {
    let t = s.trim().trim_end_matches("/s").trim_end_matches(['b', 'B']).trim_end_matches('i');
    let (num, mult) = match t.chars().last() {
        Some('k') | Some('K') => (&t[..t.len() - 1], 1u64 << 10),
        Some('m') | Some('M') => (&t[..t.len() - 1], 1 << 20),
        Some('g') | Some('G') => (&t[..t.len() - 1], 1 << 30),
        _ => (t, 1),
    };
    let v: f64 = num.trim().parse().with_context(|| format!("invalid size {s:?}"))?;
    if v < 0.0 {
        bail!("negative size {s:?}");
    }
    Ok((v * mult as f64) as u64)
}

/// Replace `src` into `dst` atomically, preferring a hard link (so staging can be
/// discarded later) and falling back to a copy across filesystems.
pub fn link_or_copy_atomic(src: &Path, dst: &Path) -> std::io::Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp = dst.as_os_str().to_owned();
    tmp.push(".cheval-new");
    let tmp = PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);
    if std::fs::hard_link(src, &tmp).is_err() {
        std::fs::copy(src, &tmp)?;
    }
    std::fs::rename(&tmp, dst)
}

/// Shell-style wildcard match of a whole file name: `*` any run of characters, `?` one.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (pattern.chars().collect(), name.chars().collect());
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths() {
        assert!(safe_rel_path("pool/main/a/a_1.deb").is_ok());
        assert_eq!(safe_rel_path("./pool/x").unwrap(), PathBuf::from("pool/x"));
        assert!(safe_rel_path("../etc/passwd").is_err());
        assert!(safe_rel_path("/etc/passwd").is_err());
        assert!(safe_rel_path("pool/../../x").is_err());
        assert!(safe_rel_path("").is_err());
    }
    #[test]
    fn sizes() {
        assert_eq!(parse_size("10M").unwrap(), 10 << 20);
        assert_eq!(parse_size("1.5k").unwrap(), 1536);
        assert_eq!(parse_size("2MiB/s").unwrap(), 2 << 20);
        assert_eq!(parse_size("123").unwrap(), 123);
        assert_eq!(split_compression("a/Packages.xz"), ("a/Packages", ".xz"));
    }

    #[test]
    fn wildcards() {
        assert!(glob_match("Rocky-9-latest-x86_64-dvd.iso", "Rocky-9-latest-x86_64-dvd.iso"));
        assert!(glob_match("CentOS-6.10-x86_64-bin-DVD?.iso", "CentOS-6.10-x86_64-bin-DVD2.iso"));
        assert!(glob_match("*-dvd*.iso", "CentOS-Stream-8-20240603.0-x86_64-dvd1.iso"));
        assert!(glob_match("*", "anything"));
        assert!(!glob_match("*-dvd*.iso", "CentOS-Stream-8-20240603.0-x86_64-dvd1.iso.manifest"));
        assert!(!glob_match("CentOS-7-x86_64-DVD-*.iso", "CentOS-7-x86_64-Everything-2009.iso"));
        assert!(!glob_match("a?c", "ac"));
    }
}
