//! Parsing of yum/dnf repository metadata: `repodata/repomd.xml`, the package list in
//! `primary.xml` (any compression), and Fedora-style metalinks.
//!
//! Only what mirroring needs is read: file locations, checksums and sizes. Everything else
//! is copied verbatim.
use crate::util::{Checksum, HashAlgo, safe_rel_path};
use anyhow::{Context, Result, bail};
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use std::io::BufRead;

/// RPM metadata names for checksum types. `sha` is yum's old name for SHA-1.
pub fn algo_from_rpm(name: &str) -> Option<HashAlgo> {
    match name.to_ascii_lowercase().as_str() {
        "sha256" => Some(HashAlgo::Sha256),
        "sha512" => Some(HashAlgo::Sha512),
        "sha1" | "sha" => Some(HashAlgo::Sha1),
        "md5" => Some(HashAlgo::Md5),
        _ => None,
    }
}

/// One `<data>` entry of `repomd.xml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepomdEntry {
    /// `primary`, `filelists`, `updateinfo`, `group_gz`, `modules`, `primary_zck`, …
    pub kind: String,
    /// Relative to the repository root (`repodata/…-primary.xml.gz`).
    pub href: String,
    pub checksum: Checksum,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Repomd {
    pub revision: Option<String>,
    pub entries: Vec<RepomdEntry>,
}

impl Repomd {
    /// The entry clients read the package list from: plain `primary` (XML, any compression).
    pub fn primary(&self) -> Option<&RepomdEntry> {
        self.entries.iter().find(|e| e.kind == "primary")
    }
}

/// A package `primary.xml` lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub href: String,
    pub checksum: Checksum,
    pub size: u64,
    pub arch: String,
}

impl Package {
    /// Source packages (`src`, `nosrc`) are not mirrored.
    pub fn is_source(&self) -> bool {
        self.arch == "src" || self.arch == "nosrc"
    }
}

fn attr(e: &BytesStart, name: &str) -> Result<Option<String>> {
    for a in e.attributes() {
        let a = a.context("bad XML attribute")?;
        let key: &str = a.key.as_ref();
        if key == name {
            return Ok(Some(
                a.normalized_value(XmlVersion::default()).context("bad XML attribute value")?.into_owned(),
            ));
        }
    }
    Ok(None)
}

/// A location must be a plain path inside the repository: no `xml:base` pointing
/// elsewhere, nothing that leaves the repository directory.
/// The local (namespace-free) name of an element.
fn ln(e: &impl ElementName) -> String {
    e.name_str()
}

trait ElementName {
    fn name_str(&self) -> String;
}
impl ElementName for BytesStart<'_> {
    fn name_str(&self) -> String {
        let n = self.local_name();
        let s: &str = n.as_ref();
        s.to_string()
    }
}
impl ElementName for quick_xml::events::BytesEnd<'_> {
    fn name_str(&self) -> String {
        let n = self.local_name();
        let s: &str = n.as_ref();
        s.to_string()
    }
}

fn location(e: &BytesStart, what: &str) -> Result<String> {
    if attr(e, "xml:base")?.is_some() {
        bail!("{what}: location with xml:base (files hosted elsewhere) is not supported");
    }
    let href = attr(e, "href")?.with_context(|| format!("{what}: location without href"))?;
    safe_rel_path(&href).with_context(|| format!("{what}: unsafe location {href:?}"))?;
    Ok(href)
}

fn checksum(algo: Option<String>, hex: &str, what: &str) -> Result<Checksum> {
    let name = algo.with_context(|| format!("{what}: checksum without type"))?;
    let algo = algo_from_rpm(&name).with_context(|| format!("{what}: unsupported checksum type {name:?}"))?;
    let hex = hex.trim().to_ascii_lowercase();
    if hex.len() != algo.hex_len() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("{what}: malformed {name} checksum {hex:?}");
    }
    Ok(Checksum { algo, hex })
}

/// Parse `repomd.xml`.
pub fn parse_repomd(xml: &[u8]) -> Result<Repomd> {
    let mut r = quick_xml::Reader::from_reader(xml);
    r.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut out = Repomd::default();
    // State of the <data> element being read.
    let mut kind: Option<String> = None;
    let (mut href, mut algo, mut hex, mut size) = (None::<String>, None::<String>, String::new(), None::<u64>);
    let mut field = String::new();
    let mut text = String::new();
    loop {
        match r.read_event_into(&mut buf).context("repomd.xml is not well-formed XML")? {
            Event::Start(e) | Event::Empty(e) if kind.is_none() && ln(&e) == "data" => {
                kind = Some(attr(&e, "type")?.context("repomd.xml: <data> without type")?);
                (href, algo, hex, size) = (None, None, String::new(), None);
            }
            Event::Start(e) => {
                let name = ln(&e);
                if kind.is_some() && name == "checksum" {
                    algo = attr(&e, "type")?;
                }
                if kind.is_some() && name == "location" {
                    href = Some(location(&e, "repomd.xml")?);
                }
                field = name;
                text.clear();
            }
            Event::Empty(e) => {
                if kind.is_some() && ln(&e) == "location" {
                    href = Some(location(&e, "repomd.xml")?);
                }
            }
            Event::Text(t) => text.push_str(&t.xml10_content()),
            Event::End(e) => {
                let name = e.local_name();
                let name: &str = name.as_ref();
                match (name, &kind) {
                    ("data", Some(k)) => {
                        let what = format!("repomd.xml <data type={k:?}>");
                        let href = href.take().with_context(|| format!("{what}: no location"))?;
                        out.entries.push(RepomdEntry {
                            kind: k.clone(),
                            href,
                            checksum: checksum(algo.take(), &hex, &what)?,
                            size,
                        });
                        kind = None;
                    }
                    ("checksum", Some(_)) if field == "checksum" => hex = text.clone(),
                    ("size", Some(_)) => size = text.trim().parse().ok(),
                    ("revision", None) => out.revision = Some(text.trim().to_string()),
                    _ => {}
                }
                field.clear();
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    if out.entries.is_empty() {
        bail!("repomd.xml lists no metadata");
    }
    Ok(out)
}

/// Read the package list of a `primary.xml` (already decompressed), calling `each` for
/// every package. Streams: repositories with tens of thousands of packages are fine.
pub fn read_primary(input: impl BufRead, mut each: impl FnMut(Package) -> Result<()>) -> Result<u64> {
    let mut r = quick_xml::Reader::from_reader(input);
    r.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut count = 0u64;
    let mut in_pkg = false;
    let (mut href, mut algo, mut hex, mut size, mut arch) =
        (None::<String>, None::<String>, String::new(), None::<u64>, String::new());
    let mut field = String::new();
    let mut text = String::new();
    loop {
        match r.read_event_into(&mut buf).context("primary.xml is not well-formed XML")? {
            Event::Start(e) if ln(&e) == "package" && !in_pkg => {
                in_pkg = true;
                (href, algo, hex, size, arch) = (None, None, String::new(), None, String::new());
            }
            Event::Start(e) if in_pkg => {
                let name = ln(&e);
                // The package's own checksum; ignore nested ones elsewhere (there are none
                // in primary today, but stay strict about which element we read).
                if name == "checksum" {
                    algo = attr(&e, "type")?;
                }
                field = name;
                text.clear();
            }
            Event::Empty(e) if in_pkg => match ln(&e).as_str() {
                "location" => href = Some(location(&e, "primary.xml")?),
                "size" => {
                    size = attr(&e, "package")?.and_then(|s| s.parse().ok());
                }
                _ => {}
            },
            Event::Text(t) if in_pkg => text.push_str(&t.xml10_content()),
            Event::End(e) if in_pkg => {
                match ln(&e).as_str() {
                    "package" => {
                        let href = href.take().context("primary.xml: package without location")?;
                        let what = format!("primary.xml package {href}");
                        let pkg = Package {
                            checksum: checksum(algo.take(), &hex, &what)?,
                            size: size.with_context(|| format!("{what}: no package size"))?,
                            arch: std::mem::take(&mut arch),
                            href,
                        };
                        count += 1;
                        each(pkg)?;
                        in_pkg = false;
                    }
                    "checksum" if field == "checksum" => hex = text.clone(),
                    "arch" if field == "arch" => arch = text.trim().to_string(),
                    _ => {}
                }
                field.clear();
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(count)
}

/// The checksums a Fedora metalink accepts for `repomd.xml`: the current one and the
/// alternates (recent previous versions), strongest algorithm first per entry.
pub fn parse_metalink(xml: &[u8]) -> Result<Vec<Checksum>> {
    let mut r = quick_xml::Reader::from_reader(xml);
    r.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut in_repomd = false;
    let mut algo: Option<String> = None;
    let mut text = String::new();
    let mut sums = Vec::new();
    loop {
        match r.read_event_into(&mut buf).context("metalink is not well-formed XML")? {
            Event::Start(e) => match ln(&e).as_str() {
                "file" => in_repomd = attr(&e, "name")?.as_deref() == Some("repomd.xml"),
                "hash" if in_repomd => {
                    algo = attr(&e, "type")?;
                    text.clear();
                }
                _ => {}
            },
            Event::Text(t) => text.push_str(&t.xml10_content()),
            Event::End(e) => match ln(&e).as_str() {
                "hash" if in_repomd => {
                    if let Some(a) = algo.take().as_deref().and_then(algo_from_rpm)
                        && !a.is_weak()
                    {
                        let hex = text.trim().to_ascii_lowercase();
                        if hex.len() == a.hex_len() {
                            sums.push(Checksum { algo: a, hex });
                        }
                    }
                }
                "file" => in_repomd = false,
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    if sums.is_empty() {
        bail!("metalink has no SHA-256 or SHA-512 checksum for repomd.xml");
    }
    Ok(sums)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPOMD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo" xmlns:rpm="http://linux.duke.edu/metadata/rpm">
  <revision>9.9</revision>
  <data type="primary">
    <checksum type="sha256">0fbf42107ad35821302fc3c37f96c3dfa8a8724d7efacbd0c10363247e867d5e</checksum>
    <open-checksum type="sha256">1111111111111111111111111111111111111111111111111111111111111111</open-checksum>
    <location href="repodata/0fbf42107ad35821302fc3c37f96c3dfa8a8724d7efacbd0c10363247e867d5e-primary.xml.gz"/>
    <timestamp>1731000000</timestamp>
    <size>3001</size>
    <open-size>20000</open-size>
  </data>
  <data type="group">
    <checksum type="sha">2929bbf89e7b7578edfd75180dd28b3a4dd1880e</checksum>
    <location href="repodata/comps-AppStream.x86_64.xml"/>
    <size>77</size>
  </data>
</repomd>"#;

    #[test]
    fn repomd_entries_with_checksums_sizes_and_old_sha_name() {
        let m = parse_repomd(REPOMD.as_bytes()).unwrap();
        assert_eq!(m.revision.as_deref(), Some("9.9"));
        assert_eq!(m.entries.len(), 2);
        let p = m.primary().unwrap();
        assert!(p.href.ends_with("-primary.xml.gz"));
        // The compressed file's checksum, not the open-checksum.
        assert!(p.checksum.hex.starts_with("0fbf"));
        assert_eq!(p.size, Some(3001));
        assert_eq!(m.entries[1].checksum.algo, HashAlgo::Sha1);
        assert_eq!(m.entries[1].size, Some(77));
    }

    #[test]
    fn hostile_or_broken_repomd_is_refused() {
        let cases = [
            (REPOMD.replace("repodata/comps-AppStream.x86_64.xml", "../../etc/passwd"), "unsafe location"),
            (
                REPOMD.replace(
                    r#"<location href="repodata/comps"#,
                    r#"<location xml:base="http://evil/" href="repodata/comps"#,
                ),
                "xml:base",
            ),
            (REPOMD.replace(r#"type="sha">"#, r#"type="crc32">"#), "unsupported checksum"),
            (REPOMD.replace("2929bbf89e7b7578edfd75180dd28b3a4dd1880e", "zz"), "malformed"),
            ("<repomd/>".to_string(), "no metadata"),
            ("<repomd><data".to_string(), "well-formed"),
        ];
        for (xml, want) in cases {
            let e = format!("{:#}", parse_repomd(xml.as_bytes()).unwrap_err());
            assert!(e.contains(want), "{want}: {e}");
        }
    }

    const PRIMARY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="3">
<package type="rpm">
  <name>bash</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="5.1.8" rel="9.el9"/>
  <checksum type="sha256" pkgid="YES">aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</checksum>
  <summary>The GNU Bourne Again shell &amp; more</summary>
  <description>x</description>
  <packager>Rocky</packager>
  <url>https://www.gnu.org/software/bash</url>
  <time file="1" build="2"/>
  <size package="1789216" installed="7738634" archive="7757380"/>
  <location href="Packages/b/bash-5.1.8-9.el9.x86_64.rpm"/>
  <format>
    <rpm:license>GPLv3+</rpm:license>
    <rpm:provides><rpm:entry name="bash" flags="EQ" epoch="0" ver="5.1.8" rel="9.el9"/></rpm:provides>
  </format>
</package>
<package type="rpm">
  <name>tzdata</name>
  <arch>noarch</arch>
  <checksum type="sha256" pkgid="YES">bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb</checksum>
  <size package="882000" installed="1" archive="1"/>
  <location href="Packages/t/tzdata-2024a-1.el9.noarch.rpm"/>
</package>
<package type="rpm">
  <name>bash</name>
  <arch>src</arch>
  <checksum type="sha256" pkgid="YES">cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc</checksum>
  <size package="10" installed="1" archive="1"/>
  <location href="Source/b/bash-5.1.8-9.el9.src.rpm"/>
</package>
</metadata>"#;

    #[test]
    fn primary_packages_and_source_detection() {
        let mut pkgs = Vec::new();
        let n = read_primary(PRIMARY.as_bytes(), |p| {
            pkgs.push(p);
            Ok(())
        })
        .unwrap();
        assert_eq!(n, 3);
        assert_eq!(pkgs[0].href, "Packages/b/bash-5.1.8-9.el9.x86_64.rpm");
        assert_eq!(pkgs[0].size, 1789216);
        assert_eq!(pkgs[0].arch, "x86_64");
        assert_eq!(pkgs[0].checksum.hex, "a".repeat(64));
        assert!(!pkgs[1].is_source());
        assert!(pkgs[2].is_source());
    }

    #[test]
    fn primary_refuses_unsafe_locations() {
        let bad = PRIMARY.replace("Packages/t/tzdata", "../../../tmp/tzdata");
        let e = format!("{:#}", read_primary(bad.as_bytes(), |_| Ok(())).unwrap_err());
        assert!(e.contains("unsafe location"), "{e}");
    }

    #[test]
    fn metalink_current_and_alternate_checksums() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<metalink version="3.0" xmlns="http://www.metalinker.org/" type="dynamic" xmlns:mm0="http://fedorahosted.org/mirrormanager">
 <files>
  <file name="repomd.xml">
   <mm0:alternates>
    <mm0:alternate><mm0:timestamp>1</mm0:timestamp><size>100</size>
     <verification><hash type="md5">00000000000000000000000000000000</hash>
      <hash type="sha256">1111111111111111111111111111111111111111111111111111111111111111</hash></verification>
    </mm0:alternate>
   </mm0:alternates>
   <size>101</size>
   <verification>
    <hash type="sha1">2222222222222222222222222222222222222222</hash>
    <hash type="sha256">3333333333333333333333333333333333333333333333333333333333333333</hash>
    <hash type="sha512">44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444</hash>
   </verification>
   <resources maxconnections="1"><url protocol="https" type="https">https://m/epel/9/repodata/repomd.xml</url></resources>
  </file>
 </files>
</metalink>"#;
        let sums = parse_metalink(xml.as_bytes()).unwrap();
        // Weak algorithms are ignored.
        assert_eq!(sums.len(), 3);
        assert!(sums.iter().all(|c| !c.algo.is_weak()));
        assert!(sums.iter().any(|c| c.hex.starts_with("1111")));
        assert!(parse_metalink(b"<metalink><files/></metalink>").is_err());
    }

    /// Metadata written by the real createrepo_c (tests/fixtures/rpm/make-sample.py).
    #[test]
    fn createrepo_c_output_parses_and_every_checksum_matches_the_files() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/rpm/sample");
        let m = parse_repomd(&std::fs::read(root.join("repodata/repomd.xml")).unwrap()).unwrap();
        let kinds: Vec<&str> = m.entries.iter().map(|e| e.kind.as_str()).collect();
        for k in ["primary", "primary_db", "filelists", "filelists_db", "other", "other_db", "group"] {
            assert!(kinds.contains(&k), "{k} in {kinds:?}");
        }
        for e in &m.entries {
            let path = root.join(&e.href);
            assert!(crate::util::file_matches(&path, e.size, Some(&e.checksum)), "{}", e.href);
        }
        let primary = crate::util::open_decoded(&root.join(&m.primary().unwrap().href)).unwrap();
        let mut pkgs = Vec::new();
        read_primary(primary, |p| {
            pkgs.push(p);
            Ok(())
        })
        .unwrap();
        assert_eq!(pkgs.len(), 4);
        assert_eq!(pkgs.iter().filter(|p| p.is_source()).count(), 1);
        assert!(pkgs.iter().any(|p| p.href == "Packages/o/odd&name-1-1.el9.x86_64.rpm"), "entities decoded");
        for p in &pkgs {
            assert!(crate::util::file_matches(&root.join(&p.href), Some(p.size), Some(&p.checksum)), "{}", p.href);
        }
    }
}
