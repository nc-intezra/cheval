//! `format = "go"`: a Go module proxy (the GOPROXY protocol, as `proxy.golang.org` serves it).
//!
//! Per module version: `<module>/@v/<version>.info`, `.mod`, and `.zip`; per module:
//! `<module>/@v/list` with the mirrored release versions. Module paths and versions are
//! escaped as the protocol says (`!` before a lower-cased capital).
//!
//! Selection: `lockfiles` (`go.sum`) name exact versions with their `h1:` hashes: a
//! `/go.mod` line needs the `.mod`, a plain line the `.zip` as well; both are checked
//! against the hash. `packages` (`module@version`, `module@latest`, or a bare module)
//! follow `require` lines through every reachable `go.mod` (as minimal version selection
//! reads them) and take the zip of the version selected for each module.
//!
//! The checksum database (`sum.golang.org`) is not mirrored: clients need a complete
//! `go.sum`, or `GOFLAGS=-mod=mod` with `GONOSUMDB`/`GOSUMDB=off` for the mirrored modules.
use crate::engine::{Ctx, Plan, PostCheck, Want, par};
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

/// The GOPROXY escaping: `!` followed by the lower-case letter for each capital.
pub fn escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            o.push('!');
            o.push(c.to_ascii_lowercase());
        } else {
            o.push(c);
        }
    }
    o
}

pub fn unescape(s: &str) -> Option<String> {
    let mut o = String::with_capacity(s.len());
    let mut bang = false;
    for c in s.chars() {
        if bang {
            if !c.is_ascii_lowercase() {
                return None;
            }
            o.push(c.to_ascii_uppercase());
            bang = false;
        } else if c == '!' {
            bang = true;
        } else if c.is_ascii_uppercase() {
            return None;
        } else {
            o.push(c);
        }
    }
    (!bang).then_some(o)
}

/// A pseudo-version (`v0.0.0-20240101120000-abcdef123456` and its variants): not listed
/// in `@v/list`.
pub fn is_pseudo(v: &str) -> bool {
    let base = v.split('+').next().unwrap_or(v);
    let Some((rest, rev)) = base.rsplit_once('-') else { return false };
    if rev.len() < 12 || !rev.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    let ts = rest.rsplit(['-', '.']).next().unwrap_or("");
    ts.len() == 14 && ts.chars().all(|c| c.is_ascii_digit())
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        o.push(T[(n >> 18) as usize & 63] as char);
        o.push(T[(n >> 12) as usize & 63] as char);
        o.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        o.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    o
}

/// Go's `dirhash.Hash1` over (name, sha256 hex) pairs.
fn hash1(mut files: Vec<(String, String)>) -> String {
    files.sort();
    let mut h = Sha256::new();
    for (name, sum) in files {
        h.update(format!("{sum}  {name}\n").as_bytes());
    }
    format!("h1:{}", b64(&h.finalize()))
}

/// The `h1:` hash of a `go.mod`, as `go.sum` records it on `/go.mod` lines.
pub fn mod_h1(data: &[u8]) -> String {
    hash1(vec![("go.mod".into(), hex::encode(Sha256::digest(data)))])
}

/// Check a module zip: every file under `prefix` (`module@version/`), and the `h1:` hash
/// when one is given. Returns the hash.
pub fn check_zip(path: &Path, prefix: &str, want: Option<&str>) -> Result<String> {
    let f = std::fs::File::open(path)?;
    let mut z = zip::ZipArchive::new(f).with_context(|| format!("{}: not a zip file", path.display()))?;
    let mut files = Vec::new();
    for i in 0..z.len() {
        let mut e = z.by_index(i)?;
        let name = e.name()?.to_string();
        if name.ends_with('/') {
            continue;
        }
        if !name.starts_with(prefix) || name.contains('\n') {
            bail!("{}: zip entry {name:?} is outside {prefix}", path.display());
        }
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let n = e.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        files.push((name, hex::encode(h.finalize())));
    }
    let got = hash1(files);
    if let Some(w) = want
        && w != got
    {
        bail!("{}: hash {got} does not match go.sum's {w}", path.display());
    }
    Ok(got)
}

/// `require` lines of a `go.mod`: (module, version).
pub fn requires(gomod: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut block = false;
    for raw in gomod.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let body = if block {
            if line == ")" {
                block = false;
                continue;
            }
            line
        } else if let Some(rest) = line.strip_prefix("require") {
            let rest = rest.trim();
            if rest == "(" {
                block = true;
                continue;
            }
            if rest.is_empty() || !line[7..].starts_with(char::is_whitespace) {
                continue;
            }
            rest
        } else {
            continue;
        };
        let f: Vec<String> = body.split_whitespace().map(|s| s.trim_matches('"').trim_matches('`').to_string()).collect();
        if f.len() >= 2 && f[1].starts_with('v') {
            out.push((f[0].clone(), f[1].clone()));
        }
    }
    out
}

/// `go.sum` lines: module version → (zip hash, go.mod hash).
pub type Sums = BTreeMap<(String, String), (Option<String>, Option<String>)>;

pub fn read_go_sum(text: &str) -> Result<Sums> {
    let mut m = Sums::new();
    for (n, line) in text.lines().enumerate() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        if f.len() != 3 || !f[2].starts_with("h1:") {
            bail!("line {}: not a go.sum line", n + 1);
        }
        let (ver, is_mod) = match f[1].strip_suffix("/go.mod") {
            Some(v) => (v, true),
            None => (f[1], false),
        };
        let e = m.entry((f[0].to_string(), ver.to_string())).or_default();
        if is_mod {
            e.1 = Some(f[2].to_string());
        } else {
            e.0 = Some(f[2].to_string());
        }
    }
    Ok(m)
}

/// Compare Go versions (semver with a `v`; `+incompatible` ignored).
fn ver_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let p = |s: &str| semver::Version::parse(s.trim_start_matches('v').split('+').next().unwrap_or("")).ok();
    match (p(a), p(b)) {
        (Some(x), Some(y)) => x.cmp(&y),
        _ => a.cmp(b),
    }
}

struct Need {
    zip: bool,
    zip_h1: Option<String>,
    mod_h1: Option<String>,
}

pub async fn plan(ctx: &Ctx<'_>) -> Result<Plan> {
    let repo = ctx.repo;
    let base = ctx.base.clone();
    let mut plan = Plan::default();
    let mut need: BTreeMap<(String, String), Need> = BTreeMap::new();

    for l in &repo.lockfiles {
        let text = std::fs::read_to_string(l).with_context(|| format!("{}", l.display()))?;
        for ((m, v), (zh, mh)) in read_go_sum(&text).with_context(|| format!("{}", l.display()))? {
            let e = need.entry((m, v)).or_insert(Need { zip: false, zip_h1: None, mod_h1: None });
            if zh.is_some() {
                e.zip = true;
                e.zip_h1 = zh;
            }
            if mh.is_some() {
                e.mod_h1 = mh;
            }
        }
    }

    // packages: resolve @latest, then walk go.mod requirements.
    let mut roots: Vec<(String, String)> = Vec::new();
    for s in &repo.packages {
        let (m, v) = s.split_once('@').map(|(m, v)| (m.trim(), v.trim())).unwrap_or((s.trim(), "latest"));
        if m.is_empty() || m.contains(char::is_whitespace) {
            bail!("go: bad package {s:?} (expected module@version)");
        }
        let v = if v == "latest" {
            let url = base.join(&format!("{}/@latest", escape(m)))?;
            let Some((_, data)) = ctx.fetch(&url).await? else { bail!("go: module {m} not found ({url})") };
            let j: serde_json::Value = serde_json::from_slice(&data).with_context(|| format!("{url}"))?;
            j.get("Version").and_then(|v| v.as_str()).with_context(|| format!("{url}: no Version"))?.to_string()
        } else {
            if !v.starts_with('v') {
                bail!("go: bad version in {s:?} (versions start with v)");
            }
            v.to_string()
        };
        roots.push((m.to_string(), v));
    }
    let mut mods: BTreeMap<(String, String), Vec<u8>> = BTreeMap::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut frontier: Vec<(String, String)> = roots.clone();
    let mut root_set: BTreeSet<(String, String)> = roots.iter().cloned().collect();
    while !frontier.is_empty() {
        if ctx.cancelled() {
            bail!("cancelled");
        }
        let batch: Vec<(String, String)> = std::mem::take(&mut frontier).into_iter().filter(|k| seen.insert(k.clone())).collect();
        let got = par(batch, ctx.parallel(), |(m, v)| {
            let base = base.clone();
            async move {
                let url = base.join(&format!("{}/@v/{}.mod", escape(&m), escape(&v)))?;
                let r = ctx.immutable(&url).await?;
                Ok::<_, anyhow::Error>((m, v, url, r))
            }
        })
        .await;
        for r in got {
            let (m, v, url, r) = r?;
            let Some((data, _)) = r else {
                if root_set.remove(&(m.clone(), v.clone())) {
                    bail!("go: {m}@{v} not found ({url})");
                }
                ctx.warn(format!("go: {m}@{v} is required but the proxy does not have it"));
                continue;
            };
            for (rm, rv) in requires(&String::from_utf8_lossy(&data)) {
                frontier.push((rm, rv));
            }
            mods.insert((m, v), data);
        }
    }
    // Minimal version selection: the highest required version of each module gets its zip.
    let mut selected: BTreeMap<&str, &str> = BTreeMap::new();
    for (m, v) in mods.keys() {
        let e = selected.entry(m.as_str()).or_insert(v.as_str());
        if ver_cmp(v, e).is_gt() {
            *e = v.as_str();
        }
    }
    for (m, v) in mods.keys() {
        let zip = selected.get(m.as_str()) == Some(&v.as_str());
        let e = need.entry((m.clone(), v.clone())).or_insert(Need { zip: false, zip_h1: None, mod_h1: None });
        e.zip |= zip;
    }

    // Files per version: .info and .mod (immutable, read during planning), .zip downloaded.
    let items: Vec<((String, String), Need)> = need.into_iter().collect();
    let n_versions = items.len();
    let n_zips = items.iter().filter(|(_, n)| n.zip).count();
    let got = par(items, ctx.parallel(), |((m, v), n)| {
        let base = base.clone();
        async move {
            let dir = format!("{}/@v/{}", escape(&m), escape(&v));
            let mod_url = base.join(&format!("{dir}.mod"))?;
            let info_url = base.join(&format!("{dir}.info"))?;
            let m_r = ctx.immutable(&mod_url).await?;
            let i_r = ctx.immutable(&info_url).await?;
            Ok::<_, anyhow::Error>((m, v, n, dir, mod_url, info_url, m_r, i_r))
        }
    })
    .await;
    let mut listed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for r in got {
        let (m, v, n, dir, mod_url, info_url, m_r, i_r) = r?;
        let Some((mdata, mstaged)) = m_r else { bail!("go: {m}@{v}: {mod_url} not found") };
        if let Some(h) = &n.mod_h1 {
            let got = mod_h1(&mdata);
            if &got != h {
                bail!("go: {m}@{v}: go.mod hash {got} does not match go.sum's {h}");
            }
        }
        if let Some(p) = mstaged {
            plan.publish(p, ctx.local(&mod_url)?);
        }
        match i_r {
            Some((_, Some(p))) => plan.publish(p, ctx.local(&info_url)?),
            Some((_, None)) => {}
            None => ctx.warn(format!("go: {m}@{v}: no .info upstream")),
        }
        if n.zip {
            let url = base.join(&format!("{dir}.zip"))?;
            plan.want(Want {
                dest: ctx.local(&url)?,
                url,
                size: None,
                sum: None,
                post: PostCheck::GoZip { prefix: format!("{m}@{v}/"), h1: n.zip_h1.clone() },
                label: format!("{m}@{v}.zip"),
            });
        }
        listed.entry(m).or_default().insert(v);
    }
    // @v/list per module: release versions mirrored now or before.
    for (m, vs) in &listed {
        let list_url = base.join(&format!("{}/@v/list", escape(m)))?;
        let dir = ctx.local(&list_url)?.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        let mut all: BTreeSet<String> = vs.iter().cloned().collect();
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if let Some(v) = name.strip_suffix(".mod").and_then(unescape) {
                    all.insert(v);
                }
            }
        }
        let mut rel: Vec<String> = all.into_iter().filter(|v| !is_pseudo(v)).collect();
        rel.sort_by(|a, b| ver_cmp(a, b));
        let mut text = rel.join("\n");
        if !text.is_empty() {
            text.push('\n');
        }
        let staged = ctx.stage_bytes("list", text.as_bytes())?;
        plan.publish(staged, ctx.local(&list_url)?);
    }
    let _ = &mut root_set;
    plan.summary = format!("{} modules, {n_versions} module versions ({n_zips} with source zips)", listed.len());
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping() {
        assert_eq!(escape("github.com/Azure/azure-sdk"), "github.com/!azure/azure-sdk");
        assert_eq!(unescape("github.com/!azure/x").unwrap(), "github.com/Azure/x");
        assert!(unescape("bad!").is_none());
        assert!(unescape("Bad").is_none());
    }

    #[test]
    fn pseudo_versions() {
        assert!(is_pseudo("v0.0.0-20240101120000-abcdef123456"));
        assert!(is_pseudo("v1.2.4-0.20240101120000-abcdef123456"));
        assert!(is_pseudo("v1.2.3-pre.0.20240101120000-abcdef123456+incompatible"));
        assert!(!is_pseudo("v1.2.3"));
        assert!(!is_pseudo("v1.2.3-rc.1"));
    }

    #[test]
    fn go_mod_requires() {
        let m = "module example.com/m\n\ngo 1.22\n\nrequire golang.org/x/net v0.30.0 // indirect\nrequire (\n\tgolang.org/x/text v0.19.0\n\t\"example.com/q\" v1.0.0 // indirect\n)\nrequirement x v1\nreplace a => b v1.0.0\n";
        assert_eq!(
            requires(m),
            vec![
                ("golang.org/x/net".into(), "v0.30.0".into()),
                ("golang.org/x/text".into(), "v0.19.0".into()),
                ("example.com/q".into(), "v1.0.0".into()),
            ]
        );
    }

    #[test]
    fn hashes_match_go() {
        // The go.sum line every Go tutorial shows: rsc.io/quote v1.5.2/go.mod h1:LzX7…
        let gomod = b"module \"rsc.io/quote\"\n\nrequire \"rsc.io/sampler\" v1.3.0\n";
        assert_eq!(mod_h1(gomod), "h1:LzX7hefJvL54yjefDEDHNONDjII0t9xZLPXsUe+TKr0=");
        let s = read_go_sum("rsc.io/quote v1.5.2 h1:x\nrsc.io/quote v1.5.2/go.mod h1:y\n").unwrap();
        assert_eq!(s[&("rsc.io/quote".into(), "v1.5.2".into())], (Some("h1:x".into()), Some("h1:y".into())));
        assert!(read_go_sum("garbage").is_err());
    }
}
