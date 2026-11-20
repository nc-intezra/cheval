//! `format = "crates"`: a sparse cargo index (RFC 2789) and its crate files.
//!
//! Layout, as cargo requests it (so the mirror works under the upstream host names):
//! - `<index>/config.json`: `{"dl": …, "api": …}`, published verbatim and last;
//! - `<index>/<prefix>/<name>`: one JSON line per version (`1/a`, `2/ab`, `3/a/abc`,
//!   `se/rd/serde`), rewritten to list only the versions in the mirror;
//! - crate files at the `dl` location: `{dl}/{name}/{version}/download` unless `dl` holds
//!   `{crate}`/`{version}`/`{prefix}`/`{lowerprefix}`/`{sha256-checksum}` markers.
//!   Each is checked against the index's `cksum` (SHA-256).
//!
//! Selection: `packages` (`name` or `name@<version requirement>`) take the newest
//! non-yanked matching version and follow its dependencies (normal, build, optional and
//! target-specific, since cargo's resolver reads them all); `lockfiles` (`Cargo.lock`)
//! give exact versions and need no closure.
use crate::engine::{Ctx, Plan, PostCheck, Want, par};
use crate::util::{Checksum, HashAlgo};
use anyhow::{Context, Result, bail};
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use url::Url;

/// One version line of an index file.
#[derive(Debug, Clone, Deserialize)]
pub struct IndexLine {
    pub name: String,
    pub vers: String,
    #[serde(default)]
    pub deps: Vec<Dep>,
    pub cksum: String,
    #[serde(default)]
    pub yanked: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Dep {
    pub name: String,
    pub req: String,
    #[serde(default)]
    pub kind: Option<String>,
    /// The real crate name when the dependency is renamed.
    #[serde(default)]
    pub package: Option<String>,
    /// Another registry: not ours to follow.
    #[serde(default)]
    pub registry: Option<String>,
}

impl Dep {
    pub fn crate_name(&self) -> &str {
        self.package.as_deref().unwrap_or(&self.name)
    }
}

/// Index path of a crate, relative to the index root.
pub fn index_rel(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    match n.len() {
        1 => format!("1/{n}"),
        2 => format!("2/{n}"),
        3 => format!("3/{}/{n}", &n[..1]),
        _ => format!("{}/{}/{n}", &n[..2], &n[2..4]),
    }
}

/// The directory part of `index_rel`, as the `{prefix}` marker uses it.
fn prefix_of(name: &str) -> String {
    let rel = index_rel(name);
    rel.rsplit_once('/').map(|(p, _)| p.to_string()).unwrap_or_default()
}

/// Where cargo downloads a crate, given the index's `dl`.
pub fn download_url(dl: &str, name: &str, vers: &str, cksum: &str) -> Result<Url> {
    const MARKERS: [&str; 5] = ["{crate}", "{version}", "{prefix}", "{lowerprefix}", "{sha256-checksum}"];
    let s = if MARKERS.iter().any(|m| dl.contains(m)) {
        dl.replace("{crate}", name)
            .replace("{version}", vers)
            .replace("{lowerprefix}", &prefix_of(name).to_ascii_lowercase())
            .replace("{prefix}", &prefix_of(name))
            .replace("{sha256-checksum}", cksum)
    } else {
        format!("{}/{name}/{vers}/download", dl.trim_end_matches('/'))
    };
    Url::parse(&s).with_context(|| format!("download URL {s}"))
}

/// Parse an index file; lines that do not parse are kept out (with their count).
pub fn parse_index(data: &[u8]) -> (Vec<(String, IndexLine)>, usize) {
    let mut v = Vec::new();
    let mut bad = 0;
    for line in String::from_utf8_lossy(data).lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<IndexLine>(line) {
            Ok(l) => v.push((line.to_string(), l)),
            Err(_) => bad += 1,
        }
    }
    (v, bad)
}

/// `name` or `name@req`.
fn parse_package(s: &str) -> Result<(String, VersionReq, bool)> {
    let (name, req) = match s.split_once('@') {
        Some((n, r)) => (n.trim(), r.trim()),
        None => (s.trim(), "*"),
    };
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        bail!("crates: bad package {s:?} (expected name or name@version-requirement)");
    }
    let exact = req.starts_with('=');
    let req = VersionReq::parse(req).with_context(|| format!("crates: bad version requirement in {s:?}"))?;
    Ok((name.to_string(), req, exact))
}

#[derive(Deserialize)]
struct Lock {
    #[serde(default)]
    package: Vec<LockPkg>,
}
#[derive(Deserialize)]
struct LockPkg {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

/// crates.io packages pinned by a `Cargo.lock`: (name, version, checksum).
pub fn read_lock(text: &str) -> Result<Vec<(String, String, Option<String>)>> {
    let l: Lock = toml::from_str(text).context("not a Cargo.lock")?;
    Ok(l.package
        .into_iter()
        .filter(|p| {
            p.source.as_deref().is_some_and(|s| {
                s == "registry+https://github.com/rust-lang/crates.io-index" || s == "sparse+https://index.crates.io/"
            })
        })
        .map(|p| (p.name, p.version, p.checksum))
        .collect())
}

pub async fn plan(ctx: &Ctx<'_>) -> Result<Plan> {
    let repo = ctx.repo;
    let mut plan = Plan::default();
    let index = ctx.base.clone();

    // config.json: where crates are downloaded from.
    let cfg_url = index.join("config.json")?;
    let Some((cfg_staged, cfg_data)) = ctx.fetch(&cfg_url).await? else {
        bail!("{cfg_url} not found: is {} a sparse cargo index?", index);
    };
    let cfg: serde_json::Value = serde_json::from_slice(&cfg_data).with_context(|| format!("{cfg_url}"))?;
    let dl = cfg.get("dl").and_then(|v| v.as_str()).with_context(|| format!("{cfg_url}: no `dl`"))?.to_string();
    let downloads = repo.crate_downloads();
    let probe = download_url(&dl, "serde", "1.0.0", "0")?;
    if !probe.as_str().starts_with(&downloads) {
        bail!(
            "the index downloads crates from {dl}, outside `downloads` ({downloads}); set `downloads` to that \
             location so bundles and cleanup cover it"
        );
    }

    // Roots.
    let mut roots: Vec<(String, VersionReq, bool)> = Vec::new();
    for s in &repo.packages {
        roots.push(parse_package(s)?);
    }
    let mut pinned: Vec<(String, String, Option<String>)> = Vec::new();
    for l in &repo.lockfiles {
        let text = std::fs::read_to_string(l).with_context(|| format!("{}", l.display()))?;
        pinned.extend(read_lock(&text).with_context(|| format!("{}", l.display()))?);
    }

    // Index files, fetched as names come up.
    let mut files: HashMap<String, Option<Vec<(String, IndexLine)>>> = HashMap::new();
    let mut selected: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // (crate, requirement, is root, allow yanked)
    let mut queue: Vec<(String, VersionReq, bool, bool)> = roots.iter().map(|(n, r, e)| (n.clone(), r.clone(), true, *e)).collect();
    let mut want_names: Vec<String> = pinned.iter().map(|p| p.0.clone()).collect();
    want_names.extend(queue.iter().map(|q| q.0.clone()));
    let mut done_reqs: BTreeSet<(String, String)> = BTreeSet::new();
    let mut missing_deps = 0usize;

    loop {
        if ctx.cancelled() {
            bail!("cancelled");
        }
        // Fetch every index file not seen yet.
        let fetch: Vec<String> = {
            let mut v: Vec<String> = want_names.drain(..).map(|n| n.to_ascii_lowercase()).collect();
            v.sort();
            v.dedup();
            v.retain(|n| !files.contains_key(n));
            v
        };
        if !fetch.is_empty() {
            let got = par(fetch, ctx.parallel(), |n| {
                let index = index.clone();
                async move {
                    let url = index.join(&index_rel(&n))?;
                    let r = ctx.fetch(&url).await?;
                    Ok::<_, anyhow::Error>((n, r.map(|(_, d)| parse_index(&d).0)))
                }
            })
            .await;
            for r in got {
                let (n, lines) = r?;
                files.insert(n, lines);
            }
        }
        if queue.is_empty() {
            break;
        }
        let round = std::mem::take(&mut queue);
        for (name, req, root, allow_yanked) in round {
            if !done_reqs.insert((name.to_ascii_lowercase(), format!("{req}{root}"))) {
                continue;
            }
            let Some(Some(lines)) = files.get(&name.to_ascii_lowercase()) else {
                if root {
                    bail!("crate {name} is not in the index");
                }
                missing_deps += 1;
                continue;
            };
            let best = lines
                .iter()
                .filter(|(_, l)| allow_yanked || !l.yanked)
                .filter_map(|(_, l)| Version::parse(&l.vers).ok().map(|v| (v, l)))
                .filter(|(v, _)| req.matches(v))
                .max_by(|a, b| a.0.cmp(&b.0));
            let Some((_, line)) = best else {
                if root {
                    bail!("crate {name}: no version matches {req}");
                }
                ctx.warn(format!("crate {name}: no version matches {req} (dependency skipped)"));
                continue;
            };
            let set = selected.entry(line.name.to_ascii_lowercase()).or_default();
            if !set.insert(line.vers.clone()) {
                continue;
            }
            for d in &line.deps {
                if d.registry.is_some() {
                    continue;
                }
                let kind = d.kind.as_deref().unwrap_or("normal");
                if kind == "dev" && !(root && repo.dev_dependencies) {
                    continue;
                }
                let Ok(r) = VersionReq::parse(&d.req) else {
                    ctx.warn(format!("crate {} {}: dependency {} has an unreadable requirement {:?}", line.name, line.vers, d.name, d.req));
                    continue;
                };
                want_names.push(d.crate_name().to_string());
                queue.push((d.crate_name().to_string(), r, false, false));
            }
        }
    }

    for (name, vers, sum) in &pinned {
        let Some(Some(lines)) = files.get(&name.to_ascii_lowercase()) else {
            bail!("crate {name} (from a lock file) is not in the index");
        };
        let Some((_, l)) = lines.iter().find(|(_, l)| &l.vers == vers) else {
            bail!("crate {name} {vers} (from a lock file) is not in the index");
        };
        if let Some(s) = sum
            && !s.eq_ignore_ascii_case(&l.cksum)
        {
            bail!("crate {name} {vers}: the lock file's checksum differs from the index's");
        }
        selected.entry(name.to_ascii_lowercase()).or_default().insert(vers.clone());
    }

    // Every index file seen: keep selected versions and versions already mirrored.
    let mut crates = 0usize;
    let mut versions = 0usize;
    let mut names: Vec<&String> = files.keys().collect();
    names.sort();
    for name in names {
        let Some(lines) = &files[name] else { continue };
        let sel = selected.get(name);
        let mut keep: Vec<&str> = Vec::new();
        for (raw, l) in lines {
            let url = download_url(&dl, &l.name, &l.vers, &l.cksum)?;
            let dest = ctx.local(&url)?;
            let chosen = sel.is_some_and(|s| s.contains(&l.vers));
            if !chosen && !dest.is_file() {
                continue;
            }
            if l.cksum.len() != 64 || !l.cksum.chars().all(|c| c.is_ascii_hexdigit()) {
                ctx.warn(format!("crate {} {}: bad cksum in the index (skipped)", l.name, l.vers));
                continue;
            }
            keep.push(raw);
            versions += 1;
            plan.want(Want {
                url,
                dest,
                size: None,
                sum: Some(Checksum { algo: HashAlgo::Sha256, hex: l.cksum.to_ascii_lowercase() }),
                post: PostCheck::None,
                label: format!("{}-{}.crate", l.name, l.vers),
            });
        }
        if keep.is_empty() {
            continue;
        }
        crates += 1;
        let mut text = keep.join("\n");
        text.push('\n');
        let rel = index_rel(name);
        let staged = ctx.stage_bytes(name, text.as_bytes())?;
        plan.publish(staged, ctx.local(&index.join(&rel)?)?);
    }
    plan.publish(cfg_staged, ctx.local(&cfg_url)?);
    plan.summary = format!(
        "{crates} crates, {versions} versions in the mirror's index{}",
        if missing_deps > 0 { format!(" ({missing_deps} dependencies not in the index)") } else { String::new() }
    );
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_paths() {
        assert_eq!(index_rel("a"), "1/a");
        assert_eq!(index_rel("ab"), "2/ab");
        assert_eq!(index_rel("abc"), "3/a/abc");
        assert_eq!(index_rel("Serde"), "se/rd/serde");
        assert_eq!(index_rel("cargo"), "ca/rg/cargo");
    }

    #[test]
    fn download_urls() {
        let u = download_url("https://static.crates.io/crates", "serde", "1.0.0", "x").unwrap();
        assert_eq!(u.as_str(), "https://static.crates.io/crates/serde/1.0.0/download");
        let u = download_url("https://h/c/{prefix}/{crate}/{crate}-{version}.crate", "Serde", "1.0.0", "x").unwrap();
        assert_eq!(u.as_str(), "https://h/c/se/rd/Serde/Serde-1.0.0.crate");
        let u = download_url("https://h/{lowerprefix}/{sha256-checksum}", "AB", "1", "ff").unwrap();
        assert_eq!(u.as_str(), "https://h/2/ff");
    }

    #[test]
    fn packages_and_locks() {
        assert_eq!(parse_package("tokio@1.40").unwrap().0, "tokio");
        assert!(parse_package("tokio@1.40").unwrap().1.matches(&Version::parse("1.41.0").unwrap()));
        assert!(parse_package("x@=1.0.0").unwrap().2);
        assert!(parse_package("bad name").is_err());
        let lock = r#"
version = 4
[[package]]
name = "mine"
version = "0.1.0"
[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"
[[package]]
name = "gitdep"
version = "0.1.0"
source = "git+https://example.com/x#abc"
"#;
        let l = read_lock(lock).unwrap();
        assert_eq!(l, vec![("serde".into(), "1.0.210".into(), Some("abc".into()))]);
    }

    #[test]
    fn index_lines() {
        let data = br#"{"name":"a","vers":"1.0.0","deps":[{"name":"b2","package":"b","req":"^1","kind":"normal","optional":false}],"cksum":"00","features":{},"yanked":false}
not json
{"name":"a","vers":"1.1.0","deps":[],"cksum":"11","features":{},"yanked":true,"v":2,"features2":{}}
"#;
        let (v, bad) = parse_index(data);
        assert_eq!((v.len(), bad), (2, 1));
        assert_eq!(v[0].1.deps[0].crate_name(), "b");
        assert!(v[1].1.yanked);
    }
}
