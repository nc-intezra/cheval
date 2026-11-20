//! `format = "maven"`: a Maven 2 layout repository (`repo.maven.apache.org/maven2`).
//!
//! Per artifact version, under `group/as/path/artifact/version/`: the POM, the artifact file
//! (`.jar`, `.war`, … or nothing for `pom` packaging), and their `.sha1` files, which are
//! checked against what is downloaded. Parent POMs and imported BOMs come along, as Maven
//! needs them to read a POM. Gradle module files (`.module`) are mirrored when a POM says
//! it was published with them. Per artifact: `maven-metadata.xml` listing the mirrored
//! versions (Maven reads it for `LATEST`, `RELEASE` and version ranges).
//!
//! Selection: `packages` are coordinates (`group:artifact:version`, with packaging and
//! classifier as `group:artifact:packaging[:classifier]:version`; `latest` as the version
//! takes the newest release) and follow compile and runtime dependencies, honouring
//! exclusions, optional flags and dependency management. `lockfiles` are the output of
//! `mvn dependency:list` (or `dependency:resolve-plugins`): exact artifacts, no closure.
use crate::engine::{Ctx, Plan, PostCheck, Want, par};
use crate::util::{Checksum, HashAlgo};
use anyhow::{Context, Result, bail};
use quick_xml::events::Event;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use url::Url;

/// group, artifact, version.
pub type Gav = (String, String, String);

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PomDep {
    pub group: String,
    pub artifact: String,
    pub version: Option<String>,
    pub typ: Option<String>,
    pub classifier: Option<String>,
    pub scope: Option<String>,
    pub optional: bool,
    pub exclusions: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct Pom {
    pub group: Option<String>,
    pub artifact: String,
    pub version: Option<String>,
    pub packaging: Option<String>,
    pub parent: Option<Gav>,
    pub props: BTreeMap<String, String>,
    pub managed: Vec<PomDep>,
    pub deps: Vec<PomDep>,
    pub gradle: bool,
}

/// Read the parts of a POM that dependency resolution needs (profiles are not applied).
pub fn parse_pom(xml: &[u8]) -> Result<Pom> {
    let mut r = quick_xml::Reader::from_reader(xml);
    let mut pom =
        Pom { gradle: String::from_utf8_lossy(xml).contains("published-with-gradle-metadata"), ..Default::default() };
    let mut path: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut dep = PomDep::default();
    let mut excl = (String::new(), String::new());
    let mut parent = (String::new(), String::new(), String::new());
    let mut buf = Vec::new();
    loop {
        match r.read_event_into(&mut buf).context("POM is not well-formed XML")? {
            Event::Start(e) => {
                let ln = e.local_name();
                let n: &str = ln.as_ref();
                path.push(n.to_string());
                text.clear();
            }
            Event::Text(t) => text.push_str(&t.xml10_content()),
            Event::CData(t) => text.push_str(&t[..]),
            Event::GeneralRef(g) => {
                let name: &str = &g[..];
                text.push_str(match name {
                    "lt" => "<",
                    "gt" => ">",
                    "amp" => "&",
                    "quot" => "\"",
                    "apos" => "'",
                    _ => "",
                });
            }
            Event::End(_) => {
                let p: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
                let v = text.trim().to_string();
                let in_dep = |base: &[&str]| p.len() > base.len() && p[..base.len()] == *base;
                const DM: [&str; 4] = ["project", "dependencyManagement", "dependencies", "dependency"];
                const DS: [&str; 3] = ["project", "dependencies", "dependency"];
                match p.as_slice() {
                    ["project", "groupId"] => pom.group = Some(v),
                    ["project", "artifactId"] => pom.artifact = v,
                    ["project", "version"] => pom.version = Some(v),
                    ["project", "packaging"] => pom.packaging = Some(v),
                    ["project", "parent", "groupId"] => parent.0 = v,
                    ["project", "parent", "artifactId"] => parent.1 = v,
                    ["project", "parent", "version"] => parent.2 = v,
                    ["project", "parent"] => pom.parent = Some(std::mem::take(&mut parent)),
                    ["project", "properties", k] => {
                        pom.props.insert(k.to_string(), v);
                    }
                    _ if p == DM || p == DS => {
                        let d = std::mem::take(&mut dep);
                        if p == DM { pom.managed.push(d) } else { pom.deps.push(d) }
                    }
                    _ if in_dep(&DM) || in_dep(&DS) => {
                        let rest = &p[if in_dep(&DM) { 4 } else { 3 }..];
                        match rest {
                            ["groupId"] => dep.group = v,
                            ["artifactId"] => dep.artifact = v,
                            ["version"] => dep.version = Some(v),
                            ["type"] => dep.typ = Some(v),
                            ["classifier"] => dep.classifier = Some(v),
                            ["scope"] => dep.scope = Some(v),
                            ["optional"] => dep.optional = v == "true",
                            ["exclusions", "exclusion", "groupId"] => excl.0 = v,
                            ["exclusions", "exclusion", "artifactId"] => excl.1 = v,
                            ["exclusions", "exclusion"] => dep.exclusions.push(std::mem::take(&mut excl)),
                            _ => {}
                        }
                    }
                    _ => {}
                }
                path.pop();
                text.clear();
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    if pom.artifact.is_empty() {
        bail!("not a POM (no project/artifactId)");
    }
    Ok(pom)
}

/// A POM with its parents and imported BOMs applied.
#[derive(Debug, Clone, Default)]
pub struct Effective {
    pub gav: Gav,
    pub packaging: String,
    pub props: BTreeMap<String, String>,
    /// (group, artifact, type, classifier) → dependency management entry.
    pub managed: BTreeMap<(String, String, String, String), PomDep>,
    pub deps: Vec<PomDep>,
}

fn interpolate(s: &str, props: &BTreeMap<String, String>) -> String {
    let mut cur = s.to_string();
    for _ in 0..10 {
        let Some(start) = cur.find("${") else { break };
        let Some(len) = cur[start..].find('}') else { break };
        let key = &cur[start + 2..start + len];
        let Some(val) = props.get(key) else { break };
        cur = format!("{}{val}{}", &cur[..start], &cur[start + len + 1..]);
    }
    cur
}

fn dep_key(d: &PomDep) -> (String, String, String, String) {
    (
        d.group.clone(),
        d.artifact.clone(),
        d.typ.clone().unwrap_or_else(|| "jar".into()),
        d.classifier.clone().unwrap_or_default(),
    )
}

fn interp_dep(d: &PomDep, props: &BTreeMap<String, String>) -> PomDep {
    let i = |s: &Option<String>| s.as_ref().map(|v| interpolate(v, props));
    PomDep {
        group: interpolate(&d.group, props),
        artifact: interpolate(&d.artifact, props),
        version: i(&d.version),
        typ: i(&d.typ),
        classifier: i(&d.classifier),
        scope: i(&d.scope),
        optional: d.optional,
        exclusions: d.exclusions.iter().map(|(g, a)| (interpolate(g, props), interpolate(a, props))).collect(),
    }
}

/// Path of a file of an artifact version, relative to the repository root.
pub fn file_rel(gav: &Gav, classifier: Option<&str>, ext: &str) -> String {
    let (g, a, v) = gav;
    let c = classifier.filter(|c| !c.is_empty()).map(|c| format!("-{c}")).unwrap_or_default();
    format!("{}/{a}/{v}/{a}-{v}{c}.{ext}", g.replace('.', "/"))
}

/// The file extension (and implied classifier) of a dependency type or packaging.
pub fn type_ext(typ: &str) -> (&str, Option<&str>) {
    match typ {
        "jar" | "bundle" | "maven-plugin" | "ejb" | "orbit" | "eclipse-plugin" | "hk2-jar" | "takari-jar" => {
            ("jar", None)
        }
        "test-jar" => ("jar", Some("tests")),
        "ejb-client" => ("jar", Some("client")),
        "java-source" => ("jar", Some("sources")),
        "javadoc" => ("jar", Some("javadoc")),
        other => (other, None),
    }
}

/// Maven's version order, close enough for picking the newest release.
pub fn ver_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    fn parts(s: &str) -> Vec<(u8, u64, String)> {
        let mut out = Vec::new();
        // Each '-' starts a sub-list whose trailing zeros (and "final"/"ga") do not count.
        for seg in s.to_ascii_lowercase().split('-') {
            let mut items = Vec::new();
            for tok in seg.split(['.', '_']) {
                if tok.is_empty() {
                    continue;
                }
                let i = tok.find(|c: char| !c.is_ascii_digit()).unwrap_or(tok.len());
                let (num, rest) = (&tok[..i], &tok[i..]);
                if !num.is_empty() {
                    items.push((2, num.parse().unwrap_or(u64::MAX), String::new()));
                }
                if !rest.is_empty() {
                    let rank = match rest {
                        "alpha" | "a" => 0,
                        "beta" | "b" => 1,
                        "milestone" | "m" => 2,
                        "rc" | "cr" => 3,
                        "snapshot" => 4,
                        "ga" | "final" | "release" => 5,
                        "sp" => 6,
                        _ => 1,
                    };
                    items.push((0, rank, rest.to_string()));
                }
            }
            while items.last().is_some_and(|p: &(u8, u64, String)| (p.0 == 2 && p.1 == 0) || (p.0 == 0 && p.1 == 5)) {
                items.pop();
            }
            out.extend(items);
        }
        out
    }
    let (x, y) = (parts(a), parts(b));
    for i in 0..x.len().max(y.len()) {
        let o = match (x.get(i), y.get(i)) {
            (Some(p), Some(q)) => match (p.0, q.0) {
                (2, 2) => p.1.cmp(&q.1),
                (2, _) => std::cmp::Ordering::Greater,
                (_, 2) => std::cmp::Ordering::Less,
                _ => p.1.cmp(&q.1).then_with(|| p.2.cmp(&q.2)),
            },
            // 1.0 < 1.0.1, but 1.0-rc1 < 1.0.
            (Some(p), None) => {
                if p.0 == 2 || p.1 >= 5 {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Less
                }
            }
            (None, Some(q)) => {
                if q.0 == 2 || q.1 >= 5 {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                }
            }
            (None, None) => std::cmp::Ordering::Equal,
        };
        if o.is_ne() {
            return o;
        }
    }
    std::cmp::Ordering::Equal
}

/// Versions listed in a `maven-metadata.xml`.
pub fn metadata_versions(xml: &[u8]) -> (Vec<String>, Option<String>) {
    let mut r = quick_xml::Reader::from_reader(xml);
    let mut buf = Vec::new();
    let (mut path, mut text, mut vs, mut release) = (Vec::<String>::new(), String::new(), Vec::new(), None);
    loop {
        match r.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let ln = e.local_name();
                let n: &str = ln.as_ref();
                path.push(n.to_string());
                text.clear();
            }
            Ok(Event::Text(t)) => text.push_str(&t.xml10_content()),
            Ok(Event::End(_)) => {
                match path.iter().map(|s| s.as_str()).collect::<Vec<_>>().as_slice() {
                    ["metadata", "versioning", "versions", "version"] => vs.push(text.trim().to_string()),
                    ["metadata", "versioning", "release"] => release = Some(text.trim().to_string()),
                    _ => {}
                }
                path.pop();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    (vs, release)
}

/// One requested artifact.
#[derive(Debug, Clone, PartialEq)]
pub struct Coord {
    pub gav: Gav,
    /// None: from the POM's packaging.
    pub typ: Option<String>,
    pub classifier: Option<String>,
}

const SCOPES: [&str; 6] = ["compile", "runtime", "test", "provided", "system", "import"];

/// `group:artifact[:packaging[:classifier]]:version`.
pub fn parse_coord(s: &str) -> Result<Coord> {
    let f: Vec<&str> = s.trim().split(':').map(|x| x.trim()).collect();
    if f.iter().any(|x| x.is_empty()) {
        bail!("maven: bad coordinate {s:?}");
    }
    let c = |g: &str, a: &str, v: &str, t: Option<&str>, cl: Option<&str>| Coord {
        gav: (g.into(), a.into(), v.into()),
        typ: t.map(String::from),
        classifier: cl.map(String::from),
    };
    Ok(match f.as_slice() {
        [g, a, v] => c(g, a, v, None, None),
        [g, a, t, v] => c(g, a, v, Some(t), None),
        [g, a, t, cl, v] => c(g, a, v, Some(t), Some(cl)),
        _ => bail!("maven: bad coordinate {s:?} (expected group:artifact[:packaging[:classifier]]:version)"),
    })
}

/// Artifacts in `mvn dependency:list` / `dependency:resolve-plugins` output.
pub fn read_dependency_list(text: &str) -> Vec<Coord> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim_start_matches("[INFO]").trim();
        let line = line.split(" -- ").next().unwrap_or("").trim();
        let line = line.split_whitespace().next().unwrap_or("");
        let mut f: Vec<&str> = line.split(':').collect();
        if f.len() < 4 || f.len() > 6 || f.iter().any(|x| x.is_empty() || x.contains('/')) {
            continue;
        }
        if f.len() >= 5 && SCOPES.contains(f.last().unwrap()) {
            f.pop();
        }
        let typ = f[2].to_string();
        let (cl, v) = match f.len() {
            4 => (None, f[3]),
            5 => (Some(f[3].to_string()), f[4]),
            _ => continue,
        };
        if !v.chars().next().is_some_and(|c| c.is_ascii_alphanumeric()) {
            continue;
        }
        out.push(Coord { gav: (f[0].into(), f[1].into(), v.into()), typ: Some(typ), classifier: cl });
    }
    out
}

/// A coordinate to resolve, the exclusions inherited on the way to it, and whether to
/// follow its dependencies.
type Queued = (Coord, Vec<(String, String)>, bool);

type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// POMs read this run, shared by parallel resolutions.
#[derive(Default)]
struct Store {
    eff: Mutex<BTreeMap<Gav, Arc<Effective>>>,
    plan: Mutex<Plan>,
    /// Artifact versions this run touches: (group, artifact) → versions.
    versions: Mutex<BTreeMap<(String, String), BTreeSet<String>>>,
}

fn url(ctx: &Ctx<'_>, rel: &str) -> Result<Url> {
    Ok(ctx.base.join(rel)?)
}

/// Fetch an immutable file and its `.sha1`, check one against the other, and schedule
/// both for publishing. `Ok(None)` when upstream does not have the file.
async fn checked(ctx: &Ctx<'_>, store: &Store, rel: &str) -> Result<Option<Vec<u8>>> {
    let u = url(ctx, rel)?;
    let Some((data, staged)) = ctx.immutable(&u).await? else { return Ok(None) };
    let su = url(ctx, &format!("{rel}.sha1"))?;
    let sha = ctx.immutable(&su).await?;
    if let Some((s, _)) = &sha {
        let want = String::from_utf8_lossy(s).split_whitespace().next().unwrap_or("").to_ascii_lowercase();
        let got = crate::util::Hasher::new(HashAlgo::Sha1);
        let mut h = got;
        h.update(&data);
        let got = h.finish();
        if want.len() == 40 && want != got {
            bail!("{rel}: SHA-1 {got} does not match the published {want}");
        }
    }
    let mut plan = store.plan.lock().unwrap();
    if let Some(p) = staged {
        plan.publish(p, ctx.local(&u)?);
    }
    if let Some((_, Some(p))) = sha {
        plan.publish(p, ctx.local(&su)?);
    }
    Ok(Some(data))
}

/// The effective model of a POM: parents and imports first.
fn effective<'a>(ctx: &'a Ctx<'a>, store: &'a Store, gav: Gav, depth: u8) -> Fut<'a, Result<Arc<Effective>>> {
    Box::pin(async move {
        if let Some(e) = store.eff.lock().unwrap().get(&gav) {
            return Ok(e.clone());
        }
        if depth > 30 {
            bail!("{}:{}:{}: parent or import chain too deep", gav.0, gav.1, gav.2);
        }
        let rel = file_rel(&gav, None, "pom");
        let Some(data) = checked(ctx, store, &rel).await? else {
            bail!("{}:{}:{}: POM not found ({rel})", gav.0, gav.1, gav.2);
        };
        let pom = parse_pom(&data).with_context(|| rel.clone())?;
        if pom.gradle {
            for f in [file_rel(&gav, None, "module")] {
                let _ = checked(ctx, store, &f).await?;
            }
        }
        store.versions.lock().unwrap().entry((gav.0.clone(), gav.1.clone())).or_default().insert(gav.2.clone());
        let mut eff = Effective { gav: gav.clone(), ..Default::default() };
        if let Some(p) = &pom.parent {
            let pe = effective(ctx, store, p.clone(), depth + 1).await?;
            eff.props = pe.props.clone();
            eff.managed = pe.managed.clone();
            eff.deps = pe.deps.clone();
            eff.props.insert("project.parent.version".into(), p.2.clone());
            eff.props.insert("project.parent.groupId".into(), p.0.clone());
        }
        eff.props.extend(pom.props.clone());
        for (k, v) in [
            ("project.groupId", &gav.0),
            ("pom.groupId", &gav.0),
            ("groupId", &gav.0),
            ("project.artifactId", &gav.1),
            ("project.version", &gav.2),
            ("pom.version", &gav.2),
            ("version", &gav.2),
        ] {
            eff.props.insert(k.into(), v.clone());
        }
        eff.packaging = interpolate(pom.packaging.as_deref().unwrap_or("jar"), &eff.props);
        let props = eff.props.clone();
        // Direct management overrides inherited; imports fill only what is not managed yet.
        let mut imports = Vec::new();
        for d in &pom.managed {
            let d = interp_dep(d, &props);
            if d.scope.as_deref() == Some("import") && d.typ.as_deref() == Some("pom") {
                imports.push(d);
            } else {
                eff.managed.insert(dep_key(&d), d);
            }
        }
        for d in imports {
            let Some(v) = d.version.clone().filter(|v| !v.contains("${")) else {
                ctx.warn(format!("{rel}: imported BOM {}:{} has no usable version", d.group, d.artifact));
                continue;
            };
            let be = effective(ctx, store, (d.group.clone(), d.artifact.clone(), v), depth + 1).await?;
            for (k, m) in &be.managed {
                eff.managed.entry(k.clone()).or_insert_with(|| m.clone());
            }
        }
        for d in &pom.deps {
            let d = interp_dep(d, &props);
            eff.deps.retain(|x| dep_key(x) != dep_key(&d));
            eff.deps.push(d);
        }
        // Fill versions and scopes from management.
        for d in &mut eff.deps {
            if let Some(m) = eff.managed.get(&dep_key(d)) {
                if d.version.is_none() {
                    d.version = m.version.clone();
                }
                if d.scope.is_none() {
                    d.scope = m.scope.clone();
                }
                if d.exclusions.is_empty() {
                    d.exclusions = m.exclusions.clone();
                }
            }
        }
        let eff = Arc::new(eff);
        store.eff.lock().unwrap().insert(gav, eff.clone());
        Ok(eff)
    })
}

/// The newest release of an artifact, from its upstream `maven-metadata.xml`.
async fn latest(ctx: &Ctx<'_>, g: &str, a: &str) -> Result<String> {
    let u = url(ctx, &format!("{}/{a}/maven-metadata.xml", g.replace('.', "/")))?;
    let Some((_, data)) = ctx.fetch(&u).await? else { bail!("maven: {g}:{a} not found ({u})") };
    let (vs, release) = metadata_versions(&data);
    release
        .or_else(|| vs.into_iter().filter(|v| !v.ends_with("-SNAPSHOT")).max_by(|a, b| ver_cmp(a, b)))
        .with_context(|| format!("maven: {u} lists no release"))
}

fn excluded(ex: &[(String, String)], g: &str, a: &str) -> bool {
    ex.iter().any(|(eg, ea)| (eg == "*" || eg == g) && (ea == "*" || ea == a))
}

pub async fn plan(ctx: &Ctx<'_>) -> Result<Plan> {
    let repo = ctx.repo;
    let store = Store::default();
    let mut queue: Vec<Queued> = Vec::new();
    for s in &repo.packages {
        let mut c = parse_coord(s)?;
        if c.gav.2.eq_ignore_ascii_case("latest") {
            c.gav.2 = latest(ctx, &c.gav.0, &c.gav.1).await?;
        }
        queue.push((c, Vec::new(), true));
    }
    for l in &repo.lockfiles {
        let text = std::fs::read_to_string(l).with_context(|| format!("{}", l.display()))?;
        let list = read_dependency_list(&text);
        if list.is_empty() {
            bail!("{}: no artifacts found (expected `mvn dependency:list` output)", l.display());
        }
        queue.extend(list.into_iter().map(|c| (c, Vec::new(), false)));
    }

    let mut seen: BTreeSet<(Gav, String, String)> = BTreeSet::new();
    let mut artifacts: Vec<(Gav, Option<String>, String)> = Vec::new();
    let mut plugin_groups: BTreeSet<String> = BTreeSet::new();
    let mut skipped = 0usize;
    let roots: BTreeSet<Gav> = queue.iter().map(|q| q.0.gav.clone()).collect();
    while !queue.is_empty() {
        if ctx.cancelled() {
            bail!("cancelled");
        }
        let batch: Vec<_> = std::mem::take(&mut queue)
            .into_iter()
            .filter(|(c, _, _)| {
                seen.insert((
                    c.gav.clone(),
                    c.typ.clone().unwrap_or_default(),
                    c.classifier.clone().unwrap_or_default(),
                ))
            })
            .collect();
        let store = &store;
        let got = par(batch, ctx.parallel(), |(c, ex, follow)| async move {
            let r = effective(ctx, store, c.gav.clone(), 0).await;
            (c, ex, follow, r)
        })
        .await;
        for (c, ex, follow, r) in got {
            let eff = match r {
                Ok(e) => e,
                Err(e) if !roots.contains(&c.gav) => {
                    ctx.warn(format!("{e:#} (dependency skipped)"));
                    skipped += 1;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let typ = c.typ.clone().unwrap_or_else(|| eff.packaging.clone());
            if typ == "maven-plugin" || eff.packaging == "maven-plugin" {
                plugin_groups.insert(c.gav.0.clone());
            }
            if typ != "pom" && !(c.typ.is_none() && eff.packaging == "pom") {
                let (ext, implied) = type_ext(&typ);
                let cl = c.classifier.clone().or(implied.map(String::from));
                artifacts.push((c.gav.clone(), cl, ext.to_string()));
            }
            if !follow {
                continue;
            }
            for d in &eff.deps {
                let scope = d.scope.as_deref().unwrap_or("compile");
                if d.optional || !matches!(scope, "compile" | "runtime") || excluded(&ex, &d.group, &d.artifact) {
                    continue;
                }
                let Some(v) = d.version.clone() else {
                    ctx.warn(format!(
                        "{}:{}:{}: dependency {}:{} has no version",
                        c.gav.0, c.gav.1, c.gav.2, d.group, d.artifact
                    ));
                    continue;
                };
                if v.contains("${") || v.starts_with('[') || v.starts_with('(') {
                    ctx.warn(format!(
                        "{}:{}:{}: dependency {}:{} version {v} is a range or unresolved property (add it to packages)",
                        c.gav.0, c.gav.1, c.gav.2, d.group, d.artifact
                    ));
                    continue;
                }
                let mut ex2 = ex.clone();
                ex2.extend(d.exclusions.iter().cloned());
                queue.push((
                    Coord {
                        gav: (d.group.clone(), d.artifact.clone(), v),
                        typ: d.typ.clone().or(Some("jar".into())),
                        classifier: d.classifier.clone(),
                    },
                    ex2,
                    true,
                ));
            }
        }
    }

    // Artifact files: .sha1 first (fetched now), the file itself downloaded and checked.
    let n_art = artifacts.len();
    let sums = par(artifacts, ctx.parallel(), |(gav, cl, ext)| {
        let store = &store;
        async move {
            let rel = file_rel(&gav, cl.as_deref(), &ext);
            let su = url(ctx, &format!("{rel}.sha1"))?;
            let sha = ctx.immutable(&su).await?;
            let mut sum = None;
            if let Some((s, staged)) = sha {
                let hex = String::from_utf8_lossy(&s).split_whitespace().next().unwrap_or("").to_ascii_lowercase();
                if hex.len() == 40 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    sum = Some(Checksum { algo: HashAlgo::Sha1, hex });
                }
                if let Some(p) = staged {
                    store.plan.lock().unwrap().publish(p, ctx.local(&su)?);
                }
            }
            Ok::<_, anyhow::Error>((rel, sum))
        }
    })
    .await;
    let mut plan = std::mem::take(&mut *store.plan.lock().unwrap());
    for r in sums {
        let (rel, sum) = r?;
        if sum.is_none() {
            ctx.warn(format!("{rel}: no .sha1 upstream; downloaded unchecked"));
        }
        let u = url(ctx, &rel)?;
        plan.want(Want { dest: ctx.local(&u)?, url: u, size: None, sum, post: PostCheck::None, label: rel });
    }

    // maven-metadata.xml per artifact: the versions in the mirror.
    let versions = std::mem::take(&mut *store.versions.lock().unwrap());
    for ((g, a), vs) in &versions {
        let rel = format!("{}/{a}/maven-metadata.xml", g.replace('.', "/"));
        let fin = ctx.local(&url(ctx, &rel)?)?;
        let mut all: BTreeSet<String> = vs.clone();
        if let Some(dir) = fin.parent()
            && let Ok(rd) = std::fs::read_dir(dir)
        {
            for e in rd.flatten() {
                let v = e.file_name().to_string_lossy().into_owned();
                if e.path().join(format!("{a}-{v}.pom")).is_file() {
                    all.insert(v);
                }
            }
        }
        let mut list: Vec<String> = all.into_iter().collect();
        list.sort_by(|x, y| ver_cmp(x, y));
        if let Ok(old) = std::fs::read(&fin)
            && metadata_versions(&old).0 == list
        {
            continue;
        }
        let xml = metadata_xml(g, a, &list);
        let staged = ctx.stage_bytes("maven-metadata.xml", xml.as_bytes())?;
        let mut h = crate::util::Hasher::new(HashAlgo::Sha1);
        h.update(xml.as_bytes());
        let sha_staged = ctx.stage_bytes("maven-metadata.xml.sha1", h.finish().as_bytes())?;
        plan.publish(sha_staged, ctx.local(&url(ctx, &format!("{rel}.sha1"))?)?);
        plan.publish(staged, fin);
    }
    // Plugin prefixes (`mvn compiler:compile`) come from the group's metadata, verbatim.
    for g in &plugin_groups {
        let rel = format!("{}/maven-metadata.xml", g.replace('.', "/"));
        let u = url(ctx, &rel)?;
        if let Some((p, _)) = ctx.fetch(&u).await? {
            plan.publish(p, ctx.local(&u)?);
            let su = url(ctx, &format!("{rel}.sha1"))?;
            if let Some((sp, _)) = ctx.fetch(&su).await? {
                plan.publish(sp, ctx.local(&su)?);
            }
        }
    }
    plan.summary = format!(
        "{} artifact versions, {n_art} artifact files{}",
        versions.values().map(|v| v.len()).sum::<usize>(),
        if skipped > 0 { format!(" ({skipped} dependencies could not be read)") } else { String::new() }
    );
    Ok(plan)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

pub fn metadata_xml(g: &str, a: &str, versions: &[String]) -> String {
    let release = versions.iter().rev().find(|v| !v.ends_with("-SNAPSHOT"));
    let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata>\n");
    s += &format!(
        "  <groupId>{}</groupId>\n  <artifactId>{}</artifactId>\n  <versioning>\n",
        xml_escape(g),
        xml_escape(a)
    );
    if let Some(l) = versions.last() {
        s += &format!("    <latest>{}</latest>\n", xml_escape(l));
    }
    if let Some(r) = release {
        s += &format!("    <release>{}</release>\n", xml_escape(r));
    }
    s += "    <versions>\n";
    for v in versions {
        s += &format!("      <version>{}</version>\n", xml_escape(v));
    }
    s += "    </versions>\n";
    s += &format!("    <lastUpdated>{}</lastUpdated>\n", chrono_now());
    s += "  </versioning>\n</metadata>\n";
    s
}

fn chrono_now() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    // Civil date from days since 1970 (Howard Hinnant's algorithm).
    let (days, rem) = ((secs / 86400) as i64, secs % 86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}{m:02}{d:02}{:02}{:02}{:02}", rem / 3600, rem / 60 % 60, rem % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinates() {
        let c = parse_coord("org.slf4j:slf4j-api:2.0.13").unwrap();
        assert_eq!(c.gav, ("org.slf4j".into(), "slf4j-api".into(), "2.0.13".into()));
        assert_eq!(c.typ, None);
        let c = parse_coord("g:a:jar:sources:1").unwrap();
        assert_eq!((c.typ.as_deref(), c.classifier.as_deref()), (Some("jar"), Some("sources")));
        assert!(parse_coord("g:a").is_err());
        assert_eq!(
            file_rel(&("org.slf4j".into(), "slf4j-api".into(), "2.0.13".into()), None, "jar"),
            "org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.jar"
        );
        assert_eq!(file_rel(&("g".into(), "a".into(), "1".into()), Some("tests"), "jar"), "g/a/1/a-1-tests.jar");
    }

    #[test]
    fn dependency_list_output() {
        let out = "[INFO] --- dependency:3.7.0:list (default-cli) @ demo ---\n\
[INFO] \n\
[INFO] The following files have been resolved:\n\
[INFO]    org.slf4j:slf4j-api:jar:2.0.13:compile -- module org.slf4j [auto]\n\
[INFO]    io.netty:netty-transport-native-epoll:jar:linux-x86_64:4.1.111.Final:runtime\n\
[INFO]    junit:junit:jar:4.13.2:test (optional)\n\
[INFO]    org.apache.maven.plugins:maven-clean-plugin:maven-plugin:3.2.0:runtime\n\
[INFO]       org.codehaus.plexus:plexus-utils:jar:3.5.1\n\
[INFO] BUILD SUCCESS\n";
        let l = read_dependency_list(out);
        assert_eq!(l.len(), 5);
        assert_eq!(l[1].classifier.as_deref(), Some("linux-x86_64"));
        assert_eq!(l[1].gav.2, "4.1.111.Final");
        assert_eq!(l[3].typ.as_deref(), Some("maven-plugin"));
        assert_eq!(l[4].gav.1, "plexus-utils");
    }

    #[test]
    fn version_order() {
        use std::cmp::Ordering::*;
        assert_eq!(ver_cmp("1.0", "1.0.0"), Equal);
        assert_eq!(ver_cmp("1.10", "1.9"), Greater);
        assert_eq!(ver_cmp("1.0-rc1", "1.0"), Less);
        assert_eq!(ver_cmp("1.0-alpha", "1.0-beta"), Less);
        assert_eq!(ver_cmp("2.0.0-SNAPSHOT", "2.0.0"), Less);
        assert_eq!(ver_cmp("4.1.111.Final", "4.1.110.Final"), Greater);
        assert_eq!(ver_cmp("1.0.1", "1.0"), Greater);
    }

    #[test]
    fn poms() {
        let xml = br#"<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <!-- do_not_remove: published-with-gradle-metadata -->
  <parent><groupId>p.g</groupId><artifactId>parent</artifactId><version>3</version></parent>
  <artifactId>child</artifactId>
  <packaging>bundle</packaging>
  <properties><dep.version>1.2</dep.version><x>a&amp;b</x></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>b.g</groupId><artifactId>bom</artifactId><version>9</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>d.g</groupId><artifactId>d</artifactId><version>${dep.version}</version>
      <exclusions><exclusion><groupId>*</groupId><artifactId>bad</artifactId></exclusion></exclusions></dependency>
    <dependency><groupId>t.g</groupId><artifactId>t</artifactId><scope>test</scope><optional>true</optional></dependency>
  </dependencies>
  <profiles><profile><dependencies><dependency><groupId>no</groupId><artifactId>no</artifactId></dependency></dependencies></profile></profiles>
</project>"#;
        let p = parse_pom(xml).unwrap();
        assert!(p.gradle);
        assert_eq!(p.parent, Some(("p.g".into(), "parent".into(), "3".into())));
        assert_eq!(p.group, None);
        assert_eq!(p.packaging.as_deref(), Some("bundle"));
        assert_eq!(p.props["x"], "a&b");
        assert_eq!(p.managed.len(), 1);
        assert_eq!(p.deps.len(), 2);
        assert_eq!(p.deps[0].exclusions, vec![("*".into(), "bad".into())]);
        assert!(p.deps[1].optional);
        let props: BTreeMap<String, String> = p.props.clone();
        assert_eq!(interpolate(p.deps[0].version.as_deref().unwrap(), &props), "1.2");
        assert!(excluded(&p.deps[0].exclusions, "any", "bad"));
    }

    #[test]
    fn metadata_round_trip() {
        let xml = metadata_xml("g", "a", &["1.0".into(), "1.1".into(), "2.0-SNAPSHOT".into()]);
        let (vs, rel) = metadata_versions(xml.as_bytes());
        assert_eq!(vs, vec!["1.0", "1.1", "2.0-SNAPSHOT"]);
        assert_eq!(rel.as_deref(), Some("1.1"));
        assert_eq!(chrono_now().len(), 14);
    }
}
