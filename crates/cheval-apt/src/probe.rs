//! `cheval probe`: inspect an unknown repository and suggest a configuration.
use crate::config::{Auth, Config, Global, Repo};
use crate::http::{FetchError, RepoHttp};
use crate::release::Release;
use crate::sig::strip_cleartext;
use crate::util::{human_bytes, split_compression};
use anyhow::Result;
use futures_util::StreamExt;
use regex::Regex;
use std::collections::BTreeSet;
use url::Url;

pub struct ProbeArgs {
    pub url: String,
    pub suites: Vec<String>,
    pub user_agent: Option<String>,
    pub username: Option<String>,
    pub password_env: Option<String>,
    pub bearer: bool,
}

struct Body {
    data: Vec<u8>,
}

async fn get(rh: &RepoHttp, rel: &str, cap: usize) -> Result<Body, FetchError> {
    let url = rh.url_for(rel).map_err(|e| FetchError::Io(e.to_string()))?;
    let url = if rel.is_empty() {
        rh.base.clone()
    } else if rel.ends_with('/') {
        Url::parse(&format!("{url}/")).unwrap_or(url)
    } else {
        url
    };
    let resp = rh.get(&url, 0).await?;
    let status = resp.status().as_u16();
    match status {
        200 => {}
        404 | 410 => return Err(FetchError::NotFound(status)),
        401 | 403 | 407 => return Err(FetchError::Denied(status)),
        s => return Err(FetchError::Status(s, None)),
    }
    let mut data = Vec::new();
    let mut st = resp.bytes_stream();
    while let Some(c) = st.next().await {
        let c = c.map_err(|e| FetchError::Network(e.to_string()))?;
        data.extend_from_slice(&c);
        if data.len() > cap {
            break;
        }
    }
    Ok(Body { data })
}

struct Found {
    suite: String,
    release: Release,
    signed: &'static str,
}

async fn probe_suite(rh: &RepoHttp, suite: &str, errors: &mut Vec<String>) -> Option<Found> {
    let dist = Repo::dist_dir(suite).ok()?;
    let d = dist.to_string_lossy();
    let rel = |n: &str| if d.is_empty() { n.to_string() } else { format!("{d}/{n}") };
    match get(rh, &rel("InRelease"), 64 << 20).await {
        Ok(b) => {
            let text = String::from_utf8_lossy(&b.data);
            if let Ok(r) = Release::parse(&strip_cleartext(&text))
                && !r.files.is_empty()
            {
                return Some(Found { suite: suite.into(), release: r, signed: "InRelease (inline signature)" });
            }
        }
        Err(e) if !e.is_not_found() => errors.push(format!("{}: {e}", rel("InRelease"))),
        Err(_) => {}
    }
    match get(rh, &rel("Release"), 64 << 20).await {
        Ok(b) => {
            if let Ok(r) = Release::parse(&String::from_utf8_lossy(&b.data))
                && !r.files.is_empty()
            {
                let signed = if get(rh, &rel("Release.gpg"), 1 << 20).await.is_ok() {
                    "Release + Release.gpg (detached signature)"
                } else {
                    "Release only — UNSIGNED"
                };
                return Some(Found { suite: suite.into(), release: r, signed });
            }
        }
        Err(e) if !e.is_not_found() => errors.push(format!("{}: {e}", rel("Release"))),
        Err(_) => {}
    }
    None
}

pub async fn run(args: ProbeArgs) -> Result<bool> {
    let auth = if args.username.is_some() || args.password_env.is_some() {
        Some(Auth {
            username: args.username.clone(),
            password_env: args.password_env.clone(),
            bearer: args.bearer,
            ..Default::default()
        })
    } else {
        None
    };
    let toml_cfg = format!(
        "[global]\nbase_path = \"/nonexistent\"\n[[repo]]\nname = \"probe\"\nurl = {:?}\nsuites = [\"x\"]\n",
        args.url
    );
    let mut cfg: Config = toml::from_str(&toml_cfg)?;
    cfg.repos[0].auth = auth;
    cfg.repos[0].user_agent = args.user_agent.clone();
    let g: &Global = &cfg.global;
    let rh = RepoHttp::new(0, &cfg.repos[0], g)?;
    println!("Probing {}", rh.base);
    if let Some(ok) = probe_rpm(&rh).await? {
        return Ok(ok);
    }
    if let Some(ok) = probe_files(&rh).await? {
        return Ok(ok);
    }

    let mut errors = Vec::new();
    let mut found: Vec<Found> = Vec::new();
    let mut candidates: Vec<String> = args.suites.clone();
    if candidates.is_empty() {
        // 1. A directory listing of dists/ tells us the suites outright.
        if let Ok(b) = get(&rh, "dists/", 4 << 20).await {
            let html = String::from_utf8_lossy(&b.data);
            let re = Regex::new(r#"href="(?:\./)?([A-Za-z0-9][A-Za-z0-9._+-]*)/?""#).unwrap();
            let listed: BTreeSet<String> = re.captures_iter(&html).map(|c| c[1].to_string()).collect();
            if !listed.is_empty() {
                println!("  dists/ is browsable: {} entries", listed.len());
            }
            candidates.extend(listed.into_iter().take(40));
        }
        // 2. Flat layouts and well-known names.
        for s in [
            "./", "stable", "trixie", "bookworm", "bullseye", "noble", "jammy", "focal", "sid", "testing", "unstable",
            "any", "all", "main", "default",
        ] {
            if !candidates.iter().any(|c| c == s) {
                candidates.push(s.to_string());
            }
        }
    }
    for s in &candidates {
        if let Some(f) = probe_suite(&rh, s, &mut errors).await {
            found.push(f);
        }
        if found.is_empty() && errors.iter().any(|e| e.contains("network error")) {
            println!("\nCannot reach the server:");
            println!("  {}", errors[0]);
            println!("\nCheck DNS, proxy settings (http_proxy/https_proxy or global.proxy), TLS interception");
            println!("(global.ca_bundle / SSL_CERT_FILE) and that this host is allowed through your firewall.");
            return Ok(false);
        }
    }

    if found.is_empty() {
        // Flat repository with a bare Packages file?
        for n in ["Packages.xz", "Packages.gz", "Packages"] {
            if get(&rh, n, 1 << 20).await.is_ok() {
                println!("\nFound a bare `{n}` without any Release file: an unsigned flat repository.");
                println!("\n[[repo]]\nname = \"CHANGE-ME\"\nurl = {:?}\nsuites = [\"./\"]\nverify = \"off\"", args.url);
                return Ok(true);
            }
        }
        println!("\nNo repository metadata found.");
        errors.sort();
        errors.dedup();
        for e in errors.iter().take(6) {
            println!("  {e}");
        }
        println!("\nThings to try:");
        println!("  * pass the suite explicitly:  cheval probe {} <suite>", args.url);
        println!(
            "    (the suite is the word after the URL in the vendor's `deb ...` line; `cheval import` reads those files)"
        );
        println!(
            "  * if you saw HTTP 401/403: add credentials (--username/--password-env, --bearer) or --user-agent apt"
        );
        println!(
            "  * some vendors put the distribution in the URL itself (GitLab: .../gitlab-ee/debian/trixie trixie main)"
        );
        println!("  * behind a proxy, make sure the vendor's storage/CDN hosts are allowed as well");
        return Ok(false);
    }

    for f in &found {
        let r = &f.release;
        println!("\nSuite `{}`  [{}]", f.suite, f.signed);
        for k in ["Origin", "Label", "Suite", "Codename", "Version", "Date", "Valid-Until"] {
            if let Some(v) = r.para.get(k) {
                println!("  {k:<12} {v}");
            }
        }
        println!(
            "  Components   {}",
            if r.components.is_empty() { "(none: flat)".into() } else { r.components.join(" ") }
        );
        println!("  Architectures {}", r.architectures.join(" "));
        println!("  By-hash      {}", if r.acquire_by_hash { "yes" } else { "no" });
        let total: u64 = r.files.values().map(|e| e.size).sum();
        println!("  Index files  {} ({})", r.files.len(), human_bytes(total));
        if !r.files.values().any(|e| e.sha256.is_some() || e.sha512.is_some()) {
            println!("  WARNING      only weak checksums (MD5/SHA1) are published");
        }
        if let Some(v) = r.valid_until
            && v < chrono::Utc::now()
        {
            println!("  WARNING      Release has expired (Valid-Until in the past)");
        }
    }

    // Where do package downloads really come from? (CDN / object-store redirects)
    if let Some(f) = found.first() {
        let dist = Repo::dist_dir(&f.suite)?;
        let d = dist.to_string_lossy();
        let idx = f
            .release
            .files
            .iter()
            .filter(|(p, e)| {
                crate::plan::index_kind(p) == crate::plan::IndexKind::Packages && e.size > 0 && e.size < (64 << 20)
            })
            .filter(|(p, e)| matches!(split_compression(p).1, ".gz" | ".xz") && e.size < (16 << 20))
            .max_by_key(|(_, e)| e.size);
        if let Some((path, _)) = idx {
            let rel = if d.is_empty() { path.clone() } else { format!("{d}/{path}") };
            match get(&rh, &rel, 64 << 20).await {
                Ok(b) => {
                    let tmp = std::env::temp_dir().join(format!(
                        "cheval-probe-{}{}",
                        std::process::id(),
                        split_compression(path).1
                    ));
                    std::fs::write(&tmp, &b.data)?;
                    let first = crate::util::open_decoded(&tmp).ok().and_then(|rd| {
                        crate::deb822::Paragraphs::new(rd).flatten().find_map(|p| p.get("Filename").map(str::to_string))
                    });
                    let _ = std::fs::remove_file(&tmp);
                    if let Some(file) = first {
                        match rh.get(&rh.url_for(&file)?, 0).await {
                            Ok(resp) => {
                                let host = resp.url().host_str().unwrap_or("").to_string();
                                println!("\nSample package {file}: HTTP {}", resp.status().as_u16());
                                if Some(host.as_str()) != rh.base.host_str() {
                                    println!(
                                        "  NOTE: packages are served from `{host}` via redirect — allow that host in proxies/firewalls."
                                    );
                                    println!("        cheval never forwards credentials to redirect targets.");
                                }
                            }
                            Err(e) => println!("\nSample package {file}: {e}"),
                        }
                    }
                }
                Err(e) => println!("\nCould not read {rel}: {e}"),
            }
        }
    }

    println!("\nSuggested configuration:\n");
    let flat: Vec<&Found> = found.iter().filter(|f| Repo::is_flat(&f.suite)).collect();
    let classic: Vec<&Found> = found.iter().filter(|f| !Repo::is_flat(&f.suite)).collect();
    let q = |v: &[String]| v.iter().map(|s| format!("{s:?}")).collect::<Vec<_>>().join(", ");
    if !classic.is_empty() {
        let suites: Vec<String> = classic.iter().map(|f| f.suite.clone()).collect();
        let comps: BTreeSet<String> = classic
            .iter()
            .flat_map(|f| f.release.components.iter().map(|c| c.rsplit('/').next().unwrap_or(c).to_string()))
            .collect();
        let archs: BTreeSet<String> = classic
            .iter()
            .flat_map(|f| f.release.architectures.iter().cloned())
            .filter(|a| a != "all" && a != "source")
            .collect();
        println!("[[repo]]\nname = \"CHANGE-ME\"\nurl = {:?}\nsuites = [{}]", args.url, q(&suites));
        println!("components = [{}]", q(&comps.into_iter().collect::<Vec<_>>()));
        println!("architectures = [{}]   # trim to what you need", q(&archs.into_iter().collect::<Vec<_>>()));
        println!("keyring = \"/path/to/vendor-key.gpg\"   # the key from the vendor's install instructions");
    }
    for f in flat {
        println!("[[repo]]\nname = \"CHANGE-ME\"\nurl = {:?}\nsuites = [{:?}]", args.url, f.suite);
        println!("keyring = \"/path/to/vendor-key.gpg\"");
    }
    if args.user_agent.is_some() {
        println!("user_agent = {:?}", args.user_agent.as_deref().unwrap_or(""));
    }
    Ok(true)
}

/// An RPM (yum/dnf) repository at the URL: describe it and suggest an entry.
async fn probe_rpm(rh: &RepoHttp) -> Result<Option<bool>> {
    let body = match get(rh, "repodata/repomd.xml", 16 << 20).await {
        Ok(b) => b,
        Err(e) if e.is_not_found() => return Ok(None),
        Err(e) => {
            println!("  repodata/repomd.xml: {e}");
            return Ok(None);
        }
    };
    let md = match cheval_rpm::meta::parse_repomd(&body.data) {
        Ok(m) => m,
        Err(e) => {
            println!("  repodata/repomd.xml is there but unreadable: {e:#}");
            return Ok(Some(false));
        }
    };
    println!(
        "  RPM repository (repodata/repomd.xml){}",
        md.revision.as_ref().map(|r| format!(", revision {r}")).unwrap_or_default()
    );
    let kinds: Vec<&str> = md.entries.iter().map(|e| e.kind.as_str()).collect();
    println!("  metadata: {}", kinds.join(", "));
    let meta_bytes: u64 = md.entries.iter().filter_map(|e| e.size).sum();
    let signed = get(rh, "repodata/repomd.xml.asc", 1 << 20).await.is_ok();
    println!(
        "  signature: {}",
        if signed {
            "repomd.xml.asc (set `keyring` to the distribution's RPM-GPG-KEY)"
        } else {
            "none: repomd.xml is unsigned (EPEL/Fedora: set `metalink`; otherwise HTTPS is the only protection)"
        }
    );
    let mut ok = true;
    if let Some(p) = md.primary() {
        match get(rh, &p.href, 1 << 30).await {
            Ok(b) => {
                let dir = tempfile_dir()?;
                let name = p.href.rsplit('/').next().unwrap_or("primary.xml");
                let path = dir.join(name);
                std::fs::write(&path, &b.data)?;
                let (mut n, mut src, mut bytes) = (0u64, 0u64, 0u64);
                let res = crate::util::open_decoded(&path).and_then(|r| {
                    cheval_rpm::meta::read_primary(r, |pkg| {
                        if pkg.is_source() {
                            src += 1;
                        } else {
                            n += 1;
                            bytes += pkg.size;
                        }
                        Ok(())
                    })
                });
                let _ = std::fs::remove_dir_all(&dir);
                match res {
                    Ok(_) => println!(
                        "  packages: {n} ({}), plus {src} source package(s) cheval skips; metadata {}",
                        human_bytes(bytes),
                        human_bytes(meta_bytes)
                    ),
                    Err(e) => {
                        println!("  primary metadata unreadable: {e:#}");
                        ok = false;
                    }
                }
            }
            Err(e) => {
                println!("  {}: {e}", p.href);
                ok = false;
            }
        }
    } else {
        println!("  repomd.xml lists no primary metadata");
        ok = false;
    }
    println!(
        "\nSuggested configuration (replace the version, section and architecture in the URL with {{release}}, {{repo}}, {{arch}} to cover several):\n"
    );
    println!("[[repo]]\nname   = \"CHANGE-ME\"\nformat = \"rpm\"\nurl    = \"{}\"", rh.base);
    if signed {
        println!("keyring = \"/etc/cheval/keys/RPM-GPG-KEY-CHANGE-ME\"");
    } else {
        println!("# metalink = \"https://mirrors.fedoraproject.org/metalink?repo=epel-{{release}}&arch={{arch}}\"");
    }
    Ok(Some(ok))
}

fn tempfile_dir() -> Result<std::path::PathBuf> {
    let d = std::env::temp_dir().join(format!("cheval-probe-{}", std::process::id()));
    std::fs::create_dir_all(&d)?;
    Ok(d)
}

/// A folder of files with a checksum list (installer ISOs): list them and suggest an entry.
async fn probe_files(rh: &RepoHttp) -> Result<Option<bool>> {
    for list in ["CHECKSUM", "SHA256SUM", "SHA256SUMS", "sha256sum.txt"] {
        let Ok(body) = get(rh, list, 4 << 20).await else { continue };
        let Ok(listed) = cheval_rpm::sums::parse(&String::from_utf8_lossy(&body.data)) else { continue };
        println!("  folder of files listed in {list} ({} entries)", listed.len());
        let mut sig = None;
        for cand in [format!("{list}.asc"), format!("{list}.sig"), format!("{list}.gpg")] {
            if get(rh, &cand, 1 << 20).await.is_ok() {
                sig = Some(cand);
                break;
            }
        }
        println!("  signature: {}", sig.as_deref().unwrap_or("none found (HTTPS is the only protection)"));
        for (name, l) in &listed {
            let size = l.size.map(human_bytes).unwrap_or_else(|| "size not listed".into());
            println!("    {name:<56} {size}");
        }
        let dvd: Vec<&String> =
            listed.keys().filter(|n| n.to_ascii_lowercase().contains("dvd") && n.ends_with(".iso")).collect();
        println!("\nSuggested configuration:\n");
        println!(
            "[[repo]]\nname      = \"CHANGE-ME\"\nformat    = \"files\"\nurl       = \"{}\"\nchecksums = [\"{list}\"]",
            rh.base
        );
        if let Some(s) = &sig {
            println!("signature = \"{s}\"\nkeyring   = \"/etc/cheval/keys/CHANGE-ME\"");
        }
        let inc: Vec<String> = dvd.iter().map(|n| format!("\"{n}\"")).collect();
        println!("include   = [{}]", if inc.is_empty() { "\"*.iso\"".to_string() } else { inc.join(", ") });
        return Ok(Some(true));
    }
    Ok(None)
}
