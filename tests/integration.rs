//! End-to-end tests against a local fixture repository served over HTTP.
use cheval::config::Config;
use cheval::progress::{Level, Progress};
use cheval::sync::{self, Summary, SyncOptions};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------- test HTTP server

#[derive(Default)]
struct ServerState {
    hits: Mutex<HashMap<String, u32>>,
    /// path substring -> remaining number of 503 answers
    fail: Mutex<Vec<(String, u32)>>,
    /// path substring -> remaining number of truncated bodies
    truncate: Mutex<Vec<(String, u32)>>,
    /// path prefix -> absolute URL prefix to redirect to
    redirect: Mutex<Vec<(String, String)>>,
    /// required Authorization header value
    auth: Mutex<Option<String>>,
    /// (path, authorization header) for every request
    seen: Mutex<Vec<(String, Option<String>)>>,
}

struct Server {
    url: String,
    state: Arc<ServerState>,
}

impl Server {
    fn hits(&self, needle: &str) -> u32 {
        self.state.hits.lock().unwrap().iter().filter(|(k, _)| k.contains(needle)).map(|(_, v)| *v).sum()
    }
}

fn take(list: &Mutex<Vec<(String, u32)>>, path: &str) -> bool {
    let mut l = list.lock().unwrap();
    for (pat, n) in l.iter_mut() {
        if path.contains(pat.as_str()) && *n > 0 {
            *n -= 1;
            return true;
        }
    }
    false
}

async fn serve(root: PathBuf) -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(ServerState::default());
    let st = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { break };
            let (root, st) = (root.clone(), st.clone());
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let mut lines = head.lines();
                let raw_path = lines.next().unwrap_or("").split(' ').nth(1).unwrap_or("/").to_string();
                let path = percent_encoding::percent_decode_str(&raw_path).decode_utf8_lossy().to_string();
                let mut range = None;
                let mut auth = None;
                for l in lines {
                    let low = l.to_ascii_lowercase();
                    if let Some(v) = low.strip_prefix("range: bytes=") {
                        range = v.trim_end_matches('-').parse::<u64>().ok();
                    }
                    if low.starts_with("authorization:") {
                        auth = Some(l[14..].trim().to_string());
                    }
                }
                *st.hits.lock().unwrap().entry(path.clone()).or_default() += 1;
                st.seen.lock().unwrap().push((path.clone(), auth.clone()));
                let reply = |code: &str, extra: &str, body: &[u8]| {
                    let mut v = format!(
                        "HTTP/1.1 {code}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
                        body.len()
                    )
                    .into_bytes();
                    v.extend_from_slice(body);
                    v
                };
                let need = st.auth.lock().unwrap().clone();
                if let Some(need) = need
                    && auth.as_deref() != Some(need.as_str())
                {
                    let _ = sock.write_all(&reply("401 Unauthorized", "", b"")).await;
                    return;
                }
                let redirect = st.redirect.lock().unwrap().iter().find(|(p, _)| path.starts_with(p.as_str())).cloned();
                if let Some((_, to)) = redirect {
                    let _ = sock.write_all(&reply("302 Found", &format!("Location: {to}{raw_path}\r\n"), b"")).await;
                    return;
                }
                if take(&st.fail, &path) {
                    let _ = sock.write_all(&reply("503 Service Unavailable", "", b"busy")).await;
                    return;
                }
                let file = root.join(path.trim_start_matches('/'));
                let Ok(data) = std::fs::read(&file) else {
                    let _ = sock.write_all(&reply("404 Not Found", "", b"nope")).await;
                    return;
                };
                let (code, body) = match range {
                    Some(off) if (off as usize) < data.len() => ("206 Partial Content", &data[off as usize..]),
                    Some(_) => {
                        let _ = sock.write_all(&reply("416 Range Not Satisfiable", "", b"")).await;
                        return;
                    }
                    None => ("200 OK", &data[..]),
                };
                if take(&st.truncate, &path) && body.len() > 10 {
                    // Announce the full length, send only half, then drop the connection.
                    let head =
                        format!("HTTP/1.1 {code}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&body[..body.len() / 2]).await;
                    let _ = sock.flush().await;
                    return;
                }
                let _ = sock.write_all(&reply(code, "", body)).await;
            });
        }
    });
    Server { url, state }
}

// ---------------------------------------------------------------- fixture builder

fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

struct Gpg {
    home: PathBuf,
    pubkey: PathBuf,
    other_pubkey: PathBuf,
}

fn gpg() -> Option<&'static Gpg> {
    static G: OnceLock<Option<Gpg>> = OnceLock::new();
    G.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("cheval-test-gpg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mk = |name: &str| -> Option<(PathBuf, PathBuf)> {
            let home = dir.join(name);
            std::fs::create_dir_all(&home).ok()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).ok()?;
            }
            let ok = Command::new("gpg")
                .args([
                    "--homedir",
                    home.to_str()?,
                    "--batch",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--quick-gen-key",
                    &format!("cheval {name} <t@example.invalid>"),
                    "ed25519",
                    "sign",
                    "never",
                ])
                .output()
                .ok()?
                .status
                .success();
            if !ok {
                return None;
            }
            let out = Command::new("gpg").args(["--homedir", home.to_str()?, "--export"]).output().ok()?;
            let key = dir.join(format!("{name}.gpg"));
            std::fs::write(&key, out.stdout).ok()?;
            let _ = Command::new("gpgconf").args(["--homedir", home.to_str()?, "--kill", "gpg-agent"]).output();
            Some((home, key))
        };
        let (home, pubkey) = mk("signer")?;
        let (_, other_pubkey) = mk("stranger")?;
        Some(Gpg { home, pubkey, other_pubkey })
    })
    .as_ref()
}

#[derive(Clone)]
struct Pkg {
    name: &'static str,
    version: &'static str,
    /// Filename override (for hostile-path tests).
    filename: Option<&'static str>,
}

fn pkg(name: &'static str, version: &'static str) -> Pkg {
    Pkg { name, version, filename: None }
}

struct Fixture {
    by_hash: bool,
    sign: bool,
    date: &'static str,
    valid_until: Option<&'static str>,
    source: bool,
}

impl Default for Fixture {
    fn default() -> Self {
        Fixture { by_hash: false, sign: false, date: "Sat, 01 Aug 2026 10:00:00 UTC", valid_until: None, source: false }
    }
}

fn deb_bytes(p: &Pkg) -> Vec<u8> {
    // Deterministic pseudo-content, a few KiB each.
    let seed = format!("{}_{}", p.name, p.version);
    let mut out = Vec::new();
    let mut h = Sha256::digest(seed.as_bytes()).to_vec();
    for _ in 0..200 {
        h = Sha256::digest(&h).to_vec();
        out.extend_from_slice(&h);
    }
    out
}

fn compress(data: &[u8], ext: &str) -> Vec<u8> {
    match ext {
        ".gz" => {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
        ".xz" => {
            let mut e = liblzma::write::XzEncoder::new(Vec::new(), 1);
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
        _ => data.to_vec(),
    }
}

impl Fixture {
    /// Build `dists/<suite>` (or a flat directory when `suite` ends in '/') below `root`.
    fn build(&self, root: &Path, suite: &str, pkgs: &[Pkg]) {
        let flat = suite.ends_with('/');
        let dist =
            if flat { root.join(suite.trim_matches(|c| c == '.' || c == '/')) } else { root.join("dists").join(suite) };
        let _ = std::fs::remove_dir_all(root.join("dists").join(suite));
        std::fs::create_dir_all(&dist).unwrap();
        let mut packages = String::new();
        for p in pkgs {
            let data = deb_bytes(p);
            let default = format!("pool/main/{}/{}/{}_{}_amd64.deb", &p.name[..1], p.name, p.name, p.version);
            let filename = p.filename.map(str::to_string).unwrap_or(default);
            if p.filename.is_none() {
                let path = root.join(&filename);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, &data).unwrap();
            }
            packages.push_str(&format!(
                "Package: {}\nVersion: {}\nArchitecture: amd64\nFilename: {}\nSize: {}\nSHA256: {}\nDescription: test\n\n",
                p.name, p.version, filename, data.len(), sha256(&data)
            ));
        }
        let mut files: Vec<(String, Vec<u8>)> = Vec::new();
        let pdir = if flat { String::new() } else { "main/binary-amd64/".to_string() };
        for ext in ["", ".gz", ".xz"] {
            files.push((format!("{pdir}Packages{ext}"), compress(packages.as_bytes(), ext)));
        }
        if !flat {
            files.push(("main/binary-arm64/Packages.gz".into(), compress(b"", ".gz")));
            files.push(("main/i18n/Translation-en.gz".into(), compress(b"Package: alpha\nDescription-en: x\n", ".gz")));
            files.push(("contrib/binary-amd64/Packages.gz".into(), compress(b"", ".gz")));
        }
        if self.source {
            let dsc = b"fake dsc".to_vec();
            let tar = deb_bytes(&pkg("srcpkg", "1.0"));
            std::fs::create_dir_all(root.join("pool/main/s/srcpkg")).unwrap();
            std::fs::write(root.join("pool/main/s/srcpkg/srcpkg_1.0.dsc"), &dsc).unwrap();
            std::fs::write(root.join("pool/main/s/srcpkg/srcpkg_1.0.tar.xz"), &tar).unwrap();
            let src = format!(
                "Package: srcpkg\nVersion: 1.0\nDirectory: pool/main/s/srcpkg\nChecksums-Sha256:\n {} {} srcpkg_1.0.dsc\n {} {} srcpkg_1.0.tar.xz\n\n",
                sha256(&dsc),
                dsc.len(),
                sha256(&tar),
                tar.len()
            );
            files.push(("main/source/Sources.xz".into(), compress(src.as_bytes(), ".xz")));
        }
        let mut rel = format!("Origin: cheval-test\nSuite: {suite}\nDate: {}\n", self.date);
        if let Some(v) = self.valid_until {
            rel.push_str(&format!("Valid-Until: {v}\n"));
        }
        if !flat {
            rel.push_str("Architectures: amd64 arm64\nComponents: main contrib\n");
        }
        if self.by_hash {
            rel.push_str("Acquire-By-Hash: yes\n");
        }
        rel.push_str("SHA256:\n");
        for (path, data) in &files {
            let h = sha256(data);
            rel.push_str(&format!(" {h} {} {path}\n", data.len()));
            // Like Debian, do not host the uncompressed Packages file.
            let hosted = !(path.ends_with("Packages") && !flat);
            let full = dist.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            if hosted {
                std::fs::write(&full, data).unwrap();
            }
            if self.by_hash && hosted {
                let bh = full.parent().unwrap().join("by-hash/SHA256");
                std::fs::create_dir_all(&bh).unwrap();
                std::fs::write(bh.join(&h), data).unwrap();
            }
        }
        std::fs::write(dist.join("Release"), &rel).unwrap();
        let _ = std::fs::remove_file(dist.join("InRelease"));
        let _ = std::fs::remove_file(dist.join("Release.gpg"));
        if self.sign {
            let g = gpg().expect("gpg required");
            let run = |args: &[&str]| {
                let st = Command::new("gpg")
                    .args([
                        "--homedir",
                        g.home.to_str().unwrap(),
                        "--batch",
                        "--yes",
                        "--pinentry-mode",
                        "loopback",
                        "--passphrase",
                        "",
                    ])
                    .args(args)
                    .output()
                    .unwrap();
                assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
            };
            run(&[
                "--clearsign",
                "-o",
                dist.join("InRelease").to_str().unwrap(),
                dist.join("Release").to_str().unwrap(),
            ]);
            run(&[
                "--armor",
                "--detach-sign",
                "-o",
                dist.join("Release.gpg").to_str().unwrap(),
                dist.join("Release").to_str().unwrap(),
            ]);
            let _ =
                Command::new("gpgconf").args(["--homedir", g.home.to_str().unwrap(), "--kill", "gpg-agent"]).output();
        }
    }
}

// ---------------------------------------------------------------- harness

struct Run {
    summary: Summary,
    logs: Vec<String>,
}

impl Run {
    fn has_log(&self, needle: &str) -> bool {
        self.logs.iter().any(|l| l.contains(needle))
    }
}

async fn sync_with(base: &Path, repos: &str, opts: SyncOptions) -> anyhow::Result<Run> {
    let text = format!(
        "[global]\nbase_path = {:?}\nretry_delay_ms = 5\nretries = 3\nstall_timeout_secs = 5\nclean_max_percent = 90\n{repos}",
        base.to_str().unwrap()
    );
    let cfg: Config = toml::from_str(&text)?;
    cfg.validate()?;
    let names: Vec<String> = cfg.repos.iter().map(|r| r.name.clone()).collect();
    let progress = Progress::new(&names);
    progress.verbose.store(true, std::sync::atomic::Ordering::Relaxed);
    let summary = sync::run(Arc::new(cfg), opts, progress.clone(), CancellationToken::new()).await?;
    let logs = progress.logs_snapshot(Level::Debug).iter().map(cheval::progress::format_line).collect();
    Ok(Run { summary, logs })
}

async fn sync_ok(base: &Path, repos: &str) -> Run {
    let r = sync_with(base, repos, SyncOptions::default()).await.unwrap();
    assert!(r.summary.success(), "sync failed:\n{}\n{}", r.summary.render(), r.logs.join("\n"));
    r
}

fn repo(url: &str, extra: &str) -> String {
    format!(
        "[[repo]]\nname = \"t\"\nurl = \"{url}/repo\"\nsuites = [\"stable\"]\ncomponents = [\"main\"]\nmirror_dir = \"t\"\n{extra}\n"
    )
}

fn deb_path(mirror: &Path, name: &str, ver: &str) -> PathBuf {
    mirror.join(format!("pool/main/{}/{name}/{name}_{ver}_amd64.deb", &name[..1]))
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn basic_sync_is_complete_and_idempotent() {
    let up = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    let fx = Fixture::default();
    fx.build(
        &up.path().join("repo"),
        "stable",
        &[pkg("alpha", "1.0"), pkg("beta", "2.0+b1"), pkg("libstdc++6", "1~rc1")],
    );
    let srv = serve(up.path().to_path_buf()).await;
    let m = base.path().join("mirror/t");

    let r = sync_ok(base.path(), &repo(&srv.url, "")).await;
    assert_eq!(r.summary.repos[0].suites_ok, vec!["stable"]);
    for (n, v) in [("alpha", "1.0"), ("beta", "2.0+b1"), ("libstdc++6", "1~rc1")] {
        let p = deb_path(&m, n, v);
        assert_eq!(std::fs::read(&p).unwrap(), deb_bytes(&pkg(n, v)), "{}", p.display());
    }
    assert!(m.join("dists/stable/Release").is_file());
    assert!(m.join("dists/stable/main/binary-amd64/Packages.xz").is_file());
    assert!(m.join("dists/stable/main/i18n/Translation-en.gz").is_file());
    // Unselected architecture and component are not mirrored.
    assert!(!m.join("dists/stable/main/binary-arm64").exists());
    assert!(!m.join("dists/stable/contrib").exists());
    // Upstream does not host the uncompressed index: tolerated silently.
    assert!(!m.join("dists/stable/main/binary-amd64/Packages").exists());
    assert!(r.has_log("no keyring configured"));
    assert!(!base.path().join("staging/t").exists());

    let pool_hits = srv.hits("/pool/");
    let r2 = sync_ok(base.path(), &repo(&srv.url, "")).await;
    assert_eq!(srv.hits("/pool/"), pool_hits, "second run must not re-download packages");
    assert_eq!(r2.summary.repos[0].files_failed, 0);
    assert!(
        cheval::verify::run(
            &toml::from_str(&format!(
                "[global]\nbase_path = {:?}\n{}",
                base.path().to_str().unwrap(),
                repo(&srv.url, "")
            ))
            .unwrap(),
            &[],
            true
        )
        .unwrap()
    );
}

#[tokio::test]
async fn failed_package_keeps_previous_consistent_state() {
    let up = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    let root = up.path().join("repo");
    Fixture::default().build(&root, "stable", &[pkg("alpha", "1.0")]);
    let srv = serve(up.path().to_path_buf()).await;
    let m = base.path().join("mirror/t");
    sync_ok(base.path(), &repo(&srv.url, "")).await;
    let old_release = std::fs::read(m.join("dists/stable/Release")).unwrap();

    // Upstream moves on, but one of the new packages is broken upstream.
    Fixture { date: "Sun, 02 Aug 2026 10:00:00 UTC", ..Default::default() }.build(
        &root,
        "stable",
        &[pkg("alpha", "1.1"), pkg("gamma", "1.0")],
    );
    std::fs::remove_file(deb_path(&root, "gamma", "1.0")).unwrap();
    let r = sync_with(base.path(), &repo(&srv.url, ""), SyncOptions::default()).await.unwrap();
    assert!(!r.summary.success());
    assert_eq!(r.summary.repos[0].files_failed, 1);
    // Indices untouched, old package still there (no clean on failure), new one staged in pool.
    assert_eq!(std::fs::read(m.join("dists/stable/Release")).unwrap(), old_release);
    assert!(deb_path(&m, "alpha", "1.0").is_file());
    assert!(deb_path(&m, "alpha", "1.1").is_file());

    // ignore_missing lets the operator accept the gap explicitly.
    let r =
        sync_with(base.path(), &repo(&srv.url, "ignore_missing = ['gamma']"), SyncOptions::default()).await.unwrap();
    assert!(r.summary.success(), "{}", r.logs.join("\n"));
    assert_ne!(std::fs::read(m.join("dists/stable/Release")).unwrap(), old_release);
    // ... and now the superseded package is cleaned up.
    assert!(!deb_path(&m, "alpha", "1.0").exists());
    assert_eq!(r.summary.cleaned_files, 1);
}

#[tokio::test]
async fn retries_resume_and_detect_corruption() {
    let up = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    let root = up.path().join("repo");
    Fixture::default().build(&root, "stable", &[pkg("alpha", "1.0"), pkg("beta", "1.0"), pkg("gamma", "1.0")]);
    let srv = serve(up.path().to_path_buf()).await;
    srv.state.fail.lock().unwrap().push(("alpha_1.0".into(), 2));
    srv.state.truncate.lock().unwrap().push(("beta_1.0".into(), 1));
    srv.state.fail.lock().unwrap().push(("Packages.xz".into(), 1));
    let m = base.path().join("mirror/t");
    let r = sync_ok(base.path(), &repo(&srv.url, "")).await;
    assert_eq!(srv.hits("alpha_1.0"), 3);
    assert_eq!(srv.hits("beta_1.0"), 2, "truncated transfer must be resumed once");
    assert!(r.has_log("retry"));
    assert_eq!(std::fs::read(deb_path(&m, "beta", "1.0")).unwrap(), deb_bytes(&pkg("beta", "1.0")));

    // Persistent corruption upstream: never accepted, never published.
    Fixture { date: "Sun, 02 Aug 2026 10:00:00 UTC", ..Default::default() }.build(
        &root,
        "stable",
        &[pkg("alpha", "1.0"), pkg("delta", "1.0")],
    );
    let mut bad = deb_bytes(&pkg("delta", "1.0"));
    bad[100] ^= 0xff;
    std::fs::write(deb_path(&root, "delta", "1.0"), &bad).unwrap();
    let r = sync_with(base.path(), &repo(&srv.url, ""), SyncOptions::default()).await.unwrap();
    assert!(!r.summary.success());
    assert!(r.has_log("verification failed"));
    assert!(!deb_path(&m, "delta", "1.0").exists());
    let listed = std::fs::read(m.join("dists/stable/main/binary-amd64/Packages.gz")).unwrap();
    let mut s = String::new();
    std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&listed[..]), &mut s).unwrap();
    assert!(!s.contains("delta"), "index mentioning the corrupt package must not be published");
}

#[tokio::test]
async fn local_corruption_is_repaired_with_hash_recheck() {
    let up = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    Fixture::default().build(&up.path().join("repo"), "stable", &[pkg("alpha", "1.0")]);
    let srv = serve(up.path().to_path_buf()).await;
    let m = base.path().join("mirror/t");
    sync_ok(base.path(), &repo(&srv.url, "")).await;
    let p = deb_path(&m, "alpha", "1.0");
    let mut data = std::fs::read(&p).unwrap();
    data[7] ^= 1; // same size, different content
    std::fs::write(&p, &data).unwrap();
    sync_ok(base.path(), &repo(&srv.url, "")).await;
    assert_ne!(std::fs::read(&p).unwrap(), deb_bytes(&pkg("alpha", "1.0")), "size check alone cannot see it");
    let opts = SyncOptions { recheck: Some(cheval::config::Recheck::Hash), ..Default::default() };
    let r = sync_with(base.path(), &repo(&srv.url, ""), opts).await.unwrap();
    assert!(r.summary.success());
    assert_eq!(std::fs::read(&p).unwrap(), deb_bytes(&pkg("alpha", "1.0")));
}

#[tokio::test]
async fn by_hash_and_sources() {
    let up = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    let root = up.path().join("repo");
    Fixture { by_hash: true, source: true, ..Default::default() }.build(&root, "stable", &[pkg("alpha", "1.0")]);
    // Canonical index is "mid-update" garbage; only by-hash is right.
    std::fs::write(root.join("dists/stable/main/binary-amd64/Packages.xz"), b"garbage").unwrap();
    let srv = serve(up.path().to_path_buf()).await;
    let m = base.path().join("mirror/t");
    sync_ok(base.path(), &repo(&srv.url, "source = true")).await;
    let bh = m.join("dists/stable/main/binary-amd64/by-hash/SHA256");
    assert_eq!(std::fs::read_dir(&bh).unwrap().count(), 2);
    assert_ne!(std::fs::read(m.join("dists/stable/main/binary-amd64/Packages.xz")).unwrap(), b"garbage");
    assert!(m.join("pool/main/s/srcpkg/srcpkg_1.0.dsc").is_file());
    assert!(m.join("pool/main/s/srcpkg/srcpkg_1.0.tar.xz").is_file());
    assert!(m.join("dists/stable/main/source/Sources.xz").is_file());
    // Without source = true nothing source-related is taken.
    let base2 = tempfile::tempdir().unwrap();
    sync_ok(base2.path(), &repo(&srv.url, "")).await;
    assert!(!base2.path().join("mirror/t/pool/main/s").exists());
    assert!(!base2.path().join("mirror/t/dists/stable/main/source").exists());
}

#[tokio::test]
async fn flat_repositories() {
    let up = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    let root = up.path().join("repo");
    Fixture::default().build(&root, "./", &[pkg("alpha", "1.0")]);
    let srv = serve(up.path().to_path_buf()).await;
    let cfg = format!("[[repo]]\nname = \"t\"\nurl = \"{}/repo\"\nsuites = [\"./\"]\nmirror_dir = \"t\"\n", srv.url);
    sync_ok(base.path(), &cfg).await;
    let m = base.path().join("mirror/t");
    assert!(m.join("Release").is_file() && m.join("Packages.gz").is_file() && m.join("Packages").is_file());
    assert!(deb_path(&m, "alpha", "1.0").is_file());

    // No Release at all: mirrored with a loud warning, refused when verification is required.
    for f in ["Release", "Packages.xz", "Packages"] {
        std::fs::remove_file(root.join(f)).unwrap();
    }
    let base2 = tempfile::tempdir().unwrap();
    let r = sync_ok(base2.path(), &cfg).await;
    assert!(r.has_log("cannot be authenticated"));
    assert!(deb_path(&base2.path().join("mirror/t"), "alpha", "1.0").is_file());
}

#[tokio::test]
async fn credentials_stay_on_the_origin_across_redirects() {
    let up = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    Fixture::default().build(&up.path().join("repo"), "stable", &[pkg("alpha", "1.0")]);
    let origin = serve(up.path().to_path_buf()).await;
    let cdn = serve(up.path().to_path_buf()).await;
    *origin.state.auth.lock().unwrap() = Some("Basic Ym90OnMzY3JldA==".into()); // bot:s3cret
    origin.state.redirect.lock().unwrap().push(("/repo/pool/".into(), cdn.url.clone()));

    // Without credentials: clear failure, nothing published.
    let r = sync_with(base.path(), &repo(&origin.url, ""), SyncOptions::default()).await.unwrap();
    assert!(!r.summary.success());
    assert!(r.has_log("HTTP 401") && r.has_log("access denied"), "{}", r.logs.join("\n"));

    // Credentials in the URL work and never show up in the log.
    let in_url = repo(&origin.url.replace("http://", "http://bot:s3cret@"), "");
    let r = sync_ok(base.path(), &in_url).await;
    assert!(!r.logs.iter().any(|l| l.contains("s3cret")), "secret leaked into the log");
    std::fs::remove_dir_all(base.path().join("mirror")).unwrap();

    // SAFETY: test-only environment variable, set before use.
    unsafe { std::env::set_var("CHEVAL_TEST_SECRET", "s3cret") };
    let auth =
        "[repo.auth]\nusername = \"bot\"\npassword_env = \"CHEVAL_TEST_SECRET\"\nheaders = { \"X-Api-Key\" = \"k\" }";
    sync_ok(base.path(), &repo(&origin.url, auth)).await;
    assert!(deb_path(&base.path().join("mirror/t"), "alpha", "1.0").is_file());
    let seen = cdn.state.seen.lock().unwrap();
    assert!(!seen.is_empty(), "package must have come from the redirect target");
    assert!(seen.iter().all(|(_, a)| a.is_none()), "credentials leaked to redirect target: {seen:?}");
}

#[tokio::test]
async fn signatures_are_enforced() {
    let Some(g) = gpg() else {
        eprintln!("gpg not available, skipping");
        return;
    };
    let up = tempfile::tempdir().unwrap();
    let root = up.path().join("repo");
    Fixture { sign: true, ..Default::default() }.build(&root, "stable", &[pkg("alpha", "1.0")]);
    let srv = serve(up.path().to_path_buf()).await;
    let with_key = |k: &Path| repo(&srv.url, &format!("keyring = {:?}\nverify = \"require\"", k.to_str().unwrap()));

    let base = tempfile::tempdir().unwrap();
    let r = sync_ok(base.path(), &with_key(&g.pubkey)).await;
    assert!(r.has_log("signature OK"));
    for f in ["InRelease", "Release", "Release.gpg"] {
        assert!(base.path().join("mirror/t/dists/stable").join(f).is_file());
    }

    // A key that did not sign the repository is rejected.
    let base2 = tempfile::tempdir().unwrap();
    let r = sync_with(base2.path(), &with_key(&g.other_pubkey), SyncOptions::default()).await.unwrap();
    assert!(!r.summary.success());
    assert!(!base2.path().join("mirror/t/dists").exists());

    // Detached signature only (no InRelease) works too.
    std::fs::remove_file(root.join("dists/stable/InRelease")).unwrap();
    let base3 = tempfile::tempdir().unwrap();
    sync_ok(base3.path(), &with_key(&g.pubkey)).await;
    assert!(!base3.path().join("mirror/t/dists/stable/InRelease").exists());

    // Tampering with the signed data is detected.
    let rel = root.join("dists/stable/Release");
    let t = std::fs::read_to_string(&rel).unwrap().replace("cheval-test", "evil-origin");
    std::fs::write(&rel, t).unwrap();
    let base4 = tempfile::tempdir().unwrap();
    let r = sync_with(base4.path(), &with_key(&g.pubkey), SyncOptions::default()).await.unwrap();
    assert!(!r.summary.success());
    assert!(r.has_log("signature"));
}

#[tokio::test]
async fn hostile_metadata_cannot_escape_the_mirror() {
    let up = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    let evil = Pkg { name: "evil", version: "1", filename: Some("../../../escape.deb") };
    let abs = Pkg { name: "abs", version: "1", filename: Some("/tmp/cheval-abs-escape.deb") };
    Fixture::default().build(&up.path().join("repo"), "stable", &[pkg("alpha", "1.0"), evil, abs]);
    let srv = serve(up.path().to_path_buf()).await;
    let r = sync_ok(base.path(), &repo(&srv.url, "")).await;
    assert!(r.has_log("unsafe Filename"));
    assert!(!base.path().join("escape.deb").exists());
    assert!(!base.path().join("mirror/escape.deb").exists());
    assert!(!Path::new("/tmp/cheval-abs-escape.deb").exists());
    assert_eq!(srv.hits("escape"), 0);
}

#[tokio::test]
async fn stale_and_expired_upstreams_are_refused() {
    let up = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    let root = up.path().join("repo");
    Fixture { date: "Sun, 02 Aug 2026 10:00:00 UTC", ..Default::default() }.build(
        &root,
        "stable",
        &[pkg("alpha", "2.0")],
    );
    let srv = serve(up.path().to_path_buf()).await;
    sync_ok(base.path(), &repo(&srv.url, "")).await;

    // A lagging upstream mirror serves yesterday's state: keep ours.
    Fixture { date: "Sat, 01 Aug 2026 10:00:00 UTC", ..Default::default() }.build(
        &root,
        "stable",
        &[pkg("alpha", "1.0")],
    );
    let r = sync_with(base.path(), &repo(&srv.url, ""), SyncOptions::default()).await.unwrap();
    assert!(!r.summary.success());
    assert!(r.has_log("older than the mirrored one"));
    assert!(deb_path(&base.path().join("mirror/t"), "alpha", "2.0").is_file());
    sync_ok(base.path(), &repo(&srv.url, "allow_downgrade = true")).await;

    Fixture {
        date: "Mon, 03 Aug 2026 10:00:00 UTC",
        valid_until: Some("Tue, 04 Aug 2026 10:00:00 UTC"),
        ..Default::default()
    }
    .build(&root, "stable", &[pkg("alpha", "3.0")]);
    let r = sync_with(base.path(), &repo(&srv.url, ""), SyncOptions::default()).await.unwrap();
    assert!(!r.summary.success());
    assert!(r.has_log("expired"));
    sync_ok(base.path(), &repo(&srv.url, "check_valid_until = false")).await;
}

#[tokio::test]
async fn clean_is_conservative() {
    let up = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    let root = up.path().join("repo");
    Fixture::default().build(&root, "stable", &[pkg("alpha", "1.0")]);
    Fixture::default().build(&root, "testing", &[pkg("beta", "1.0")]);
    let srv = serve(up.path().to_path_buf()).await;
    let m = base.path().join("mirror/t");
    // Two config entries sharing one directory.
    let two = format!(
        "[[repo]]\nname = \"a\"\nurl = \"{0}/repo\"\nsuites = [\"stable\"]\nmirror_dir = \"t\"\n[[repo]]\nname = \"b\"\nurl = \"{0}/repo\"\nsuites = [\"testing\"]\nmirror_dir = \"t\"\n",
        srv.url
    );
    let r = sync_ok(base.path(), &two).await;
    assert_eq!(r.summary.cleaned_files, 0);
    assert!(deb_path(&m, "alpha", "1.0").is_file() && deb_path(&m, "beta", "1.0").is_file());
    std::fs::write(m.join("pool/stray.deb"), b"x").unwrap();

    // Running only one of them must not delete the other's files (nor anything else).
    let r = sync_with(base.path(), &two, SyncOptions { only: vec!["a".into()], ..Default::default() }).await.unwrap();
    assert!(r.summary.success());
    assert!(deb_path(&m, "beta", "1.0").is_file() && m.join("pool/stray.deb").is_file());

    // clean = "report" lists but keeps.
    let report = two.replace("mirror_dir = \"t\"\n[[repo]]", "mirror_dir = \"t\"\nclean = \"report\"\n[[repo]]");
    let r = sync_ok(base.path(), &report).await;
    assert!(r.has_log("obsolete") && m.join("pool/stray.deb").is_file());

    // Full run: only the stray file goes.
    let r = sync_ok(base.path(), &two).await;
    assert_eq!(r.summary.cleaned_files, 1);
    assert!(!m.join("pool/stray.deb").exists());
    assert!(deb_path(&m, "alpha", "1.0").is_file() && deb_path(&m, "beta", "1.0").is_file());
}

#[tokio::test]
async fn wrong_suite_or_architecture_is_reported_not_silent() {
    let up = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    Fixture::default().build(&up.path().join("repo"), "stable", &[pkg("alpha", "1.0")]);
    let srv = serve(up.path().to_path_buf()).await;
    let cfg = repo(&srv.url, "").replace("\"stable\"", "\"nonexistent\"");
    let r = sync_with(base.path(), &cfg, SyncOptions::default()).await.unwrap();
    assert!(!r.summary.success());
    assert!(r.has_log("no InRelease or Release"));
    let r =
        sync_with(base.path(), &repo(&srv.url, "architectures = [\"riscv64\"]"), SyncOptions::default()).await.unwrap();
    assert!(!r.summary.success());
    assert!(r.has_log("nothing to mirror"));
    let r = sync_ok(base.path(), &repo(&srv.url, "architectures = [\"amd64\", \"s390x\"]")).await;
    assert!(r.has_log("architecture s390x is not published"));
}

#[tokio::test]
async fn dry_run_and_filters() {
    let up = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    Fixture::default().build(
        &up.path().join("repo"),
        "stable",
        &[pkg("alpha", "1.0"), pkg("alpha-dbg", "1.0"), pkg("beta", "1.0")],
    );
    let srv = serve(up.path().to_path_buf()).await;
    let m = base.path().join("mirror/t");
    let r =
        sync_with(base.path(), &repo(&srv.url, ""), SyncOptions { dry_run: true, ..Default::default() }).await.unwrap();
    assert!(r.summary.success());
    assert_eq!(r.summary.repos[0].pending_files, 3);
    assert!(!m.join("dists").exists() && !m.join("pool").exists());
    sync_ok(base.path(), &repo(&srv.url, "exclude_packages = ['-dbg$']")).await;
    assert!(deb_path(&m, "alpha", "1.0").is_file() && deb_path(&m, "beta", "1.0").is_file());
    assert!(!deb_path(&m, "alpha-dbg", "1.0").exists());
}

#[tokio::test]
async fn offline_bundles_round_trip() {
    let up = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    let far = tempfile::tempdir().unwrap();
    let root = up.path().join("repo");
    Fixture { by_hash: true, ..Default::default() }.build(&root, "stable", &[pkg("alpha", "1.0"), pkg("beta", "1.0")]);
    let srv = serve(up.path().to_path_buf()).await;
    let cfg_text = format!("[global]\nbase_path = {:?}\n{}", base.path().to_str().unwrap(), repo(&srv.url, ""));
    let cfg: Config = toml::from_str(&cfg_text).unwrap();
    sync_ok(base.path(), &repo(&srv.url, "")).await;

    let b1 = base.path().join("b1.tar");
    cheval::bundle::create(&cfg.global, &b1, false, None).unwrap();
    cheval::bundle::apply(&b1, &far.path().join("mirror"), false).unwrap();
    let far_cfg: Config =
        toml::from_str(&format!("[global]\nbase_path = {:?}\n{}", far.path().to_str().unwrap(), repo(&srv.url, "")))
            .unwrap();
    assert!(cheval::verify::run(&far_cfg, &[], true).unwrap());

    // Upstream changes: alpha upgraded, beta dropped. The incremental bundle is small.
    Fixture { by_hash: true, date: "Sun, 02 Aug 2026 10:00:00 UTC", ..Default::default() }.build(
        &root,
        "stable",
        &[pkg("alpha", "1.1")],
    );
    sync_ok(base.path(), &repo(&srv.url, "")).await;
    let b2 = base.path().join("b2.tar");
    cheval::bundle::create(&cfg.global, &b2, false, None).unwrap();
    assert!(std::fs::metadata(&b2).unwrap().len() < std::fs::metadata(&b1).unwrap().len());
    cheval::bundle::apply(&b2, &far.path().join("mirror"), false).unwrap();
    let fm = far.path().join("mirror/t");
    assert!(deb_path(&fm, "alpha", "1.1").is_file());
    assert!(!deb_path(&fm, "alpha", "1.0").exists() && !deb_path(&fm, "beta", "1.0").exists());
    assert!(cheval::verify::run(&far_cfg, &[], true).unwrap());

    // A tar that tries to climb out of the destination is refused.
    let evil = base.path().join("evil.tar");
    {
        let mut t = tar::Builder::new(std::fs::File::create(&evil).unwrap());
        for (name, data) in [(".cheval-bundle/info.json", &b"{}"[..]), ("x/../../escape", &b"boom"[..])] {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            // Write the raw name so the tar crate's own `..` guard does not hide the test.
            h.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name.as_bytes());
            h.set_cksum();
            t.append(&h, data).unwrap();
        }
        t.finish().unwrap();
    }
    assert!(cheval::bundle::apply(&evil, &far.path().join("mirror"), false).is_err());
    assert!(!far.path().join("escape").exists());
}
