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
            let _one = GPG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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

// ---------------------------------------------------------------- status stream (v0.6.0)

use cheval::status::{Body, Hub, MAX_DATAGRAM, Message, Reporter};
use std::time::{Duration, Instant};

/// Collect datagrams arriving on a fresh loopback UDP port.
async fn udp_collector() -> (u16, Arc<Mutex<Vec<String>>>) {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let got = Arc::new(Mutex::new(Vec::new()));
    let sink = got.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, _)) = sock.recv_from(&mut buf).await {
            sink.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).into_owned());
        }
    });
    (port, got)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn status_config(base: &Path, repos: &str, status: &str) -> Arc<Config> {
    let text = format!(
        "[global]\nbase_path = {:?}\nretry_delay_ms = 5\nretries = 3\nstall_timeout_secs = 5\n{repos}\n{status}",
        base.to_str().unwrap()
    );
    let cfg: Config = toml::from_str(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
    cfg.validate().unwrap();
    Arc::new(cfg)
}

/// What `cheval sync` does when sinks are configured.
async fn sync_reported(cfg: Arc<Config>) -> (Summary, Arc<Hub>) {
    let names: Vec<String> = cfg.repos.iter().map(|r| r.name.clone()).collect();
    let progress = Progress::new(&names);
    let hub = Hub::new(&cfg.status).unwrap();
    let reporter = Reporter::spawn(hub.clone(), progress.clone(), false);
    let summary = sync::run(cfg, SyncOptions::default(), progress, CancellationToken::new()).await.unwrap();
    reporter.finish_with(Some(&summary), None).await;
    hub.close(Duration::from_secs(2)).await;
    (summary, hub)
}

async fn http_get(addr: std::net::SocketAddr, request: &str) -> (u16, String) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    let text = String::from_utf8_lossy(&out).into_owned();
    let code = text.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    (code, body)
}

fn get(path: &str, token: Option<&str>) -> String {
    let auth = token.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
    format!("GET {path} HTTP/1.1\r\nHost: x\r\n{auth}\r\n")
}

fn three_packages(up: &Path) {
    Fixture::default().build(
        &up.join("repo"),
        "stable",
        &[pkg("alpha", "1.0"), pkg("beta", "2.0"), pkg("gamma", "3.0")],
    );
}

#[tokio::test]
async fn status_stream_reports_a_sync_as_json_and_syslog() {
    let (up, base) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    three_packages(up.path());
    let srv = serve(up.path().to_path_buf()).await;
    let (json_port, json) = udp_collector().await;
    let (syslog_port, syslog) = udp_collector().await;
    let cfg = status_config(
        base.path(),
        &repo(&srv.url, ""),
        &format!(
            "[status]\ninterval_ms = 200\nhost = \"mirror01\"\n\
             [[status.sink]]\nurl = \"udp://127.0.0.1:{json_port}\"\nformat = \"json\"\n\
             [[status.sink]]\nurl = \"udp://127.0.0.1:{syslog_port}\"\nformat = \"syslog\"\nfacility = \"local3\"\n"
        ),
    );
    let (summary, hub) = sync_reported(cfg).await;
    assert!(summary.success());
    assert_eq!(hub.dropped(), 0);
    wait_for("the end message", || json.lock().unwrap().iter().filter(|d| d.contains("\"type\":\"end\"")).count() == 3)
        .await;

    let datagrams = json.lock().unwrap().clone();
    let msgs: Vec<Message> = datagrams
        .iter()
        .map(|d| {
            assert!(d.len() <= MAX_DATAGRAM, "{} byte datagram", d.len());
            serde_json::from_str(d).unwrap_or_else(|e| panic!("{e}: {d}"))
        })
        .collect();
    // One session, one run, sequence numbers without gaps (the end message is sent three times).
    assert!(msgs.iter().all(|m| m.v == 1 && m.host == "mirror01" && m.sid == msgs[0].sid && m.run == msgs[0].run));
    assert!(msgs[0].run.starts_with('r') && msgs[0].run.ends_with('Z'));
    let mut seqs: Vec<u64> = msgs.iter().map(|m| m.seq).collect();
    seqs.dedup();
    assert_eq!(seqs, (1..=seqs.len() as u64).collect::<Vec<_>>());
    assert!(matches!(msgs[0].body, Body::Run(_)), "progress is the first thing sent");

    let last_repo =
        msgs.iter().rev().find_map(|m| if let Body::Repo(r) = &m.body { Some(r.clone()) } else { None }).unwrap();
    assert_eq!((last_repo.name.as_str(), last_repo.phase.as_str()), ("t", "done"));
    assert_eq!((last_repo.suites_ok, last_repo.suites_failed), (Some(1), Some(0)));
    // Packages and the index files fetched for them.
    let fetched = summary.repos[0].files_fetched;
    assert!(fetched >= 3);
    assert_eq!(last_repo.files_fetched, fetched);
    assert!(last_repo.bytes_done > 0 && last_repo.bytes_done == last_repo.bytes_total);
    let published = msgs.iter().any(
        |m| matches!(&m.body, Body::Event(e) if e.kind == "suite_ok" && e.repo == "t" && e.text.contains("published")),
    );
    assert!(published, "suite publication is reported as an event");
    let Body::End(end) = &msgs.last().unwrap().body else { panic!("the stream ends with `end`") };
    assert_eq!(
        (end.state.as_str(), end.exit_code, end.repos_ok, end.repos_failed, end.files_fetched),
        ("finished", 0, 1, 0, fetched)
    );

    // last-run.json carries the same object.
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(base.path().join("state/last-run.json")).unwrap()).unwrap();
    assert_eq!(state["end"]["state"], "finished");
    assert_eq!(state["end"]["files_fetched"], fetched);

    // Syslog: RFC 5424, local3 (19) -> info 158; no per-repository lines; one line per datagram.
    wait_for("the syslog end line", || syslog.lock().unwrap().iter().any(|l| l.contains(" end - "))).await;
    let lines = syslog.lock().unwrap().clone();
    let shape =
        regex::Regex::new(r"^<1(58|56|55)>1 \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ mirror01 cheval \d+ (run|event|end) - \S")
            .unwrap();
    for l in &lines {
        assert!(shape.is_match(l) && !l.contains('\n'), "{l}");
    }
    assert!(lines.iter().any(|l| l.contains(" event - [t] suite stable published")), "{lines:#?}");
    assert!(lines.iter().any(|l| l.contains(" end - sync finished in ") && l.contains("1 repos ok, 0 failed")));
    assert_eq!(lines.iter().filter(|l| l.contains(" run - ")).count(), 1, "progress lines are rate-limited");
}

#[tokio::test]
async fn failed_suite_is_reported_with_exit_code_1() {
    let (up, base) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    three_packages(up.path());
    std::fs::remove_file(deb_path(&up.path().join("repo"), "beta", "2.0")).unwrap();
    let srv = serve(up.path().to_path_buf()).await;
    let (port, json) = udp_collector().await;
    let (sys_port, syslog) = udp_collector().await;
    let cfg = status_config(
        base.path(),
        &repo(&srv.url, ""),
        &format!(
            "[status]\ninterval_ms = 200\n[[status.sink]]\nurl = \"udp://127.0.0.1:{port}\"\n\
             [[status.sink]]\nurl = \"udp://127.0.0.1:{sys_port}\"\nformat = \"syslog\"\n"
        ),
    );
    let (summary, _) = sync_reported(cfg).await;
    assert!(!summary.success());
    wait_for("end", || json.lock().unwrap().iter().any(|d| d.contains("\"type\":\"end\""))).await;
    let msgs: Vec<Message> = json.lock().unwrap().iter().map(|d| serde_json::from_str(d).unwrap()).collect();
    let end = msgs.iter().find_map(|m| if let Body::End(e) = &m.body { Some(e.clone()) } else { None }).unwrap();
    assert_eq!((end.state.as_str(), end.exit_code, end.repos_failed), ("failed", 1, 1));
    assert_eq!(end.failed, vec!["t"]);
    assert!(end.files_failed >= 1);
    assert!(msgs.iter().any(|m| matches!(&m.body, Body::Event(e) if e.level == "error" && e.kind == "suite_failed")));
    assert!(msgs.iter().any(|m| matches!(&m.body, Body::Repo(r) if r.phase == "failed" && r.suites_failed == Some(1))));
    wait_for("syslog end", || syslog.lock().unwrap().iter().any(|l| l.contains(" end - "))).await;
    let lines = syslog.lock().unwrap().clone();
    // local0.err = 131
    assert!(
        lines.iter().any(|l| l.starts_with("<131>1 ") && l.contains(" end - sync finished WITH ERRORS")),
        "{lines:#?}"
    );
}

#[tokio::test]
async fn receiver_converges_despite_loss_and_rejects_unsigned_messages() {
    let (up, base) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    three_packages(up.path());
    let srv = serve(up.path().to_path_buf()).await;
    let key = base.path().join("status.key");
    std::fs::write(&key, "a-shared-secret-of-decent-length\n").unwrap();

    let (fwd_port, forwarded) = udp_collector().await;
    let listener = cheval::listen::bind(cheval::listen::Options {
        listen: "udp://127.0.0.1:0".into(),
        http: Some("127.0.0.1:0".parse().unwrap()),
        token: None,
        forward: vec![format!("udp://127.0.0.1:{fwd_port}")],
        hmac_key: Some(cheval::status::read_key(&key).unwrap()),
        stale_after: Duration::from_secs(60),
        print: false,
    })
    .await
    .unwrap();
    let (store, rx_addr, http) = (listener.store.clone(), listener.local, listener.http_local.unwrap());
    let stop = CancellationToken::new();
    tokio::spawn(listener.run(stop.clone()));

    // A "diode" that loses every third datagram.
    let lossy = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let lossy_port = lossy.local_addr().unwrap().port();
    let relayed = Arc::new(Mutex::new((0u32, 0u32)));
    let counts = relayed.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, _)) = lossy.recv_from(&mut buf).await {
            let seen = {
                let mut c = counts.lock().unwrap();
                c.0 += 1;
                c.0
            };
            if seen % 3 != 0 {
                lossy.send_to(&buf[..n], rx_addr).await.unwrap();
                counts.lock().unwrap().1 += 1;
            }
        }
    });

    let cfg = status_config(
        base.path(),
        &repo(&srv.url, ""),
        &format!(
            "[status]\ninterval_ms = 200\n[[status.sink]]\nurl = \"udp://127.0.0.1:{lossy_port}\"\nhmac_key_file = {:?}\n",
            key.to_str().unwrap()
        ),
    );
    let (summary, _) = sync_reported(cfg).await;
    assert!(summary.success());
    wait_for("the receiver to see the end of the run", || matches!(store.status().map(|m| m.body), Some(Body::End(_))))
        .await;

    // The receiver ends up with the true final state although a third of the stream is gone.
    let Some(Body::End(end)) = store.status().map(|m| m.body) else { unreachable!() };
    let fetched = summary.repos[0].files_fetched;
    assert_eq!((end.state.as_str(), end.repos_ok, end.files_fetched), ("finished", 1, fetched));
    let repos = store.repos();
    let Body::Repo(r) = &repos[0].body else { panic!() };
    assert_eq!((repos.len(), r.name.as_str(), r.phase.as_str(), r.files_fetched), (1, "t", "done", fetched));
    let rx = store.rx();
    assert!(rx.lost >= 1, "loss must be noticed: {rx:?}");
    assert_eq!(rx.bad_mac, 0);

    // Forgeries and unsigned messages are counted and change nothing.
    let attacker = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let forged = r#"{"v":1,"sid":"evil","seq":1,"ts":"2026-01-01T00:00:00Z","host":"x","type":"end","state":"failed","exit_code":1}"#;
    attacker.send_to(forged.as_bytes(), rx_addr).await.unwrap();
    attacker
        .send_to(format!("{},\"mac\":\"{}\"}}", &forged[..forged.len() - 1], "0".repeat(64)).as_bytes(), rx_addr)
        .await
        .unwrap();
    wait_for("the forgeries to be rejected", || store.rx().bad_mac == 2).await;
    let Some(Body::End(still)) = store.status().map(|m| m.body) else { panic!() };
    assert_eq!(still.state, "finished");

    // The receiving side's HTTP API tells the same story, plus what it knows about the link.
    let (code, body) = http_get(http, &get("/v1/status", None)).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|e| panic!("{e}: {body}"));
    assert_eq!(code, 200);
    assert_eq!(v["role"], "receiver");
    assert_eq!(v["status"]["type"], "end");
    assert_eq!(v["status"]["state"], "finished");
    assert_eq!(v["receiver"]["stale"], false);
    assert_eq!(v["receiver"]["bad_mac"], 2);
    assert!(v["receiver"]["lost"].as_u64().unwrap() >= 1);
    let (_, body) = http_get(http, &get("/v1/repos/t", None)).await;
    assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["phase"], "done");
    let (code, _) = http_get(http, &get("/v1/repos/nope", None)).await;
    assert_eq!(code, 404);
    let (_, body) = http_get(http, &get("/metrics", None)).await;
    assert!(body.contains("cheval_status_stale 0") && body.contains("cheval_last_run_success 1"), "{body}");
    assert!(body.contains("cheval_status_bad_mac_total 2") && body.contains("cheval_repo_failed{repo=\"t\"} 0"));

    // --forward passes on exactly the accepted datagrams, signature intact.
    let accepted = store.rx().accepted as usize;
    wait_for("forwarded copies", || forwarded.lock().unwrap().len() == accepted).await;
    let key_bytes = cheval::status::read_key(&key).unwrap();
    assert!(forwarded.lock().unwrap().iter().all(|d| cheval::status::verify(d, &key_bytes).is_some()));
    assert!(relayed.lock().unwrap().1 as usize >= accepted);
    stop.cancel();
}

#[tokio::test]
async fn dead_or_stuck_status_peers_never_slow_or_fail_the_sync() {
    let (up, base) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    three_packages(up.path());
    let srv = serve(up.path().to_path_buf()).await;
    // A TCP peer that accepts and then never reads, one that refuses, and a UDP port nobody listens on.
    let stuck = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stuck_port = stuck.local_addr().unwrap().port();
    let held = Arc::new(Mutex::new(Vec::new()));
    let hold = held.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = stuck.accept().await {
            hold.lock().unwrap().push(s);
        }
    });
    let (refused, nobody) = (free_port(), free_port());
    let cfg = status_config(
        base.path(),
        &repo(&srv.url, ""),
        &format!(
            "[status]\ninterval_ms = 200\n\
             [[status.sink]]\nurl = \"tcp://127.0.0.1:{stuck_port}\"\n\
             [[status.sink]]\nurl = \"tcp://127.0.0.1:{refused}\"\nformat = \"syslog\"\n\
             [[status.sink]]\nurl = \"udp://127.0.0.1:{nobody}\"\nrepeat = 3\n\
             [[status.sink]]\nurl = \"udp://name.that.does.not.resolve.invalid:514\"\nformat = \"syslog\"\n"
        ),
    );
    let started = Instant::now();
    let (summary, hub) = sync_reported(cfg).await;
    assert!(summary.success(), "{}", summary.render());
    assert!(deb_path(&base.path().join("mirror/t"), "alpha", "1.0").is_file());
    // hub.close waits at most 2 s for the dead sinks; the mirror itself is not held up.
    assert!(started.elapsed() < Duration::from_secs(8), "took {:?}", started.elapsed());
    assert!(hub.dropped() > 0, "undeliverable messages are counted");
    assert_eq!(held.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn tcp_sink_writes_ndjson_and_receiver_reads_it() {
    let (up, base) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    three_packages(up.path());
    let srv = serve(up.path().to_path_buf()).await;
    let listener = cheval::listen::bind(cheval::listen::Options {
        listen: "tcp://127.0.0.1:0".into(),
        http: None,
        token: None,
        forward: vec![],
        hmac_key: None,
        stale_after: Duration::from_secs(60),
        print: false,
    })
    .await
    .unwrap();
    let (store, addr) = (listener.store.clone(), listener.local);
    let stop = CancellationToken::new();
    tokio::spawn(listener.run(stop.clone()));
    let cfg = status_config(
        base.path(),
        &repo(&srv.url, ""),
        &format!("[status]\ninterval_ms = 200\n[[status.sink]]\nurl = \"tcp://{addr}\"\n"),
    );
    let (summary, hub) = sync_reported(cfg).await;
    assert!(summary.success());
    assert_eq!(hub.dropped(), 0);
    wait_for("end over TCP", || matches!(store.status().map(|m| m.body), Some(Body::End(_)))).await;
    let rx = store.rx();
    assert_eq!((rx.lost, rx.malformed), (0, 0), "{rx:?}");
    assert_eq!(rx.duplicates, 2, "the end message is written three times");
    stop.cancel();
}

#[tokio::test]
async fn daemon_runs_then_heartbeats_and_serves_the_api_and_silence_turns_stale() {
    let (up, base) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    three_packages(up.path());
    let srv = serve(up.path().to_path_buf()).await;
    let listener = cheval::listen::bind(cheval::listen::Options {
        listen: "udp://127.0.0.1:0".into(),
        http: None,
        token: None,
        forward: vec![],
        hmac_key: None,
        stale_after: Duration::from_millis(2500),
        print: false,
    })
    .await
    .unwrap();
    let (far, far_addr) = (listener.store.clone(), listener.local);
    let far_stop = CancellationToken::new();
    tokio::spawn(listener.run(far_stop.clone()));

    let api_port = free_port();
    let api: std::net::SocketAddr = format!("127.0.0.1:{api_port}").parse().unwrap();
    let cfg = status_config(
        base.path(),
        &repo(&srv.url, ""),
        &format!(
            "[status]\ninterval_ms = 200\nheartbeat_secs = 1\n\
             [[status.sink]]\nurl = \"udp://{far_addr}\"\nrepeat = 2\n\
             [status.http]\nlisten = \"{api}\"\ntoken = \"s3cret-token\"\n"
        ),
    );
    let stop = CancellationToken::new();
    let reload = cfg.clone();
    let daemon = tokio::spawn(cheval::daemon::run((*cfg).clone(), move || Ok((*reload).clone()), true, stop.clone()));

    // The run happens, then the daemon settles into heartbeats that remember its result.
    wait_for(
        "an idle heartbeat after the run",
        || matches!(far.status().map(|m| m.body), Some(Body::Heartbeat(h)) if h.last_run.is_some()),
    )
    .await;
    assert!(deb_path(&base.path().join("mirror/t"), "gamma", "3.0").is_file(), "the daemon really mirrored");
    let Some(Body::Heartbeat(hb)) = far.status().map(|m| m.body) else { unreachable!() };
    let last = hb.last_run.unwrap();
    assert_eq!((last.state.as_str(), last.exit_code, last.repos_ok, last.repos_failed), ("finished", 0, 1, 0));
    assert!(last.run.starts_with('r'));
    assert_eq!(hb.repos_total, 1);
    assert!(hb.next_run.is_none(), "no schedule configured");
    // The fixture's Release is dated 1 Aug 2026; the mirror's copy is that old.
    assert!(hb.oldest_release_age_s.unwrap() > 86_400);
    assert!(matches!(far.last_end().map(|m| m.body), Some(Body::End(e)) if e.state == "finished"));
    let first = far.status().unwrap().seq;
    wait_for("heartbeats to keep coming", || far.status().is_some_and(|m| m.seq > first + 2)).await;
    assert!(!far.stale());
    assert!(far.rx().duplicates > 0 && far.rx().lost == 0, "repeat = 2 arrives twice: {:?}", far.rx());
    wait_for("the idle repository refresh", || {
        matches!(far.repo("t").map(|m| m.body), Some(Body::Repo(r)) if r.release_age_s.is_some() && r.phase == "done")
    })
    .await;

    // Sender-side API: token required, read-only, same data.
    let (code, _) = http_get(api, &get("/v1/status", None)).await;
    assert_eq!(code, 401);
    let (code, _) = http_get(api, &get("/v1/status", Some("wrong"))).await;
    assert_eq!(code, 401);
    let (code, body) = http_get(api, &get("/healthz", None)).await;
    assert_eq!((code, body.as_str()), (200, "ok\n"));
    let (code, body) = http_get(api, &get("/v1/status", Some("s3cret-token"))).await;
    assert_eq!(code, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["role"], "sender");
    assert_eq!(v["status"]["type"], "heartbeat");
    assert_eq!(v["status"]["last_run"]["state"], "finished");
    assert!(v["last_end"]["files_fetched"].as_u64().unwrap() >= 3);
    assert_eq!(v["sender"]["sinks"][0]["dropped"], 0);
    assert!(v["sender"]["sinks"][0]["sent"].as_u64().unwrap() > 5);
    let (_, body) = http_get(api, &get("/v1/events?since=0", Some("s3cret-token"))).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let events = v["events"].as_array().unwrap();
    assert!(events.iter().any(|e| e["text"].as_str().unwrap().contains("daemon started")));
    assert!(events.iter().any(|e| e["kind"] == "suite_ok"));
    let next = v["next"].as_u64().unwrap();
    let (_, body) = http_get(api, &get(&format!("/v1/events?since={next}"), Some("s3cret-token"))).await;
    assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["events"].as_array().unwrap().len(), 0);
    let (code, _) = http_get(api, &get("/v1/events?since=abc", Some("s3cret-token"))).await;
    assert_eq!(code, 400);
    let (code, _) =
        http_get(api, "POST /v1/status HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer s3cret-token\r\n\r\n").await;
    assert_eq!(code, 405);
    let (code, _) = http_get(api, &get("/v1/nothing", Some("s3cret-token"))).await;
    assert_eq!(code, 404);
    let (_, body) = http_get(api, &get("/metrics", Some("s3cret-token"))).await;
    for want in
        ["cheval_up 1", "cheval_run_active 0", "cheval_last_run_success 1", "cheval_sink_dropped_total{sink=\"udp://"]
    {
        assert!(body.contains(want), "missing {want} in\n{body}");
    }
    // /v1/stream delivers live messages as NDJSON.
    let mut s = tokio::net::TcpStream::connect(api).await.unwrap();
    s.write_all(get("/v1/stream", Some("s3cret-token")).as_bytes()).await.unwrap();
    let mut seen = Vec::new();
    let mut buf = [0u8; 4096];
    let until = Instant::now() + Duration::from_secs(10);
    while !String::from_utf8_lossy(&seen).contains("\"type\":\"heartbeat\"") {
        assert!(Instant::now() < until, "no heartbeat on /v1/stream");
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.unwrap().unwrap();
        seen.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&seen).into_owned();
    assert!(text.starts_with("HTTP/1.1 200 OK") && text.contains("application/x-ndjson"));
    drop(s);

    // Stop the daemon: it says goodbye, and after the grace period the far side knows it hears nothing.
    stop.cancel();
    daemon.await.unwrap().unwrap();
    wait_for("the goodbye event", || {
        far.events(0).iter().any(|(_, m)| matches!(&m.body, Body::Event(e) if e.text == "daemon stopping"))
    })
    .await;
    assert!(!far.stale());
    wait_for("staleness", || far.stale()).await;
    assert!(far.age().unwrap() >= Duration::from_millis(2500));
    assert!(tokio::net::TcpStream::connect(api).await.is_err(), "the API is gone with the daemon");
    far_stop.cancel();
}

#[test]
fn status_configuration_is_validated() {
    let check = |extra: &str| {
        let text = format!("[global]\nbase_path = \"/x\"\n{extra}");
        toml::from_str::<Config>(&text).map_err(anyhow::Error::from).and_then(|c| c.validate())
    };
    assert!(check("").is_ok());
    assert!(
        check("[daemon]\nschedule = \"03:17\"\n[status]\n[[status.sink]]\nurl = \"udp://diode:5514\"\nrepeat = 2\n")
            .is_ok()
    );
    assert!(check("[status.http]\nlisten = \"127.0.0.1:8611\"\n").is_ok());
    assert!(check("[status.http]\nlisten = \"0.0.0.0:8611\"\ntoken = \"t\"\n").is_ok());
    for (bad, why) in [
        ("[status.http]\nlisten = \"0.0.0.0:8611\"\n", "not a loopback"),
        ("[status.http]\nlisten = \"localhost\"\n", "ADDRESS:PORT"),
        ("[[status.sink]]\nurl = \"http://x:1\"\n", "udp://"),
        ("[[status.sink]]\nurl = \"udp://x\"\n", "udp://"),
        ("[[status.sink]]\nurl = \"udp://x:0\"\n", "port 0"),
        ("[[status.sink]]\nurl = \"udp://x:1\"\nrepeat = 9\n", "repeat"),
        ("[[status.sink]]\nurl = \"tcp://x:1\"\nrepeat = 2\n", "repeat"),
        ("[[status.sink]]\nurl = \"udp://x:1\"\nformat = \"syslog\"\nfacility = \"nope\"\n", "facility"),
        ("[[status.sink]]\nurl = \"udp://x:1\"\nformat = \"syslog\"\nhmac_key_file = \"/k\"\n", "hmac_key_file"),
        ("[status]\ninterval_ms = 10\n", "interval_ms"),
        ("[daemon]\nschedule = \"whenever\"\n", "schedule"),
    ] {
        let err = format!("{:#}", check(bad).expect_err(bad));
        assert!(err.contains(why), "{bad:?} -> {err}");
    }
}

// ------------------------------------------------------ per-repository bundles (v0.6.1)

fn named_repo(name: &str, url: &str, dir: &str, suite: &str) -> String {
    format!(
        "[[repo]]\nname = \"{name}\"\nurl = \"{url}\"\nsuites = [\"{suite}\"]\ncomponents = [\"main\"]\n\
         architectures = [\"amd64\"]\nmirror_dir = \"{dir}\"\nverify = \"off\"\n"
    )
}

#[tokio::test]
async fn bundles_of_single_repositories() {
    let (up, base, far) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (ra, rb) = (up.path().join("a"), up.path().join("b"));
    Fixture::default().build(&ra, "stable", &[pkg("alpha", "1.0"), pkg("apple", "1.0")]);
    Fixture::default().build(&rb, "stable", &[pkg("beta", "1.0")]);
    let srv = serve(up.path().to_path_buf()).await;
    let host = srv.url.trim_end_matches("/repo").to_string();
    let repos = format!(
        "{}{}{}",
        named_repo("a", &format!("{host}/a"), "a", "stable"),
        named_repo("b", &format!("{host}/b"), "b", "stable"),
        // A second entry on b's upstream directory: it shares b's pool.
        named_repo("b-again", &format!("{host}/b"), "b", "stable"),
    );
    let cfg: Config =
        toml::from_str(&format!("[global]\nbase_path = {:?}\n{repos}", base.path().to_str().unwrap())).unwrap();
    sync_ok(base.path(), &repos).await;
    let (fm, only) = (far.path().join("mirror"), |n: &[&str]| n.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    let tar = |n: &str| base.path().join(n);
    let files_in = |p: &Path| -> Vec<String> {
        let mut ar = tar::Archive::new(std::fs::File::open(p).unwrap());
        ar.entries().unwrap().map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned()).collect()
    };

    // Only repository a crosses; nothing of b is in the file or on the far side.
    cheval::bundle::create_only(&cfg, &only(&["a"]), &tar("a1.tar"), false, None).unwrap();
    let listed = files_in(&tar("a1.tar"));
    assert!(listed.iter().any(|f| f == "a/dists/stable/Release") && listed.iter().any(|f| f.starts_with("a/pool/")));
    assert!(!listed.iter().any(|f| f.starts_with("b/")), "{listed:?}");
    cheval::bundle::apply(&tar("a1.tar"), &fm, false).unwrap();
    assert!(deb_path(&fm.join("a"), "alpha", "1.0").is_file() && !fm.join("b").exists());

    // Repositories sharing a directory cannot be split; unknown names are errors.
    let err = cheval::bundle::create_only(&cfg, &only(&["b"]), &tar("x.tar"), false, None).unwrap_err().to_string();
    assert!(err.contains("b-again") && err.contains("--only b-again"), "{err}");
    assert!(cheval::bundle::create_only(&cfg, &only(&["nope"]), &tar("x.tar"), false, None).is_err());
    assert!(!tar("x.tar").exists());

    // Nothing changed in a: no file. The whole-mirror bundle then carries only what a's did not.
    cheval::bundle::create_only(&cfg, &only(&["a"]), &tar("a2.tar"), false, None).unwrap();
    assert!(!tar("a2.tar").exists());
    cheval::bundle::create(&cfg.global, &tar("all1.tar"), false, None).unwrap();
    let listed = files_in(&tar("all1.tar"));
    assert!(listed.iter().any(|f| f.starts_with("b/pool/")));
    assert!(!listed.iter().any(|f| f.starts_with("a/")), "a was already sent: {listed:?}");
    cheval::bundle::apply(&tar("all1.tar"), &fm, false).unwrap();
    assert!(deb_path(&fm.join("b"), "beta", "1.0").is_file());

    // Both upstreams change. A bundle of b (with its sibling) carries b's change and b's
    // deletion only; a's files on the far side stay exactly as they were.
    Fixture { date: "Sun, 02 Aug 2026 10:00:00 UTC", ..Default::default() }.build(
        &ra,
        "stable",
        &[pkg("alpha", "1.1")],
    );
    Fixture { date: "Sun, 02 Aug 2026 10:00:00 UTC", ..Default::default() }.build(&rb, "stable", &[pkg("beta", "1.1")]);
    sync_ok(base.path(), &repos).await;
    cheval::bundle::create_only(&cfg, &only(&["b", "b-again"]), &tar("b2.tar"), false, None).unwrap();
    assert!(!files_in(&tar("b2.tar")).iter().any(|f| f.starts_with("a/")));
    cheval::bundle::apply(&tar("b2.tar"), &fm, false).unwrap();
    assert!(deb_path(&fm.join("b"), "beta", "1.1").is_file() && !deb_path(&fm.join("b"), "beta", "1.0").exists());
    assert!(deb_path(&fm.join("a"), "alpha", "1.0").is_file() && deb_path(&fm.join("a"), "apple", "1.0").is_file());
    assert!(!deb_path(&fm.join("a"), "alpha", "1.1").exists());

    // a's change was not lost by b's bundle: the next whole-mirror bundle brings it, with a's
    // deletions, and nothing of b again. The far side then verifies in full.
    cheval::bundle::create(&cfg.global, &tar("all2.tar"), false, None).unwrap();
    assert!(!files_in(&tar("all2.tar")).iter().any(|f| f.starts_with("b/")));
    cheval::bundle::apply(&tar("all2.tar"), &fm, false).unwrap();
    assert!(deb_path(&fm.join("a"), "alpha", "1.1").is_file());
    assert!(!deb_path(&fm.join("a"), "alpha", "1.0").exists() && !deb_path(&fm.join("a"), "apple", "1.0").exists());
    let far_cfg: Config =
        toml::from_str(&format!("[global]\nbase_path = {:?}\n{repos}", far.path().to_str().unwrap())).unwrap();
    assert!(cheval::verify::run(&far_cfg, &[], true).unwrap());

    // --full for one repository resends all of it and nothing else.
    cheval::bundle::create_only(&cfg, &only(&["a"]), &tar("afull.tar"), true, None).unwrap();
    let listed = files_in(&tar("afull.tar"));
    assert!(listed.iter().any(|f| f.starts_with("a/pool/")) && !listed.iter().any(|f| f.starts_with("b/")));

    // A bundle that claims to cover a but carries or deletes files elsewhere is refused or ignored.
    let forge = |name: &str, entries: &[(&str, &[u8])]| {
        let p = tar(name);
        let mut t = tar::Builder::new(std::fs::File::create(&p).unwrap());
        for (n, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            t.append_data(&mut h, n, *data).unwrap();
        }
        t.finish().unwrap();
        p
    };
    let info = br#"{"format":1,"scope":["a"],"repos":["a"]}"#;
    let stray = forge("stray.tar", &[(".cheval-bundle/info.json", info), ("b/pool/evil.deb", b"x")]);
    assert!(cheval::bundle::apply(&stray, &fm, false).is_err());
    assert!(!fm.join("b/pool/evil.deb").exists());
    let victim = deb_path(&fm.join("b"), "beta", "1.1");
    let rel = victim.strip_prefix(&fm).unwrap().to_string_lossy().into_owned();
    let wipe = forge("wipe.tar", &[(".cheval-bundle/info.json", info), (".cheval-bundle/delete", rel.as_bytes())]);
    cheval::bundle::apply(&wipe, &fm, false).unwrap();
    assert!(victim.is_file(), "a deletion outside the bundle's directories must be ignored");
}

// ---------------------------------------------------- hard links and zstd in bundles (v0.6.2)

#[cfg(unix)]
fn nlink(p: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).unwrap().nlink()
}

fn tar_kinds(path: &Path) -> (usize, usize) {
    let f = std::fs::File::open(path).unwrap();
    let mut r = std::io::BufReader::new(f);
    let zst = std::io::BufRead::fill_buf(&mut r).unwrap().starts_with(&[0x28, 0xb5, 0x2f, 0xfd]);
    let rd: Box<dyn std::io::Read> = if zst { Box::new(zstd::stream::Decoder::new(r).unwrap()) } else { Box::new(r) };
    let mut ar = tar::Archive::new(rd);
    let (mut files, mut links) = (0, 0);
    for e in ar.entries().unwrap() {
        let e = e.unwrap();
        if e.header().entry_type().is_hard_link() {
            links += 1;
        } else {
            files += 1;
        }
    }
    (files, links)
}

#[cfg(unix)]
#[tokio::test]
async fn bundles_keep_hard_links_and_can_be_compressed() {
    let (up, base) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let root = up.path().join("repo");
    // Enough packages (each with an incompressible SHA256) that the compressed indices exceed
    // the 4 KiB below which links are not worth it.
    let pkgs: Vec<_> = (0..300).map(|i| pkg(String::leak(format!("package-number-{i:03}")), "1.0")).collect();
    Fixture { by_hash: true, ..Default::default() }.build(&root, "stable", &pkgs);
    let srv = serve(up.path().to_path_buf()).await;
    let cfg: Config =
        toml::from_str(&format!("[global]\nbase_path = {:?}\n{}", base.path().to_str().unwrap(), repo(&srv.url, "")))
            .unwrap();
    sync_ok(base.path(), &repo(&srv.url, "")).await;
    // The mirror stores each index once and its by-hash names as hard links.
    let mirror = base.path().join("mirror");
    let linked: Vec<PathBuf> = walkdir::WalkDir::new(&mirror)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && nlink(e.path()) > 1 && e.metadata().unwrap().len() >= 4096)
        .map(|e| e.into_path())
        .collect();
    assert!(!linked.is_empty(), "the fixture mirror has hard-linked by-hash files");

    let far_cfg = |dir: &Path| -> Config {
        toml::from_str(&format!("[global]\nbase_path = {:?}\n{}", dir.to_str().unwrap(), repo(&srv.url, ""))).unwrap()
    };
    let opts = |m: &str, links: bool, compress: Option<i32>| cheval::bundle::CreateOptions {
        full: true,
        manifest: Some(base.path().join(m)),
        hard_links: links,
        compress,
        checksum_file: true,
        progress: cheval::meter::Progress::Auto,
    };
    let (plain, zst, copies) = (base.path().join("b.tar"), base.path().join("b.tar.zst"), base.path().join("c.tar"));
    cheval::bundle::create_with(&cfg, &[], &plain, &opts("m1", true, None)).unwrap();
    cheval::bundle::create_with(&cfg, &[], &zst, &opts("m2", true, Some(3))).unwrap();
    cheval::bundle::create_with(&cfg, &[], &copies, &opts("m3", false, None)).unwrap();

    let (files, links) = tar_kinds(&plain);
    assert!(links >= 1, "hard-linked names travel as link entries");
    assert_eq!(tar_kinds(&zst), (files, links));
    assert_eq!(tar_kinds(&copies), (files + links, 0), "--no-hard-links writes copies");
    let size = |p: &Path| std::fs::metadata(p).unwrap().len();
    assert!(size(&plain) < size(&copies));
    assert_eq!(&std::fs::read(&zst).unwrap()[..4], &[0x28, 0xb5, 0x2f, 0xfd]);

    // Every variant applies to a mirror that verifies; the linked ones keep the links.
    for (bundle, keeps_links) in [(&plain, true), (&zst, true), (&copies, false)] {
        let far = tempfile::tempdir().unwrap();
        cheval::bundle::apply(bundle, &far.path().join("mirror"), false).unwrap();
        assert!(cheval::verify::run(&far_cfg(far.path()), &[], true).unwrap(), "{}", bundle.display());
        let rel = linked[0].strip_prefix(&mirror).unwrap();
        assert_eq!(nlink(&far.path().join("mirror").join(rel)) > 1, keeps_links, "{}", bundle.display());
        assert_eq!(std::fs::read(far.path().join("mirror").join(rel)).unwrap(), std::fs::read(&linked[0]).unwrap());
    }

    // A link may only point at a file the bundle placed (or one already there), inside its scope.
    let forge = |name: &str, scope: &str, link: (&str, &str)| -> PathBuf {
        let p = base.path().join(name);
        let mut t = tar::Builder::new(std::fs::File::create(&p).unwrap());
        let info = format!(r#"{{"format":2{scope}}}"#);
        let mut h = tar::Header::new_gnu();
        h.set_size(info.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        t.append_data(&mut h, ".cheval-bundle/info.json", info.as_bytes()).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Link);
        h.set_size(0);
        h.set_mode(0o644);
        t.append_link(&mut h, link.0, link.1).unwrap();
        t.finish().unwrap();
        p
    };
    let far = tempfile::tempdir().unwrap();
    let fm = far.path().join("mirror");
    std::fs::create_dir_all(fm.join("b")).unwrap();
    std::fs::write(fm.join("b/secret"), "other repository").unwrap();
    let missing = forge("l1.tar", "", ("t/x", "t/not-there"));
    assert!(cheval::bundle::apply(&missing, &fm, false).is_err());
    let outside = forge("l2.tar", r#","scope":["t"],"repos":["t"]"#, ("t/x", "b/secret"));
    assert!(cheval::bundle::apply(&outside, &fm, false).is_err());
    assert!(!fm.join("t/x").exists());
    let newer = base.path().join("newer.tar");
    {
        let mut t = tar::Builder::new(std::fs::File::create(&newer).unwrap());
        let info = br#"{"format":3}"#;
        let mut h = tar::Header::new_gnu();
        h.set_size(info.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        t.append_data(&mut h, ".cheval-bundle/info.json", &info[..]).unwrap();
        t.finish().unwrap();
    }
    let err = cheval::bundle::apply(&newer, &fm, false).unwrap_err().to_string();
    assert!(err.contains("newer cheval"), "{err}");
    assert!(cheval::bundle::create_with(&cfg, &[], &base.path().join("x"), &opts("m4", true, Some(30))).is_err());
}

// ------------------------------------------------------------ cheval ingest (diode drop folder)

#[tokio::test]
async fn ingest_applies_bundles_in_order_once_they_have_arrived() {
    use cheval::ingest::{Ingest, IngestOptions, VerifyAfter};
    use std::time::Duration;
    let (up, base, far, drop) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let root = up.path().join("repo");
    let srv = serve(up.path().to_path_buf()).await;
    let r = repo(&srv.url, "");
    let cfg: Config =
        toml::from_str(&format!("[global]\nbase_path = {:?}\n{r}", base.path().to_str().unwrap())).unwrap();
    let far_cfg: Config =
        toml::from_str(&format!("[global]\nbase_path = {:?}\n{r}", far.path().to_str().unwrap())).unwrap();
    let out = |n: u32| base.path().join(format!("b{n}.tar"));
    let opts = cheval::bundle::CreateOptions::default();
    // Six upstream states, one bundle each (the last one full).
    for n in 1..=6u32 {
        let date = format!("Sun, 0{n} Aug 2026 10:00:00 UTC");
        Fixture { date: String::leak(date), ..Default::default() }.build(
            &root,
            "stable",
            &[pkg("alpha", String::leak(format!("1.{n}"))), pkg("beta", "1.0")],
        );
        sync_ok(base.path(), &r).await;
        let o = cheval::bundle::CreateOptions { full: n == 6, ..opts.clone() };
        cheval::bundle::create_with(&cfg, &[], &out(n), &o).unwrap();
        assert!(cheval::bundle::checksum_path(&out(n)).is_file(), "bundle {n} has a .sha256 beside it");
        let info = cheval::bundle::read_info(&out(n)).unwrap();
        assert_eq!(info.sequence, Some(n as u64));
        assert_eq!(info.full, n == 1 || n == 6);
    }
    let send = |n: u32, as_name: &str| {
        std::fs::copy(out(n), drop.path().join(as_name)).unwrap();
        std::fs::copy(cheval::bundle::checksum_path(&out(n)), drop.path().join(format!("{as_name}.sha256"))).unwrap();
    };
    let fm = far_cfg.global.mirror_path();
    let new = |gap_wait: Duration| {
        Ingest::new(
            IngestOptions {
                drop: drop.path().to_path_buf(),
                dest: fm.clone(),
                done: drop.path().join("done"),
                failed: drop.path().join("failed"),
                state: far.path().join("state/ingest"),
                settle: Duration::ZERO,
                require_checksum: false,
                gap_wait,
                keep_done: 2,
                keep_deleted: false,
                verify: VerifyAfter::Full,
                once: false,
                interval: Duration::from_secs(1),
            },
            Some(far_cfg.clone()),
        )
        .unwrap()
    };
    let record = || -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(far.path().join("state/ingest/ingest.json")).unwrap()).unwrap()
    };
    let mut ing = new(Duration::from_secs(3600));

    // 3 arrives first, with a file still being written and a diode temp name: nothing happens.
    send(3, "c.tar");
    std::fs::write(drop.path().join("d.tar.partial"), b"half").unwrap();
    let p = ing.pass().unwrap();
    assert!(p.applied.is_empty() && p.failed.is_empty(), "{p:?}");
    assert!(p.waiting.iter().any(|w| w.contains("c.tar") && w.contains("waits for 1..2")), "{p:?}");

    // 1 and 2 arrive (out of name order): 1, 2, 3 are applied in sequence, then verified.
    send(2, "a.tar");
    send(1, "z.tar");
    let p = ing.pass().unwrap();
    assert_eq!(p.applied, vec!["z.tar", "a.tar", "c.tar"], "{p:?}");
    assert_eq!(p.verify_ok, Some(true));
    assert!(deb_path(&fm.join("t"), "alpha", "1.3").is_file());
    assert!(!deb_path(&fm.join("t"), "alpha", "1.2").exists(), "deletions applied");
    assert!(!drop.path().join("z.tar").exists() && !drop.path().join("z.tar.sha256").exists());
    // Only the newest two applied bundles are kept.
    assert!(!drop.path().join("done/z.tar").exists() && drop.path().join("done/c.tar").exists());
    assert!(drop.path().join("d.tar.partial").exists(), "temp names are left alone");

    // The diode repeats 2: set aside, not applied again.
    send(2, "a-again.tar");
    let p = ing.pass().unwrap();
    assert_eq!(p.set_aside, vec!["a-again.tar"]);
    assert!(p.applied.is_empty());

    // 4 arrives damaged (cut short): it is caught by its checksum and changes nothing.
    let bytes = std::fs::read(out(4)).unwrap();
    std::fs::write(drop.path().join("d.tar"), &bytes[..bytes.len() / 2]).unwrap();
    std::fs::copy(cheval::bundle::checksum_path(&out(4)), drop.path().join("d.tar.sha256")).unwrap();
    let p = ing.pass().unwrap();
    assert!(p.applied.is_empty() && p.failed.is_empty(), "first mismatch: maybe still arriving {p:?}");
    let p = ing.pass().unwrap();
    assert_eq!(p.failed, vec!["d.tar"]);
    let reason = std::fs::read_to_string(drop.path().join("failed/d.tar.reason")).unwrap();
    assert!(reason.contains("truncated"), "{reason}");
    assert!(!deb_path(&fm.join("t"), "alpha", "1.4").exists());

    // 5 arrives; 4 never will. It waits, and after the gap wait it is applied with the gap noted.
    send(5, "e.tar");
    let p = ing.pass().unwrap();
    assert!(p.applied.is_empty() && p.waiting.iter().any(|w| w.contains("waits for 4")), "{p:?}");
    std::mem::drop(ing);
    let mut ing = new(Duration::ZERO);
    let p = ing.pass().unwrap();
    assert_eq!(p.applied, vec!["e.tar"]);
    let rec = record();
    let chain = rec["chains"].as_object().unwrap().values().next().unwrap().clone();
    assert_eq!(chain["applied"], 5);
    assert_eq!(chain["missing"], serde_json::json!([4]));

    // A full bundle (6) puts everything right and clears the gap.
    send(6, "f.tar");
    let p = ing.pass().unwrap();
    assert_eq!(p.applied, vec!["f.tar"]);
    assert_eq!(p.verify_ok, Some(true));
    let rec = record();
    let chain = rec["chains"].as_object().unwrap().values().next().unwrap().clone();
    assert_eq!((chain["applied"].clone(), chain["missing"].clone()), (serde_json::json!(6), serde_json::json!([])));
    assert_eq!(rec["applied_total"], 5);
    assert_eq!(rec["failed_total"], 1);

    // A second ingest on the same state is refused while one runs.
    assert!(
        Ingest::new(
            IngestOptions {
                drop: drop.path().to_path_buf(),
                dest: fm.clone(),
                done: drop.path().join("done"),
                failed: drop.path().join("failed"),
                state: far.path().join("state/ingest"),
                settle: Duration::ZERO,
                require_checksum: false,
                gap_wait: Duration::ZERO,
                keep_done: 2,
                keep_deleted: false,
                verify: VerifyAfter::Off,
                once: true,
                interval: Duration::from_secs(1),
            },
            None
        )
        .is_err()
    );
}

#[test]
fn bundles_are_checked_end_to_end_before_anything_is_written() {
    let d = tempfile::tempdir().unwrap();
    // Not a bundle at all.
    let junk = d.path().join("junk.tar");
    std::fs::write(&junk, b"hello").unwrap();
    assert!(cheval::bundle::check(&junk).is_err());
    // A tar that ends before the closing deletion list (cut at an entry boundary).
    let p = d.path().join("cut.tar");
    let mut b = tar::Builder::new(std::fs::File::create(&p).unwrap());
    let mut add = |name: &str, data: &[u8]| {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, data).unwrap();
    };
    add(".cheval-bundle/info.json", br#"{"format":1}"#);
    add("host/pool/a.deb", b"x");
    b.finish().unwrap();
    drop(b);
    let e = cheval::bundle::check(&p).unwrap_err().to_string();
    assert!(e.contains("truncated"), "{e}");
}

// ------------------------------------------------------------------ RPM and files (ISOs)

/// One signer at a time: tests run in parallel, share the throwaway GPG home, and stop its
/// agent after signing, which would break a concurrent signature.
static GPG_LOCK: Mutex<()> = Mutex::new(());

/// Run gpg with the test signer's key.
fn gpg_sign(args: &[&str]) {
    let _one = GPG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let g = gpg().expect("gpg required");
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
    let _ = Command::new("gpgconf").args(["--homedir", g.home.to_str().unwrap(), "--kill", "gpg-agent"]).output();
}

/// A yum repository at `dir`: packages `(name, version, arch)`, gzip'd primary.xml, an
/// updateinfo file, repomd.xml (and repomd.xml.asc when `sign`). Metadata files are named
/// by checksum, as createrepo_c does.
fn rpm_repo(dir: &Path, pkgs: &[(&str, &str, &str)], sign: bool) {
    let _ = std::fs::remove_dir_all(dir.join("repodata"));
    std::fs::create_dir_all(dir.join("repodata")).unwrap();
    let mut primary = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata xmlns=\"http://linux.duke.edu/metadata/common\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" packages=\"{}\">\n",
        pkgs.len()
    );
    for (name, ver, arch) in pkgs {
        let href = format!("Packages/{}/{name}-{ver}.{arch}.rpm", &name[..1]);
        let data = format!("rpm {name} {ver} {arch}").into_bytes();
        std::fs::create_dir_all(dir.join(&href).parent().unwrap()).unwrap();
        std::fs::write(dir.join(&href), &data).unwrap();
        primary.push_str(&format!(
            "<package type=\"rpm\"><name>{name}</name><arch>{arch}</arch><version epoch=\"0\" ver=\"{ver}\" rel=\"1\"/>\
             <checksum type=\"sha256\" pkgid=\"YES\">{}</checksum><summary>s</summary>\
             <size package=\"{}\" installed=\"1\" archive=\"1\"/><location href=\"{href}\"/></package>\n",
            sha256(&data),
            data.len()
        ));
    }
    primary.push_str("</metadata>\n");
    let mut repomd = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<repomd xmlns=\"http://linux.duke.edu/metadata/repo\">\n<revision>1</revision>\n",
    );
    for (kind, name, data) in [
        ("primary", "primary.xml.gz", compress(primary.as_bytes(), ".gz")),
        ("updateinfo", "updateinfo.xml", format!("<updates n=\"{}\"/>", pkgs.len()).into_bytes()),
    ] {
        let sum = sha256(&data);
        let href = format!("repodata/{sum}-{name}");
        std::fs::write(dir.join(&href), &data).unwrap();
        repomd.push_str(&format!(
            "<data type=\"{kind}\"><checksum type=\"sha256\">{sum}</checksum><location href=\"{href}\"/><size>{}</size></data>\n",
            data.len()
        ));
    }
    repomd.push_str("</repomd>\n");
    std::fs::write(dir.join("repodata/repomd.xml"), &repomd).unwrap();
    if sign {
        let r = dir.join("repodata/repomd.xml");
        gpg_sign(&[
            "--armor",
            "--detach-sign",
            "-o",
            dir.join("repodata/repomd.xml.asc").to_str().unwrap(),
            r.to_str().unwrap(),
        ]);
    }
}

fn rpm_entry(url: &str, extra: &str) -> String {
    format!(
        "[[repo]]\nname = \"rocky\"\nformat = \"rpm\"\nurl = \"{url}/pub/rocky/{{release}}/{{repo}}/{{arch}}/os/\"\n\
         releases = [\"9\"]\nrepos = [\"BaseOS\", \"AppStream\"]\narches = [\"x86_64\"]\n{extra}\n"
    )
}

/// Every regular file below `dir`, relative, sorted.
fn tree(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().strip_prefix(dir).unwrap().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[tokio::test]
async fn rpm_repositories_are_mirrored_verbatim_and_updated_safely() {
    let (up, base) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let sign = gpg().is_some();
    let os = |r: &str| up.path().join(format!("pub/rocky/9/{r}/x86_64/os"));
    rpm_repo(&os("BaseOS"), &[("bash", "5.1", "x86_64"), ("tzdata", "2024a", "noarch"), ("bash", "5.1", "src")], sign);
    rpm_repo(&os("AppStream"), &[("vim", "9.0", "x86_64")], sign);
    let srv = serve(up.path().to_path_buf()).await;
    let keyring =
        gpg().map(|g| format!("keyring = {:?}\nverify = \"require\"", g.pubkey.to_str().unwrap())).unwrap_or_default();
    let entry = rpm_entry(&srv.url, &keyring);
    let r = sync_ok(base.path(), &entry).await;
    let mirror = |r: &str| {
        base.path().join(format!("mirror/127.0.0.1:{}/pub/rocky/9/{r}/x86_64/os", srv.url.rsplit(':').next().unwrap()))
    };
    // Everything upstream, byte for byte, except the source package.
    let mut want = tree(&os("BaseOS"));
    want.retain(|f| !f.ends_with(".src.rpm"));
    assert_eq!(tree(&mirror("BaseOS")), want);
    assert_eq!(tree(&mirror("AppStream")), tree(&os("AppStream")));
    for f in want {
        assert_eq!(
            std::fs::read(mirror("BaseOS").join(&f)).unwrap(),
            std::fs::read(os("BaseOS").join(&f)).unwrap(),
            "{f}"
        );
    }
    assert!(r.has_log("9/BaseOS/x86_64 published"), "{}", r.logs.join("\n"));
    if sign {
        assert!(r.has_log("repomd.xml signed by"));
    }
    assert!(r.has_log("skipping 1 source"));

    // Nothing changed: no package is fetched again.
    let before = srv.hits(".rpm");
    let r = sync_ok(base.path(), &entry).await;
    assert_eq!(srv.hits(".rpm"), before);
    assert!(r.has_log("9/BaseOS/x86_64 is up to date"), "{}", r.logs.join("\n"));

    // An update: bash 5.2 replaces 5.1. The old package goes; the previous metadata
    // generation stays one more run for clients that read the old repomd.xml.
    let old_primary: Vec<String> =
        tree(&mirror("BaseOS")).into_iter().filter(|f| f.contains("-primary.xml.gz")).collect();
    rpm_repo(&os("BaseOS"), &[("bash", "5.2", "x86_64"), ("tzdata", "2024a", "noarch")], sign);
    sync_ok(base.path(), &entry).await;
    let now = tree(&mirror("BaseOS"));
    assert!(now.contains(&"Packages/b/bash-5.2.x86_64.rpm".to_string()));
    assert!(!now.contains(&"Packages/b/bash-5.1.x86_64.rpm".to_string()), "{now:?}");
    assert!(now.contains(&old_primary[0]), "previous generation kept: {now:?}");
    assert_eq!(
        std::fs::read(mirror("BaseOS").join("repodata/repomd.xml")).unwrap(),
        std::fs::read(os("BaseOS").join("repodata/repomd.xml")).unwrap()
    );
    // One run later it is gone.
    sync_ok(base.path(), &entry).await;
    assert!(!tree(&mirror("BaseOS")).contains(&old_primary[0]));
}

#[tokio::test]
async fn rpm_failures_keep_the_previous_state_and_stay_contained() {
    let (up, base) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let os = |r: &str| up.path().join(format!("pub/rocky/9/{r}/x86_64/os"));
    rpm_repo(&os("BaseOS"), &[("bash", "5.1", "x86_64")], false);
    rpm_repo(&os("AppStream"), &[("vim", "9.0", "x86_64")], false);
    let srv = serve(up.path().to_path_buf()).await;
    let entry = rpm_entry(&srv.url, "");
    sync_ok(base.path(), &entry).await;
    let port = srv.url.rsplit(':').next().unwrap().to_string();
    let mirror = |r: &str| base.path().join(format!("mirror/127.0.0.1:{port}/pub/rocky/9/{r}/x86_64/os"));
    let old_repomd = std::fs::read(mirror("BaseOS").join("repodata/repomd.xml")).unwrap();

    // BaseOS gets an update whose package is corrupt upstream; AppStream a good one.
    rpm_repo(&os("BaseOS"), &[("bash", "5.2", "x86_64")], false);
    std::fs::write(os("BaseOS").join("Packages/b/bash-5.2.x86_64.rpm"), b"tampered").unwrap();
    rpm_repo(&os("AppStream"), &[("vim", "9.1", "x86_64")], false);
    let r = sync_with(base.path(), &entry, SyncOptions::default()).await.unwrap();
    assert!(!r.summary.success());
    let o = &r.summary.repos[0];
    assert_eq!(o.suites_ok, vec!["9/AppStream/x86_64"]);
    assert_eq!(o.suites_failed.len(), 1, "{:?}", o.suites_failed);
    assert!(o.suites_failed[0].1.contains("NOT published"), "{:?}", o.suites_failed);
    // BaseOS still serves its old, consistent state; the bad file never landed.
    assert_eq!(std::fs::read(mirror("BaseOS").join("repodata/repomd.xml")).unwrap(), old_repomd);
    assert!(mirror("BaseOS").join("Packages/b/bash-5.1.x86_64.rpm").is_file());
    assert!(!mirror("BaseOS").join("Packages/b/bash-5.2.x86_64.rpm").exists());
    assert!(mirror("AppStream").join("Packages/v/vim-9.1.x86_64.rpm").is_file());

    // A metadata file that does not match repomd.xml fails that repository only. (New
    // metadata: files the mirror already has with the right checksum are reused, not fetched.)
    rpm_repo(&os("BaseOS"), &[("bash", "5.1", "x86_64"), ("tzdata", "2024b", "noarch")], false);
    let upd = tree(&os("BaseOS")).into_iter().find(|f| f.ends_with("-updateinfo.xml")).unwrap();
    std::fs::write(os("BaseOS").join(&upd), b"<updates tampered/>").unwrap();
    let r = sync_with(base.path(), &entry, SyncOptions::default()).await.unwrap();
    assert!(!r.summary.success());
    assert_eq!(r.summary.repos[0].suites_ok, vec!["9/AppStream/x86_64"]);
    assert_eq!(std::fs::read(mirror("BaseOS").join("repodata/repomd.xml")).unwrap(), old_repomd);
}

#[tokio::test]
async fn rpm_trust_signatures_and_metalinks() {
    let (up, base) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let os = |r: &str| up.path().join(format!("pub/rocky/9/{r}/x86_64/os"));
    let sign = gpg().is_some();
    rpm_repo(&os("BaseOS"), &[("bash", "5.1", "x86_64")], sign);
    rpm_repo(&os("AppStream"), &[("vim", "9.0", "x86_64")], sign);
    let srv = serve(up.path().to_path_buf()).await;
    if let Some(g) = gpg() {
        // A key that did not sign: refused, nothing published.
        let bad = rpm_entry(&srv.url, &format!("keyring = {:?}", g.other_pubkey.to_str().unwrap()));
        let r = sync_with(base.path(), &bad, SyncOptions::default()).await.unwrap();
        assert!(!r.summary.success());
        assert!(
            r.summary.repos[0].suites_failed.iter().all(|(_, e)| e.contains("does not verify")),
            "{:?}",
            r.summary.repos[0].suites_failed
        );
        assert!(
            !base
                .path()
                .join("mirror")
                .join(format!("127.0.0.1:{}", srv.url.rsplit(':').next().unwrap()))
                .join("pub/rocky/9/BaseOS/x86_64/os/repodata")
                .exists()
        );
    }
    // Metalink (EPEL style, repomd.xml unsigned): the checksum must match.
    let metalink = |dir: &Path, hash: &str| {
        std::fs::write(
            dir.join("metalink.xml"),
            format!(
                "<?xml version=\"1.0\"?><metalink xmlns=\"http://www.metalinker.org/\"><files><file name=\"repomd.xml\">\
                 <verification><hash type=\"sha256\">{hash}</hash></verification></file></files></metalink>"
            ),
        )
        .unwrap();
    };
    for r in ["BaseOS", "AppStream"] {
        let _ = std::fs::remove_file(os(r).join("repodata/repomd.xml.asc"));
        metalink(&os(r), &sha256(&std::fs::read(os(r).join("repodata/repomd.xml")).unwrap()));
    }
    let ml = rpm_entry(
        &srv.url,
        &format!(
            "metalink = \"{}/pub/rocky/{{release}}/{{repo}}/{{arch}}/os/metalink.xml\"\nverify = \"require\"",
            srv.url
        ),
    );
    let base2 = tempfile::tempdir().unwrap();
    sync_ok(base2.path(), &ml).await;
    // A mirror serving a repomd.xml the metalink does not know is refused.
    metalink(&os("BaseOS"), &"0".repeat(64));
    let base3 = tempfile::tempdir().unwrap();
    let r = sync_with(base3.path(), &ml, SyncOptions::default()).await.unwrap();
    assert!(!r.summary.success());
    assert!(
        r.summary.repos[0].suites_failed[0].1.contains("does not match the metalink"),
        "{:?}",
        r.summary.repos[0].suites_failed
    );
    assert_eq!(r.summary.repos[0].suites_ok, vec!["9/AppStream/x86_64"]);
}

#[tokio::test]
async fn iso_folders_take_listed_files_once_and_follow_changes() {
    let (up, base) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let iso = up.path().join("pub/rocky/9/isos/x86_64");
    std::fs::create_dir_all(&iso).unwrap();
    let sign = gpg().is_some();
    // Rocky style: BSD lines with size comments; the `latest` DVD and the versioned DVD are
    // the same file; plus a boot ISO nobody asked for.
    let write = |dvd: &[u8]| {
        let boot = b"boot iso".to_vec();
        std::fs::write(iso.join("Rocky-9-latest-x86_64-dvd.iso"), dvd).unwrap();
        std::fs::write(iso.join("Rocky-9.9-x86_64-dvd.iso"), dvd).unwrap();
        std::fs::write(iso.join("Rocky-9.9-x86_64-boot.iso"), &boot).unwrap();
        let mut list = String::new();
        for (n, d) in [
            ("Rocky-9-latest-x86_64-dvd.iso", dvd.to_vec()),
            ("Rocky-9.9-x86_64-dvd.iso", dvd.to_vec()),
            ("Rocky-9.9-x86_64-boot.iso", boot),
        ] {
            list.push_str(&format!("# {n}: {} bytes\nSHA256 ({n}) = {}\n", d.len(), sha256(&d)));
        }
        std::fs::write(iso.join("CHECKSUM"), list).unwrap();
        if sign {
            let c = iso.join("CHECKSUM");
            gpg_sign(&[
                "--armor",
                "--detach-sign",
                "-o",
                iso.join("CHECKSUM.asc").to_str().unwrap(),
                c.to_str().unwrap(),
            ]);
        }
    };
    write(b"dvd version one");
    let srv = serve(up.path().to_path_buf()).await;
    let keyring = gpg()
        .map(|g| {
            format!("keyring = {:?}\nverify = \"require\"\nsignature = \"CHECKSUM.asc\"", g.pubkey.to_str().unwrap())
        })
        .unwrap_or_default();
    let entry = format!(
        "[[repo]]\nname = \"rocky-isos\"\nformat = \"files\"\nurl = \"{}/pub/rocky/{{release}}/isos/{{arch}}/\"\nreleases = [\"9\"]\narches = [\"x86_64\"]\n\
         checksums = [\"CHECKSUM\"]\ninclude = [\"Rocky-9-latest-x86_64-dvd.iso\", \"Rocky-9.*-x86_64-dvd.iso\"]\n{keyring}\n",
        srv.url
    );
    let r = sync_ok(base.path(), &entry).await;
    if sign {
        assert!(r.has_log("checksums signed by"));
    }
    let port = srv.url.rsplit(':').next().unwrap().to_string();
    let m = base.path().join(format!("mirror/127.0.0.1:{port}/pub/rocky/9/isos/x86_64"));
    let mut want = vec!["CHECKSUM", "Rocky-9-latest-x86_64-dvd.iso", "Rocky-9.9-x86_64-dvd.iso"];
    if sign {
        want.insert(1, "CHECKSUM.asc");
    }
    assert_eq!(tree(&m), want);
    // Downloaded once, stored once.
    assert_eq!(srv.hits("dvd.iso"), 1);
    assert_eq!(nlink(&m.join("Rocky-9.9-x86_64-dvd.iso")), 2);

    // A new release under the same name: fetched again and replaced.
    write(b"dvd version two, a little longer");
    sync_ok(base.path(), &entry).await;
    assert_eq!(std::fs::read(m.join("Rocky-9-latest-x86_64-dvd.iso")).unwrap(), b"dvd version two, a little longer");
    assert_eq!(std::fs::read(m.join("Rocky-9.9-x86_64-dvd.iso")).unwrap(), b"dvd version two, a little longer");

    // A pattern that matches nothing is an error, not silence.
    let typo = entry.replace("Rocky-9-latest-x86_64-dvd.iso", "Rocky-9-lastest-x86_64-dvd.iso");
    let r = sync_with(tempfile::tempdir().unwrap().path(), &typo, SyncOptions::default()).await.unwrap();
    assert!(!r.summary.success());
    assert!(r.summary.repos[0].suites_failed[0].1.contains("matches nothing"));
}

#[tokio::test]
async fn iso_folders_with_clear_signed_gnu_lists_as_the_centos_vault_publishes() {
    let Some(g) = gpg() else {
        eprintln!("gpg not available, skipping");
        return;
    };
    let (up, base) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let iso = up.path().join("7.9.2009/isos/x86_64");
    std::fs::create_dir_all(&iso).unwrap();
    let dvd = b"centos 7 dvd".to_vec();
    std::fs::write(iso.join("CentOS-7-x86_64-DVD-2207-02.iso"), &dvd).unwrap();
    std::fs::write(iso.join("sha256sum.txt"), format!("{}  CentOS-7-x86_64-DVD-2207-02.iso\n", sha256(&dvd))).unwrap();
    let t = iso.join("sha256sum.txt");
    gpg_sign(&["--clearsign", "-o", iso.join("sha256sum.txt.asc").to_str().unwrap(), t.to_str().unwrap()]);
    let srv = serve(up.path().to_path_buf()).await;
    let entry = format!(
        "[[repo]]\nname = \"c7-isos\"\nformat = \"files\"\nurl = \"{}/7.9.2009/isos/x86_64/\"\nchecksums = [\"sha256sum.txt\"]\n\
         signature = \"sha256sum.txt.asc\"\ninclude = [\"CentOS-7-x86_64-DVD-2207-02.iso\"]\nkeyring = {:?}\nverify = \"require\"\n",
        srv.url,
        g.pubkey.to_str().unwrap()
    );
    sync_ok(base.path(), &entry).await;
    // The plain list says one thing, the signed copy another: the signed copy wins.
    std::fs::write(iso.join("sha256sum.txt"), format!("{}  CentOS-7-x86_64-DVD-2207-02.iso\n", "0".repeat(64)))
        .unwrap();
    let base2 = tempfile::tempdir().unwrap();
    sync_ok(base2.path(), &entry).await;
}
