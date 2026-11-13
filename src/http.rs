//! HTTP transfer layer: bounded concurrency, resume, retries, checksum-on-the-fly,
//! and credential-safe redirect handling.
use crate::config::{Global, Repo};
use crate::progress::Progress;
use crate::util::{Checksum, Hasher};
use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::header::{
    AUTHORIZATION, CONTENT_LENGTH, HeaderMap, HeaderName, HeaderValue, LOCATION, RANGE, RETRY_AFTER,
};
use reqwest::{Client, Response, StatusCode};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Debug, Clone)]
pub enum FetchError {
    NotFound(u16),
    Denied(u16),
    Status(u16, Option<u64>),
    Mismatch(String),
    Network(String),
    Io(String),
    Cancelled,
}

impl FetchError {
    pub fn retryable(&self) -> bool {
        match self {
            FetchError::Status(s, _) => matches!(s, 408 | 425 | 429) || *s >= 500,
            FetchError::Mismatch(_) | FetchError::Network(_) => true,
            _ => false,
        }
    }
    pub fn is_not_found(&self) -> bool {
        matches!(self, FetchError::NotFound(_))
    }
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::NotFound(s) => write!(f, "HTTP {s} not found"),
            FetchError::Denied(s) => {
                write!(f, "HTTP {s} access denied (check credentials, user_agent = \"apt\", or proxy allow-lists)")
            }
            FetchError::Status(s, _) => write!(f, "HTTP {s}"),
            FetchError::Mismatch(m) => write!(f, "verification failed: {m}"),
            FetchError::Network(m) => write!(f, "network error: {m}"),
            FetchError::Io(m) => write!(f, "I/O error: {m}"),
            FetchError::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Global token bucket (bytes per second) shared by all transfers.
struct Limiter {
    rate: f64,
    state: tokio::sync::Mutex<(f64, Instant)>,
}

impl Limiter {
    async fn take(&self, n: usize) {
        let wait = {
            let mut st = self.state.lock().await;
            let now = Instant::now();
            let burst = self.rate; // at most one second of burst
            st.0 = (st.0 + now.duration_since(st.1).as_secs_f64() * self.rate).min(burst);
            st.1 = now;
            st.0 -= n as f64;
            if st.0 < 0.0 { -st.0 / self.rate } else { 0.0 }
        };
        if wait > 0.0 {
            tokio::time::sleep(Duration::from_secs_f64(wait)).await;
        }
    }
}

/// Per-repository HTTP context (client identity, credentials, origin).
pub struct RepoHttp {
    pub idx: usize,
    pub base: Url,
    client: Client,
    headers: HeaderMap,
    /// Maximum wait for response headers.
    header_timeout: Duration,
}

/// Characters left unescaped inside a path segment.
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme() && a.host_str() == b.host_str() && a.port_or_known_default() == b.port_or_known_default()
}

impl RepoHttp {
    pub fn new(idx: usize, repo: &Repo, g: &Global) -> Result<RepoHttp> {
        let base = repo.base_url()?;
        let mut b = Client::builder()
            .user_agent(repo.user_agent(g))
            .connect_timeout(Duration::from_secs(g.connect_timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(g.per_host)
            .tcp_keepalive(Duration::from_secs(30));
        if let Some(p) = &g.proxy {
            b = b.proxy(reqwest::Proxy::all(p).context("global.proxy")?);
        }
        if let Some(ca) = &g.ca_bundle {
            let pem = std::fs::read(ca).with_context(|| format!("ca_bundle {}", ca.display()))?;
            for cert in reqwest::Certificate::from_pem_bundle(&pem).context("ca_bundle")? {
                b = b.add_root_certificate(cert);
            }
        }
        let mut headers = HeaderMap::new();
        let mut basic: Option<(String, String)> = repo.url_credentials();
        if let Some(a) = &repo.auth {
            if let Some(c) = &a.client_cert {
                let pem = std::fs::read(c).with_context(|| format!("client_cert {}", c.display()))?;
                b = b.identity(reqwest::Identity::from_pem(&pem).context("client_cert")?);
            }
            let mut secret = a.password.clone();
            if let Some(var) = &a.password_env {
                secret = Some(
                    std::env::var(var)
                        .with_context(|| format!("repo {}: environment variable {var} is not set", repo.name))?,
                );
            }
            if let Some(f) = &a.password_file {
                let t = std::fs::read_to_string(f)
                    .with_context(|| format!("repo {}: password_file {}", repo.name, f.display()))?;
                secret = Some(t.lines().next().unwrap_or("").trim().to_string());
            }
            let bearer = a.bearer_token.clone().or(if a.bearer { secret.clone() } else { None });
            if let Some(tok) = bearer {
                let mut v = HeaderValue::from_str(&format!("Bearer {tok}")).context("bearer token")?;
                v.set_sensitive(true);
                headers.insert(AUTHORIZATION, v);
                basic = None;
            } else if a.username.is_some() || secret.is_some() {
                basic = Some((a.username.clone().unwrap_or_default(), secret.unwrap_or_default()));
            }
            for (k, v) in &a.headers {
                let name = HeaderName::from_bytes(k.as_bytes()).with_context(|| format!("header {k}"))?;
                let mut val = HeaderValue::from_str(v).with_context(|| format!("header {k}"))?;
                val.set_sensitive(true);
                headers.insert(name, val);
            }
        }
        if let Some((u, p)) = basic {
            use std::io::Write;
            let mut enc = Vec::new();
            {
                let mut w = Base64Writer::new(&mut enc);
                write!(w, "{u}:{p}").ok();
                w.finish();
            }
            let mut v =
                HeaderValue::from_str(&format!("Basic {}", String::from_utf8_lossy(&enc))).context("basic auth")?;
            v.set_sensitive(true);
            headers.insert(AUTHORIZATION, v);
        }
        Ok(RepoHttp {
            idx,
            base,
            client: b.build().context("building HTTP client")?,
            headers,
            header_timeout: Duration::from_secs(g.connect_timeout_secs + g.stall_timeout_secs),
        })
    }

    /// URL for a repository-relative path, escaping every segment (so `+`, spaces,
    /// `%` and friends survive S3/GCS style backends).
    pub fn url_for(&self, rel: &str) -> Result<Url> {
        let enc: Vec<String> = rel
            .trim_start_matches("./")
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| utf8_percent_encode(s, SEGMENT).to_string())
            .collect();
        self.base.join(&enc.join("/")).map_err(|e| anyhow!("bad path {rel:?}: {e}"))
    }

    /// URL for a path that is sent verbatim (legacy servers expecting raw `%xx`).
    pub fn url_raw(&self, rel: &str) -> Option<Url> {
        self.base.join(rel.trim_start_matches("./")).ok()
    }

    /// GET following redirects by hand: credentials and custom headers are only
    /// ever sent to the repository's own origin, never to a redirect target.
    pub async fn get(&self, url: &Url, offset: u64) -> Result<Response, FetchError> {
        let mut cur = url.clone();
        for _ in 0..10 {
            let mut req = self.client.get(cur.clone());
            if same_origin(&cur, &self.base) {
                req = req.headers(self.headers.clone());
            }
            if offset > 0 {
                req = req.header(RANGE, format!("bytes={offset}-"));
            }
            let resp = tokio::time::timeout(self.header_timeout, req.send())
                .await
                .map_err(|_| FetchError::Network(format!("no response within {}s", self.header_timeout.as_secs())))?
                .map_err(|e| FetchError::Network(describe(&e)))?;
            if resp.status().is_redirection() && resp.status() != StatusCode::NOT_MODIFIED {
                let loc = resp
                    .headers()
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| FetchError::Network("redirect without Location".into()))?;
                cur = cur.join(loc).map_err(|e| FetchError::Network(format!("bad redirect: {e}")))?;
                if !matches!(cur.scheme(), "http" | "https") {
                    return Err(FetchError::Network(format!("redirect to unsupported scheme {}", cur.scheme())));
                }
                continue;
            }
            return Ok(resp);
        }
        Err(FetchError::Network("too many redirects".into()))
    }
}

fn describe(e: &reqwest::Error) -> String {
    let mut s = e.to_string();
    let mut src = std::error::Error::source(e);
    while let Some(inner) = src {
        let t = inner.to_string();
        if !s.contains(&t) {
            s.push_str(": ");
            s.push_str(&t);
        }
        src = inner.source();
    }
    // Never leak credentials embedded in URLs.
    if let Some(u) = e.url()
        && !u.username().is_empty()
    {
        s = s.replace(u.as_str(), "<url>");
    }
    s
}

/// Minimal base64 encoder (avoids an extra dependency for one header).
struct Base64Writer<'a> {
    out: &'a mut Vec<u8>,
    buf: Vec<u8>,
}
impl<'a> Base64Writer<'a> {
    fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out, buf: Vec::new() }
    }
    fn finish(self) {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for c in self.buf.chunks(3) {
            let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
            self.out.push(T[(n >> 18) as usize & 63]);
            self.out.push(T[(n >> 12) as usize & 63]);
            self.out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] } else { b'=' });
            self.out.push(if c.len() > 2 { T[n as usize & 63] } else { b'=' });
        }
    }
}
impl std::io::Write for Base64Writer<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct Job<'a> {
    pub rh: &'a RepoHttp,
    pub url: Url,
    /// Tried when `url` answers 404 (by-hash → canonical, encoded → raw path).
    pub alt_url: Option<Url>,
    pub dest: &'a Path,
    pub size: Option<u64>,
    pub sum: Option<Checksum>,
    pub label: String,
}

pub struct Net {
    pub progress: Arc<Progress>,
    pub cancel: CancellationToken,
    sem: Arc<Semaphore>,
    host_sems: Mutex<HashMap<String, Arc<Semaphore>>>,
    per_host: usize,
    limiter: Option<Limiter>,
    retries: u32,
    retry_delay: Duration,
    stall: Duration,
}

const UNKNOWN_SIZE_CAP: u64 = 4 << 30;

pub fn part_path(dest: &Path) -> PathBuf {
    let mut s = dest.as_os_str().to_owned();
    s.push(".cheval-part");
    PathBuf::from(s)
}

impl Net {
    pub fn new(g: &Global, progress: Arc<Progress>, cancel: CancellationToken) -> Result<Net> {
        let limiter = match &g.rate_limit {
            Some(r) => {
                let rate = crate::util::parse_size(r)? as f64;
                if rate < 1024.0 {
                    bail!("rate_limit must be at least 1K");
                }
                Some(Limiter { rate, state: tokio::sync::Mutex::new((rate, Instant::now())) })
            }
            None => None,
        };
        Ok(Net {
            progress,
            cancel,
            sem: Arc::new(Semaphore::new(g.threads)),
            host_sems: Mutex::new(HashMap::new()),
            per_host: g.per_host,
            limiter,
            retries: g.retries,
            retry_delay: Duration::from_millis(g.retry_delay_ms),
            stall: Duration::from_secs(g.stall_timeout_secs.max(1)),
        })
    }

    fn host_sem(&self, url: &Url) -> Arc<Semaphore> {
        let key = format!("{}:{}", url.host_str().unwrap_or(""), url.port_or_known_default().unwrap_or(0));
        self.host_sems.lock().unwrap().entry(key).or_insert_with(|| Arc::new(Semaphore::new(self.per_host))).clone()
    }

    /// Download `job.url` to `job.dest` atomically. Returns bytes received.
    pub async fn fetch(&self, job: Job<'_>) -> Result<u64, FetchError> {
        let _h = self.host_sem(&job.url).acquire_owned().await.map_err(|_| FetchError::Cancelled)?;
        let _g = self.sem.acquire().await.map_err(|_| FetchError::Cancelled)?;
        let (id, done) = self.progress.begin(job.rh.idx, job.label.clone(), job.size);
        let res = self.fetch_inner(&job, &done).await;
        self.progress.end(id);
        res
    }

    async fn fetch_inner(&self, job: &Job<'_>, done: &AtomicU64) -> Result<u64, FetchError> {
        let rp = &self.progress.repos[job.rh.idx];
        let mut counted = 0u64; // bytes credited to the repo's progress for this file
        let mut received = 0u64;
        let mut attempt = 0u32;
        let mut url = job.url.clone();
        let mut alt = job.alt_url.clone();
        loop {
            if self.cancel.is_cancelled() {
                return Err(FetchError::Cancelled);
            }
            let r = self.attempt(job, &url, done, &mut counted, &mut received).await;
            let err = match r {
                Ok(()) => return Ok(received),
                Err(e) => e,
            };
            if err.is_not_found()
                && let Some(a) = alt.take()
            {
                url = a;
                continue;
            }
            if !err.retryable() || attempt >= self.retries {
                rp.bytes_done.fetch_sub(counted.min(rp.bytes_done.load(Ordering::Relaxed)), Ordering::Relaxed);
                // A partial file is kept on purpose: the next run resumes it (its checksum
                // is verified at the end, and `clean` removes abandoned parts after a day).
                return Err(err);
            }
            attempt += 1;
            let mut delay = (self.retry_delay * (1u32 << (attempt - 1).min(5))).min(Duration::from_secs(30));
            if let FetchError::Status(_, Some(ra)) = err {
                delay = Duration::from_secs(ra.clamp(1, 300));
            }
            self.progress.debug(
                Some(job.rh.idx),
                format!("{}: {err}; retry {attempt}/{} in {:.1}s", job.label, self.retries, delay.as_secs_f64()),
            );
            tokio::select! {
                _ = self.cancel.cancelled() => return Err(FetchError::Cancelled),
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }

    async fn attempt(
        &self,
        job: &Job<'_>,
        url: &Url,
        done: &AtomicU64,
        counted: &mut u64,
        received: &mut u64,
    ) -> Result<(), FetchError> {
        let io = |e: std::io::Error| FetchError::Io(e.to_string());
        let rp = &self.progress.repos[job.rh.idx];
        let part = part_path(job.dest);
        if let Some(parent) = job.dest.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(io)?;
        }
        let uncount = |counted: &mut u64| {
            rp.bytes_done.fetch_sub((*counted).min(rp.bytes_done.load(Ordering::Relaxed)), Ordering::Relaxed);
            *counted = 0;
            done.store(0, Ordering::Relaxed);
        };

        // Resume a partial file when we know how big the result must be.
        let mut offset = 0u64;
        if let (Some(size), Ok(md)) = (job.size, tokio::fs::metadata(&part).await)
            && md.len() > 0
            && md.len() < size
        {
            offset = md.len();
        }
        let resp = job.rh.get(url, offset).await?;
        let status = resp.status();
        let retry_after = resp.headers().get(RETRY_AFTER).and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());
        match status.as_u16() {
            200 => offset = 0,
            206 if offset > 0 => {}
            404 | 410 => return Err(FetchError::NotFound(status.as_u16())),
            401 | 403 | 407 => return Err(FetchError::Denied(status.as_u16())),
            416 => {
                let _ = tokio::fs::remove_file(&part).await;
                uncount(counted);
                return Err(FetchError::Network("range not satisfiable; restarting".into()));
            }
            s => return Err(FetchError::Status(s, retry_after)),
        }
        if offset == 0 {
            uncount(counted);
            if let (Some(size), Some(cl)) = (
                job.size,
                resp.headers().get(CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok()),
            ) && cl != size
            {
                return Err(FetchError::Mismatch(format!(
                    "upstream offers {cl} bytes, index says {size} (upstream mid-update?)"
                )));
            }
        }

        let mut hasher = job.sum.as_ref().map(|c| Hasher::new(c.algo));
        let mut file = if offset > 0 {
            if let Some(h) = hasher.as_mut() {
                // Fold the already-downloaded prefix into the checksum.
                let p = part.clone();
                let algo = job.sum.as_ref().unwrap().algo;
                let pre = tokio::task::spawn_blocking(move || -> std::io::Result<Hasher> {
                    use std::io::Read;
                    let mut h = Hasher::new(algo);
                    let mut f = std::fs::File::open(p)?;
                    let mut buf = vec![0u8; 1 << 16];
                    loop {
                        let n = f.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        h.update(&buf[..n]);
                    }
                    Ok(h)
                })
                .await
                .map_err(|e| FetchError::Io(e.to_string()))?
                .map_err(io)?;
                *h = pre;
            }
            if *counted < offset {
                rp.bytes_done.fetch_add(offset - *counted, Ordering::Relaxed);
                *counted = offset;
            }
            done.store(offset, Ordering::Relaxed);
            tokio::fs::OpenOptions::new().append(true).open(&part).await.map_err(io)?
        } else {
            tokio::fs::File::create(&part).await.map_err(io)?
        };

        let mut total = offset;
        let limit = job.size.unwrap_or(UNKNOWN_SIZE_CAP);
        let mut stream = resp.bytes_stream();
        loop {
            let next = tokio::select! {
                _ = self.cancel.cancelled() => {
                    let _ = file.flush().await;
                    return Err(FetchError::Cancelled);
                }
                r = tokio::time::timeout(self.stall, stream.next()) => r,
            };
            let chunk = match next {
                Err(_) => {
                    let _ = file.flush().await;
                    return Err(FetchError::Network(format!("stalled for {}s", self.stall.as_secs())));
                }
                Ok(None) => break,
                Ok(Some(Err(e))) => {
                    let _ = file.flush().await;
                    return Err(FetchError::Network(describe(&e)));
                }
                Ok(Some(Ok(c))) => c,
            };
            total += chunk.len() as u64;
            if total > limit {
                drop(file);
                let _ = tokio::fs::remove_file(&part).await;
                uncount(counted);
                return Err(FetchError::Mismatch(format!("body exceeds expected size {limit}")));
            }
            if let Some(h) = hasher.as_mut() {
                h.update(&chunk);
            }
            file.write_all(&chunk).await.map_err(io)?;
            let n = chunk.len() as u64;
            *received += n;
            done.fetch_add(n, Ordering::Relaxed);
            if job.size.is_some() {
                // Files of unknown size (Release, extra files) are not part of the byte budget.
                *counted += n;
                rp.bytes_done.fetch_add(n, Ordering::Relaxed);
            }
            self.progress.net_bytes.fetch_add(n, Ordering::Relaxed);
            rp.net_bytes.fetch_add(n, Ordering::Relaxed);
            if let Some(l) = &self.limiter {
                l.take(chunk.len()).await;
            }
        }
        file.flush().await.map_err(io)?;
        drop(file);

        if let Some(size) = job.size
            && total != size
        {
            if total < size {
                // Short read: keep the part file so the next attempt can resume.
                return Err(FetchError::Network(format!("connection closed at {total}/{size} bytes")));
            }
            let _ = tokio::fs::remove_file(&part).await;
            uncount(counted);
            return Err(FetchError::Mismatch(format!("size {total} != expected {size}")));
        }
        if let (Some(h), Some(c)) = (hasher, job.sum.as_ref()) {
            let got = h.finish();
            if !got.eq_ignore_ascii_case(&c.hex) {
                let _ = tokio::fs::remove_file(&part).await;
                uncount(counted);
                return Err(FetchError::Mismatch(format!("{} is {got}, expected {}", c.algo.release_field(), c.hex)));
            }
        }
        tokio::fs::rename(&part, job.dest).await.map_err(io)?;
        Ok(())
    }
}
