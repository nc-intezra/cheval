//! Configuration file model (TOML).
use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum VerifyMode {
    /// Fail unless a valid signature from the configured keyring is present.
    Require,
    /// Verify when a keyring is configured, warn otherwise.
    #[default]
    Auto,
    /// Never verify signatures (checksums are still enforced).
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CleanMode {
    Off,
    /// Only report what would be removed.
    Report,
    #[default]
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Recheck {
    /// Trust files already present when their size matches.
    #[default]
    Size,
    /// Re-hash every file already present (slow, finds silent corruption).
    Hash,
}

fn d_threads() -> usize {
    16
}
fn d_per_host() -> usize {
    8
}
fn d_repo_parallel() -> usize {
    4
}
fn d_retries() -> u32 {
    5
}
fn d_retry_delay() -> u64 {
    1000
}
fn d_connect() -> u64 {
    30
}
fn d_stall() -> u64 {
    60
}
fn d_ua() -> String {
    format!("cheval/{}", env!("CARGO_PKG_VERSION"))
}
fn d_arch() -> Vec<String> {
    vec!["amd64".into()]
}
fn d_true() -> bool {
    true
}
fn d_clean_pct() -> u8 {
    40
}
fn d_byhash_days() -> u64 {
    3
}
fn d_components() -> Vec<String> {
    vec!["main".into()]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Global {
    /// Root directory; `mirror/`, `staging/`, `state/`, `snapshots/` live below it.
    pub base_path: PathBuf,
    pub mirror_path: Option<PathBuf>,
    pub staging_path: Option<PathBuf>,
    pub state_path: Option<PathBuf>,
    pub snapshot_path: Option<PathBuf>,
    /// Total simultaneous downloads.
    #[serde(default = "d_threads")]
    pub threads: usize,
    /// Simultaneous downloads per upstream host.
    #[serde(default = "d_per_host")]
    pub per_host: usize,
    /// Repositories processed in parallel.
    #[serde(default = "d_repo_parallel")]
    pub repo_parallel: usize,
    #[serde(default = "d_retries")]
    pub retries: u32,
    /// First retry delay in milliseconds; doubles on every attempt (max 30 s).
    #[serde(default = "d_retry_delay")]
    pub retry_delay_ms: u64,
    #[serde(default = "d_connect")]
    pub connect_timeout_secs: u64,
    /// Abort a transfer when no data arrives for this long.
    #[serde(default = "d_stall")]
    pub stall_timeout_secs: u64,
    /// Overall download rate limit, e.g. "20M" (bytes per second).
    pub rate_limit: Option<String>,
    /// `"apt"` impersonates apt's own user agent for picky servers.
    #[serde(default = "d_ua")]
    pub user_agent: String,
    /// Explicit proxy URL. Otherwise http_proxy/https_proxy/no_proxy are honoured.
    pub proxy: Option<String>,
    /// Extra PEM CA bundle to trust (TLS-intercepting proxies, private CAs).
    pub ca_bundle: Option<PathBuf>,
    #[serde(default = "d_arch")]
    pub architectures: Vec<String>,
    #[serde(default)]
    pub verify: VerifyMode,
    #[serde(default)]
    pub clean: CleanMode,
    #[serde(default)]
    pub recheck: Recheck,
    /// Refuse to clean when more than this share of files would be deleted.
    #[serde(default = "d_clean_pct")]
    pub clean_max_percent: u8,
    /// Keep superseded by-hash index files for this many days.
    #[serde(default = "d_byhash_days")]
    pub by_hash_keep_days: u64,
    #[serde(default = "d_true")]
    pub check_valid_until: bool,
    #[serde(default)]
    pub source: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    pub username: Option<String>,
    pub password: Option<String>,
    /// Environment variable holding the password or token.
    pub password_env: Option<String>,
    /// File holding the password or token (first line).
    pub password_file: Option<PathBuf>,
    /// Bearer token (literal). Prefer `password_env`/`password_file` + `bearer = true`.
    pub bearer_token: Option<String>,
    /// Send the secret from password_env/password_file as a Bearer token.
    #[serde(default)]
    pub bearer: bool,
    /// Extra request headers, sent only to the repository's own origin.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// PEM file with client certificate and private key (mutual TLS).
    pub client_cert: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repo {
    pub name: String,
    pub url: String,
    /// Suites/codenames (`bookworm`, `noble-updates`). A value ending in `/`
    /// (for example `./`) denotes a flat repository directory.
    pub suites: Vec<String>,
    #[serde(default = "d_components")]
    pub components: Vec<String>,
    pub architectures: Option<Vec<String>>,
    pub source: Option<bool>,
    /// Mirror debian-installer (udeb) indices and packages.
    #[serde(default)]
    pub installer: bool,
    /// Mirror Packages.diff/ pdiff directories.
    #[serde(default)]
    pub pdiffs: bool,
    /// Restrict i18n Translation files to these languages (default: all).
    pub languages: Option<Vec<String>>,
    /// Keyring file or directory (binary .gpg or armored .asc) for signature checks.
    pub keyring: Option<PathBuf>,
    pub verify: Option<VerifyMode>,
    pub clean: Option<CleanMode>,
    pub check_valid_until: Option<bool>,
    /// Directory below mirror_path. Default `<host>/<url path>` (apt-mirror layout).
    pub mirror_dir: Option<String>,
    /// Only mirror packages whose name matches one of these regexes.
    #[serde(default)]
    pub include_packages: Vec<String>,
    #[serde(default)]
    pub exclude_packages: Vec<String>,
    /// Skip index or pool paths matching these regexes.
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    /// Paths (regex) that may be missing upstream without failing the suite.
    #[serde(default)]
    pub ignore_missing: Vec<String>,
    /// Additional files relative to `url` to copy verbatim (keys, ls-lR.gz, ...).
    #[serde(default)]
    pub extra_files: Vec<String>,
    /// Publish new indices even when some packages could not be fetched.
    #[serde(default)]
    pub publish_partial: bool,
    /// Accept a Release file older than the one already mirrored.
    #[serde(default)]
    pub allow_downgrade: bool,
    pub user_agent: Option<String>,
    pub auth: Option<Auth>,
    #[serde(default = "d_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub global: Global,
    #[serde(default, rename = "repo")]
    pub repos: Vec<Repo>,
    /// Status reporting: one-way UDP/TCP streams and the local HTTP API.
    #[serde(default)]
    pub status: Status,
    /// Settings for `cheval daemon`.
    #[serde(default)]
    pub daemon: Daemon,
}

fn d_interval() -> u64 {
    2000
}
fn d_heartbeat() -> u64 {
    60
}
fn d_repeat() -> u8 {
    1
}
fn d_facility() -> String {
    "local0".into()
}
fn d_syslog_progress() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    /// How often progress is emitted during a run.
    #[serde(default = "d_interval")]
    pub interval_ms: u64,
    /// How often the daemon reports "alive" between runs.
    #[serde(default = "d_heartbeat")]
    pub heartbeat_secs: u64,
    /// Host name put into every message [default: the system host name].
    pub host: Option<String>,
    #[serde(default, rename = "sink")]
    pub sinks: Vec<Sink>,
    pub http: Option<HttpApi>,
}

impl Default for Status {
    fn default() -> Self {
        Status { interval_ms: d_interval(), heartbeat_secs: d_heartbeat(), host: None, sinks: Vec::new(), http: None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SinkFormat {
    /// One JSON object per datagram (UDP) or per line (TCP).
    #[default]
    Json,
    /// RFC 5424 syslog lines written for people.
    Syslog,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sink {
    /// `udp://host:port` (preferred) or `tcp://host:port`. Send-only either way.
    pub url: String,
    #[serde(default)]
    pub format: SinkFormat,
    /// UDP only: send every datagram this many times (loss protection).
    #[serde(default = "d_repeat")]
    pub repeat: u8,
    /// JSON only: file with a shared secret; adds an HMAC-SHA256 `mac` field.
    pub hmac_key_file: Option<PathBuf>,
    /// Syslog only: kern, user, daemon, local0 … local7.
    #[serde(default = "d_facility")]
    pub facility: String,
    /// Syslog only: at most one progress line per this many seconds.
    #[serde(default = "d_syslog_progress")]
    pub syslog_progress_secs: u64,
}

impl Sink {
    /// (is_tcp, "host:port")
    pub fn target(&self) -> Result<(bool, String)> {
        let (tcp, addr) = parse_stream_url(&self.url)?;
        if addr.ends_with(":0") {
            bail!("{:?}: port 0 is not a destination", self.url);
        }
        Ok((tcp, addr))
    }
    pub fn facility_code(&self) -> Result<u8> {
        syslog_facility(&self.facility)
    }
}

/// Split `udp://host:port` / `tcp://host:port` into (is_tcp, "host:port"). Port 0 is allowed
/// here: a listener may ask the system for any free port.
pub fn parse_stream_url(url: &str) -> Result<(bool, String)> {
    let (tcp, rest) = if let Some(r) = url.strip_prefix("udp://") {
        (false, r)
    } else if let Some(r) = url.strip_prefix("tcp://") {
        (true, r)
    } else {
        bail!("{url:?}: expected udp://host:port or tcp://host:port");
    };
    let rest = rest.trim_end_matches('/');
    let port = rest.rsplit_once(':').map(|(h, p)| (h, p.parse::<u16>()));
    match port {
        Some((h, Ok(_))) if !h.is_empty() => Ok((tcp, rest.to_string())),
        _ => bail!("{url:?}: expected udp://host:port or tcp://host:port"),
    }
}

pub fn syslog_facility(name: &str) -> Result<u8> {
    Ok(match name.to_ascii_lowercase().as_str() {
        "kern" => 0,
        "user" => 1,
        "daemon" => 3,
        "auth" => 4,
        "syslog" => 5,
        "cron" => 9,
        l if l.len() == 6 && l.starts_with("local") && l.as_bytes()[5].is_ascii_digit() && l.as_bytes()[5] <= b'7' => {
            16 + (l.as_bytes()[5] - b'0')
        }
        _ => bail!("unknown syslog facility {name:?} (use user, daemon or local0 … local7)"),
    })
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpApi {
    /// Address of the read-only HTTP API, e.g. "127.0.0.1:8611".
    pub listen: String,
    /// Bearer token clients must send. Required when `listen` is not a loopback address.
    pub token: Option<String>,
    pub token_file: Option<PathBuf>,
}

impl HttpApi {
    pub fn addr(&self) -> Result<std::net::SocketAddr> {
        self.listen.parse().with_context(|| format!("status.http.listen {:?}: expected ADDRESS:PORT", self.listen))
    }
    pub fn token(&self) -> Result<Option<String>> {
        read_secret(self.token.as_deref(), self.token_file.as_deref(), "status.http.token_file")
    }
}

/// A literal secret or the first line of a file.
pub fn read_secret(literal: Option<&str>, file: Option<&Path>, what: &str) -> Result<Option<String>> {
    if let Some(t) = literal {
        return Ok(Some(t.to_string()));
    }
    match file {
        Some(f) => {
            let text = std::fs::read_to_string(f).with_context(|| format!("{what}: cannot read {}", f.display()))?;
            let line = text.lines().next().unwrap_or("").trim().to_string();
            if line.is_empty() {
                bail!("{what}: {} is empty", f.display());
            }
            Ok(Some(line))
        }
        None => Ok(None),
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Daemon {
    /// Daily times ("03:17" or "03:17,15:17", local time) or an interval ("6h", "30m").
    /// Without a schedule the daemon only runs on SIGUSR1.
    pub schedule: Option<String>,
    /// Also start a run as soon as the daemon starts.
    #[serde(default)]
    pub run_on_start: bool,
}

pub struct Filters {
    pub include_packages: Vec<Regex>,
    pub exclude_packages: Vec<Regex>,
    pub exclude_paths: Vec<Regex>,
    pub ignore_missing: Vec<Regex>,
}

impl Filters {
    pub fn package_wanted(&self, name: &str) -> bool {
        (self.include_packages.is_empty() || self.include_packages.iter().any(|r| r.is_match(name)))
            && !self.exclude_packages.iter().any(|r| r.is_match(name))
    }
    pub fn path_excluded(&self, path: &str) -> bool {
        self.exclude_paths.iter().any(|r| r.is_match(path))
    }
    pub fn may_be_missing(&self, path: &str) -> bool {
        self.ignore_missing.iter().any(|r| r.is_match(path))
    }
    pub fn filters_packages(&self) -> bool {
        !self.include_packages.is_empty() || !self.exclude_packages.is_empty()
    }
}

fn compile(list: &[String], what: &str, repo: &str) -> Result<Vec<Regex>> {
    list.iter().map(|p| Regex::new(p).with_context(|| format!("repo {repo}: invalid {what} regex {p:?}"))).collect()
}

pub const APT_USER_AGENT: &str = "Debian APT-HTTP/1.3 (2.9.8)";

impl Global {
    pub fn mirror_path(&self) -> PathBuf {
        self.mirror_path.clone().unwrap_or_else(|| self.base_path.join("mirror"))
    }
    pub fn staging_path(&self) -> PathBuf {
        self.staging_path.clone().unwrap_or_else(|| self.base_path.join("staging"))
    }
    pub fn state_path(&self) -> PathBuf {
        self.state_path.clone().unwrap_or_else(|| self.base_path.join("state"))
    }
    pub fn snapshot_path(&self) -> PathBuf {
        self.snapshot_path.clone().unwrap_or_else(|| self.base_path.join("snapshots"))
    }
}

impl Repo {
    /// Repository URL with credentials stripped and a guaranteed trailing slash.
    pub fn base_url(&self) -> Result<Url> {
        let mut u = Url::parse(&self.url).with_context(|| format!("repo {}: bad url", self.name))?;
        if !matches!(u.scheme(), "http" | "https") {
            bail!("repo {}: only http and https URLs are supported (got {})", self.name, u.scheme());
        }
        let _ = u.set_username("");
        let _ = u.set_password(None);
        u.set_query(None);
        u.set_fragment(None);
        if !u.path().ends_with('/') {
            let p = format!("{}/", u.path());
            u.set_path(&p);
        }
        Ok(u)
    }
    /// Credentials embedded in the URL (`https://user:pass@host/`), if any.
    pub fn url_credentials(&self) -> Option<(String, String)> {
        let u = Url::parse(&self.url).ok()?;
        if u.username().is_empty() {
            return None;
        }
        let dec = |s: &str| percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned();
        Some((dec(u.username()), dec(u.password().unwrap_or(""))))
    }
    /// Local root directory of this repository.
    pub fn root(&self, g: &Global) -> Result<PathBuf> {
        let rel = match &self.mirror_dir {
            Some(d) => crate::util::safe_rel_path(d).with_context(|| format!("repo {}: mirror_dir", self.name))?,
            None => {
                let u = self.base_url()?;
                let mut host = u.host_str().unwrap_or("unknown").to_string();
                if let Some(p) = u.port() {
                    host = format!("{host}:{p}");
                }
                let decoded = percent_encoding::percent_decode_str(u.path()).decode_utf8_lossy().into_owned();
                let mut p = PathBuf::from(host);
                let trimmed = decoded.trim_matches('/');
                if !trimmed.is_empty() {
                    p.push(crate::util::safe_rel_path(trimmed)?);
                }
                p
            }
        };
        Ok(g.mirror_path().join(rel))
    }
    pub fn architectures<'a>(&'a self, g: &'a Global) -> &'a [String] {
        self.architectures.as_deref().unwrap_or(&g.architectures)
    }
    pub fn source(&self, g: &Global) -> bool {
        self.source.unwrap_or(g.source)
    }
    pub fn verify(&self, g: &Global) -> VerifyMode {
        self.verify.unwrap_or(g.verify)
    }
    pub fn clean(&self, g: &Global) -> CleanMode {
        self.clean.unwrap_or(g.clean)
    }
    pub fn check_valid_until(&self, g: &Global) -> bool {
        self.check_valid_until.unwrap_or(g.check_valid_until)
    }
    pub fn user_agent(&self, g: &Global) -> String {
        let ua = self.user_agent.clone().unwrap_or_else(|| g.user_agent.clone());
        if ua.eq_ignore_ascii_case("apt") { APT_USER_AGENT.to_string() } else { ua }
    }
    pub fn filters(&self) -> Result<Filters> {
        Ok(Filters {
            include_packages: compile(&self.include_packages, "include_packages", &self.name)?,
            exclude_packages: compile(&self.exclude_packages, "exclude_packages", &self.name)?,
            exclude_paths: compile(&self.exclude_paths, "exclude_paths", &self.name)?,
            ignore_missing: compile(&self.ignore_missing, "ignore_missing", &self.name)?,
        })
    }
    pub fn is_flat(suite: &str) -> bool {
        suite.ends_with('/')
    }
    /// Directory of a suite's metadata relative to the repository root.
    pub fn dist_dir(suite: &str) -> Result<PathBuf> {
        if Self::is_flat(suite) {
            let t = suite.trim_start_matches("./").trim_matches('/');
            if t.is_empty() || t == "." { Ok(PathBuf::new()) } else { crate::util::safe_rel_path(t) }
        } else {
            Ok(Path::new("dists").join(crate::util::safe_rel_path(suite)?))
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("cannot read config file {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("cannot parse config file {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        let g = &self.global;
        if g.threads == 0 || g.per_host == 0 || g.repo_parallel == 0 {
            bail!("threads, per_host and repo_parallel must be at least 1");
        }
        if let Some(r) = &g.rate_limit {
            crate::util::parse_size(r).context("global.rate_limit")?;
        }
        let mut names = HashSet::new();
        for r in &self.repos {
            if r.name.is_empty() || !r.name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
                bail!("repo name {:?} must be non-empty and use only [A-Za-z0-9._-]", r.name);
            }
            if !names.insert(r.name.as_str()) {
                bail!("duplicate repo name {:?}", r.name);
            }
            r.base_url()?;
            r.root(g)?;
            r.filters()?;
            if r.suites.is_empty() {
                bail!("repo {}: at least one suite is required", r.name);
            }
            for s in &r.suites {
                Repo::dist_dir(s).with_context(|| format!("repo {}: suite {s:?}", r.name))?;
            }
            if r.architectures(g).is_empty() && !r.source(g) {
                bail!("repo {}: no architectures and no source — nothing to mirror", r.name);
            }
            for e in &r.extra_files {
                crate::util::safe_rel_path(e).with_context(|| format!("repo {}: extra_files", r.name))?;
            }
            if r.verify(g) == VerifyMode::Require && r.keyring.is_none() {
                bail!("repo {}: verify = \"require\" needs a keyring", r.name);
            }
            if let Some(k) = &r.keyring
                && !k.exists()
            {
                bail!("repo {}: keyring {} does not exist", r.name, k.display());
            }
        }
        self.validate_status()
    }

    /// The `[status]` and `[daemon]` sections.
    pub fn validate_status(&self) -> Result<()> {
        let st = &self.status;
        if st.interval_ms < 200 {
            bail!("status.interval_ms must be at least 200");
        }
        if st.heartbeat_secs == 0 {
            bail!("status.heartbeat_secs must be at least 1");
        }
        for k in &st.sinks {
            let (tcp, _) = k.target().context("status.sink.url")?;
            if !(1..=5).contains(&k.repeat) {
                bail!("status.sink {}: repeat must be between 1 and 5", k.url);
            }
            if tcp && k.repeat != 1 {
                bail!("status.sink {}: repeat only applies to udp:// sinks", k.url);
            }
            k.facility_code().with_context(|| format!("status.sink {}", k.url))?;
            if k.format == SinkFormat::Syslog && k.hmac_key_file.is_some() {
                bail!("status.sink {}: hmac_key_file only applies to format = \"json\"", k.url);
            }
        }
        if let Some(h) = &st.http {
            let addr = h.addr()?;
            if h.token.is_some() && h.token_file.is_some() {
                bail!("status.http: set token or token_file, not both");
            }
            if !addr.ip().is_loopback() && h.token.is_none() && h.token_file.is_none() {
                bail!("status.http.listen {addr} is not a loopback address: set token or token_file");
            }
        }
        if let Some(s) = &self.daemon.schedule {
            crate::daemon::Schedule::parse(s).context("daemon.schedule")?;
        }
        Ok(())
    }
}

pub const EXAMPLE: &str = include_str!("../examples/cheval.toml");

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn example_parses() {
        let cfg: Config = toml::from_str(EXAMPLE).expect("examples/cheval.toml must stay valid");
        assert!(cfg.repos.len() >= 6);
        assert_eq!(cfg.repos[0].root(&cfg.global).unwrap(), PathBuf::from("/srv/cheval/mirror/deb.debian.org/debian"));
        let gl = cfg.repos.iter().find(|r| r.name == "gitlab-ee-trixie").unwrap();
        assert_eq!(
            gl.root(&cfg.global).unwrap(),
            PathBuf::from("/srv/cheval/mirror/packages.gitlab.com/gitlab/gitlab-ee/debian/trixie")
        );
        assert_eq!(Repo::dist_dir("./").unwrap(), PathBuf::new());
        assert_eq!(Repo::dist_dir("sub/dir/").unwrap(), PathBuf::from("sub/dir"));
        assert_eq!(Repo::dist_dir("noble").unwrap(), PathBuf::from("dists/noble"));
        assert!(Repo::dist_dir("../x").is_err());
    }
    #[test]
    fn commented_status_example_is_valid() {
        // The daemon/status block ships commented out; make sure it still parses when enabled.
        let at = EXAMPLE.find("# --- Daemon:").expect("daemon section in the example");
        let setting = Regex::new(r"^# (\[|[a-z_]+\s*=)").unwrap();
        let enabled: String =
            EXAMPLE[at..].lines().filter(|l| setting.is_match(l)).map(|l| &l[2..]).collect::<Vec<_>>().join("\n");
        let text = format!("{}\n{enabled}", &EXAMPLE[..at]);
        let cfg: Config = toml::from_str(&text).unwrap_or_else(|e| panic!("{e}\n{enabled}"));
        cfg.validate_status().unwrap();
        assert_eq!(cfg.daemon.schedule.as_deref(), Some("03:17"));
        assert_eq!(cfg.status.sinks.len(), 3);
        assert_eq!(cfg.status.sinks[2].format, SinkFormat::Syslog);
        assert_eq!(cfg.status.sinks[1].repeat, 2);
        assert_eq!(cfg.status.http.unwrap().listen, "127.0.0.1:8611");
    }

    #[test]
    fn url_credentials_are_stripped() {
        let cfg: Config = toml::from_str("[global]\nbase_path = \"/x\"\n[[repo]]\nname = \"a\"\nurl = \"https://u:p%40ss@h.example:8443/r\"\nsuites = [\"s\"]\n").unwrap();
        let r = &cfg.repos[0];
        assert_eq!(r.base_url().unwrap().as_str(), "https://h.example:8443/r/");
        assert_eq!(r.url_credentials(), Some(("u".into(), "p@ss".into())));
        assert_eq!(r.root(&cfg.global).unwrap(), PathBuf::from("/x/mirror/h.example:8443/r"));
    }
}
