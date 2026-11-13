# cheval

A fast, consistent, verifiable **APT repository mirror** written in Rust, with a
terminal UI. A replacement for `apt-mirror` and Refrapt.

```
┌ cheval · /srv/cheval → /srv/cheval/mirror  RUNNING  elapsed 00:14 ─────────────────────────────┐
│██████████████████████ 72.6%  346.0 MiB / 476.7 MiB                        ▂▄▆▆▇▆▆▇▆▅▆▆▇▆▆▆▇▆│
│↓ 29.8 MiB/s   ETA 00:04   files 149 fetched · 2 present · 308 total   0 failed   1 warnings     │
├ Repositories (3) ──────────────────────────────────────────────────────────────────────────────┤
│ubuntu-backports     downloading  ███████████░░░░░  71.3%  114/206     326.2 MiB / 457.4 MiB     │
│ubuntu-proposed      indices      ████████████████ 100.0%  37/102      19.8 MiB / 19.8 MiB       │
│bad-suite            FAILED       ░░░░░░░░░░░░░░░░   0.0%  0/0         0 B / 0 B                 │
├ Active transfers (8) ──────────────────────────────────────────────────────────────────────────┤
│ubuntu-backpor …/libreoffice-dev-doc_26.2.5.2-0ubuntu0…_all.deb  ██████░░  73% 195.8 MiB  6 MiB/s│
├ Log ───────────────────────────────────────────────────────────────────────────────────────────┤
│00:25:08 [ubuntu-backports] suite noble-backports: signature OK (key F6ECB376…991BC93C)         │
│00:25:08 [bad-suite] suite does-not-exist: no InRelease or Release at https://… (try `probe`)   │
└ q q: stop · ↑↓ PgUp PgDn: scroll log · f: follow · e: warnings only · v: verbose ──────────────┘
```

## Why another mirror tool

| Problem with apt-mirror / Refrapt | What cheval does |
|---|---|
| Mirror is inconsistent while (and after a failed) sync: new indices next to missing packages → clients see `Hash Sum mismatch` / 404 | Indices are staged privately and published **only after every package they reference is present and verified**. by-hash files go first, `InRelease` last. A failed suite keeps its previous, working state. |
| Files are trusted by size, or not checked at all | Every download is checksummed while streaming (SHA-256/512 from the signed index). `--recheck hash` and `cheval verify --full` re-audit what is on disk. |
| No signature checking | Built-in OpenPGP verification of `InRelease` / `Release.gpg` (pure Rust, no `gpgv`). |
| `clean` scripts that delete the wrong things | Deletion only when every repository sharing a directory completed; a percentage guard; `clean = "report"`; superseded by-hash files are kept for a grace period. |
| Interrupted downloads restart; `wget` dependency | HTTP range resume, retries with back-off, `Retry-After`, stall detection; no external tools. |
| Silent failure on wrong URLs/suites; missing indices ignored | Wrong suite, unpublished architecture/component, missing index → explicit errors or warnings and a non-zero exit code. |
| Only `Packages`; i18n/dep11/cnf/Contents incomplete | Everything the `Release` file lists for your components/architectures is mirrored (AppStream `dep11`, `cnf`, `i18n`, `Contents`, optional pdiffs, udebs, sources). |
| Third-party repositories fail (user-agent blocks, redirects to object storage, flat layouts, auth) | Per-repo user agent (`"apt"`), credential-safe redirect following, flat repositories, Basic/Bearer/header/client-certificate auth, `%`/`+`/space-safe URLs, `cheval probe`. |
| Progress per file only, no overview | TUI with byte-accurate progress, speed graph, ETA, per-repository state, live transfers and a scrollable log; plain log mode for cron. |

## Install

```sh
cargo build --release        # Rust 1.89 or newer
install -m755 target/release/cheval /usr/local/bin/
```

The binary is self-contained (rustls for TLS; xz/zstd/bzip2 are compiled in).

## Quick start

```sh
cheval example > /etc/cheval/cheval.toml      # annotated template — edit it
# or convert what you already have:
cheval import /etc/apt/mirror.list            # apt-mirror / Refrapt config
cheval import /etc/apt/sources.list /etc/apt/sources.list.d/*

cheval check                 # validate, show what goes where
cheval sync --dry-run        # fetch indices, report download size, publish nothing
cheval sync                  # TUI on a terminal, plain log otherwise
cheval verify --full         # offline audit of the mirror against its signed indices
cheval sources --base-url http://mirror.lan   # sources.list lines for clients
```

The configuration file is looked up as `-c FILE`, `$CHEVAL_CONFIG`, `./cheval.toml`,
`/etc/cheval/cheval.toml`. A minimal one:

```toml
[global]
base_path = "/srv/cheval"
architectures = ["amd64"]

[[repo]]
name       = "ubuntu"
url        = "http://archive.ubuntu.com/ubuntu"
suites     = ["noble", "noble-updates", "noble-security"]
components = ["main", "restricted", "universe", "multiverse"]
keyring    = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
```

Files land in `/srv/cheval/mirror/<host>/<path>/…` — the same layout apt-mirror uses,
so an existing apt-mirror tree can be adopted: point `base_path` (or `mirror_path`) at
it and the first run only downloads what is missing or wrong.

See [`examples/cheval.toml`](examples/cheval.toml) for every option.

### Commands

| Command | Purpose |
|---|---|
| `sync [--dry-run] [--only NAME]… [--recheck hash] [--no-clean] [--force-clean] [--no-tui] [--exit-when-done] [-v]` | Mirror |
| `verify [--full] [--only NAME]…` | Offline check: signatures, indices, every package present (and hashed with `--full`) |
| `probe URL [SUITE…]` | Inspect an unknown repository, report layout/redirects, print a config snippet |
| `import FILE…` | Convert `sources.list`, deb822 `.sources`, apt-mirror `mirror.list`, Refrapt config |
| `sources --base-url URL [--deb822]` | Client configuration for the mirror |
| `snapshot create [NAME] \| list \| delete NAME` | Hard-linked point-in-time copies |
| `bundle create OUT.tar [--full] \| apply IN.tar [--to DIR]` | Incremental transfer across an air gap |
| `check`, `example` | Validate configuration, print the template |

Exit codes: `0` success, `1` one or more suites failed (previous state kept), `2`
usage/configuration error, `130` interrupted. `state/last-run.json` holds a machine-readable
summary for monitoring; `log/cheval.log` the full log.

### TUI keys

`q q` (twice) or `Ctrl-C` stop cleanly · `↑ ↓ PgUp PgDn Home End` scroll the log ·
`f` follow · `e` warnings and errors only · `v` verbose (retries, per-index details).
After the run the screen stays until `q`/`Enter` (`--exit-when-done` to leave at once).
Without a terminal (cron, systemd, pipes) cheval prints log lines and a status line
every 10 seconds instead.

## How a run works

1. **Release** — `InRelease` (or `Release` + `Release.gpg`) is fetched into `staging/`
   and its signature checked against the repo's `keyring`. Expired (`Valid-Until`) and
   older-than-mirrored Release files are refused (a lagging upstream mirror cannot roll
   you back).
2. **Indices** — every index the Release lists for your components/architectures is
   fetched (via `by-hash` when offered, so an upstream mid-update cannot hand you
   mismatched files), verified against the Release checksums, and kept in staging.
3. **Packages** — the indices are parsed; files already on disk are checked by size
   (or hash); the rest are downloaded with checksum verification into the pool. Pool
   writes are `temp file → rename`, never in place.
4. **Publish** — only if *all* package files of the suite are in place: by-hash
   indices, then canonical indices, then `Release.gpg`, `Release`, `InRelease`.
5. **Clean** — only if every repository sharing the directory completed.

Interrupting at any point leaves the previously published state intact; partial
downloads are resumed by the next run.

## Hard-to-mirror repositories

Start with `cheval probe URL [SUITE]`. It finds the layout (classic or flat), lists
suites, components and architectures, checks whether package downloads are redirected
to another host, and prints a configuration snippet. When it fails it says why
(403 → credentials or user agent; unreachable host → proxy/firewall).

The suite and components are whatever follows the URL in the vendor's own
`deb URL SUITE COMPONENT…` line — `cheval import` reads those files directly.

**GitLab (`packages.gitlab.com`)** — the hosting backend and URL scheme changed in 2026.
For `gitlab-ee`/`gitlab-ce` the distribution codename is now part of the URL and each
distribution is its own repository (they reuse version strings with different content,
so they must not share a pool); `gitlab-runner` has one repository per OS:

```toml
[[repo]]
name = "gitlab-ee-trixie"
url  = "https://packages.gitlab.com/gitlab/gitlab-ee/debian/trixie"
suites = ["trixie"]
components = ["main"]
keyring = "/etc/cheval/keys/gitlab.gpg"   # from https://packages.gitlab.com/gpgkey/gpg.key

[[repo]]
name = "gitlab-runner-debian"
url  = "https://packages.gitlab.com/runner/gitlab-runner/debian"
suites = ["trixie", "bookworm"]
components = ["main"]
keyring = "/etc/cheval/keys/gitlab.gpg"
```

Package downloads are redirected to Google Cloud Storage
(`storage.googleapis.com/packages-ops`): allow that host in your proxy/firewall, or
downloads fail with 503s. cheval follows the redirect and never forwards credentials to
it. The official procedure is documented at <https://docs.gitlab.com/install/mirror/>.
The full `gitlab-ee` history is very large; trim it with `exclude_paths`.

**Flat repositories** (NVIDIA CUDA, many vendor and OBS repositories; `deb URL /` or
`deb URL ./`): use a suite ending in `/`.

```toml
[[repo]]
name = "cuda"
url  = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64"
suites = ["./"]
keyring = "/etc/cheval/keys/cuda-archive-keyring.gpg"
```

Flat repositories without any `Release` file are mirrored from their bare `Packages`
index with a warning (nothing can be authenticated) unless `verify = "require"`.

**Servers that reject unknown clients** (403 on everything): `user_agent = "apt"`.

**Object-store backed repositories** (S3/GCS/Azure, packagecloud, Artifactory, Nexus):
missing optional files answer 403 instead of 404 and file names need strict escaping;
both are handled. For an index or package that is listed but really gone upstream, add
a regex to `ignore_missing` so the suite can still be published.

**Authenticated repositories** — `[repo.auth]`: `username` + `password` /
`password_env` / `password_file` (HTTP Basic), `bearer = true` or `bearer_token`
(Bearer), arbitrary `headers`, `client_cert` (mutual TLS). `https://user:pass@host/…`
URLs work too. Ubuntu Pro (ESM) repositories use Basic auth with the user name
`bearer` and the per-service token from `/etc/apt/auth.conf.d/90ubuntu-advantage`.
Secrets are only ever sent to the repository's own scheme/host/port.

**Proxies and TLS inspection** — `http_proxy`/`https_proxy`/`no_proxy` are honoured,
or set `global.proxy`. Add your inspection CA with `global.ca_bundle`.

**Established channels when HTTP mirroring is not the answer**

* Debian and Ubuntu officially recommend `rsync`/`ftpsync` (Debian) for *full public*
  mirrors; cheval targets partial, private mirrors over HTTP(S).
* Ubuntu Pro has an official air-gap path (`pro` airgapped/`contracts` tooling) if you
  may not copy ESM pockets yourself.
* Vendors with licence-gated repositories (Red Hat style entitlement, NVIDIA
  enterprise, etc.) usually provide offline bundles or a satellite product; mirror
  those only within your licence.
* For a pull-through cache rather than a full mirror, `apt-cacher-ng` or a repository
  manager (Nexus, Artifactory, Pulp, aptly) may fit better.

## Serving the mirror

Any static web server works; point it at `mirror_path` (or at a snapshot):

```nginx
server {
    listen 80;
    root /srv/cheval/mirror;
    autoindex on;
}
```

`cheval sources --base-url http://mirror.lan` prints matching client entries. Clients
keep verifying the **original** archive signatures: the mirror is byte-identical, so no
re-signing and no `trusted=yes` is needed.

## Snapshots — repeatable states

```sh
cheval snapshot create 2026-11-patchday     # hard links: instant, no extra space
cheval snapshot list
```

Published files are never modified in place, so a snapshot is a frozen, exact state of
every repository. Serve `snapshots/<name>/` to pin clients to it, or promote
dev → test → prod by switching a symlink.

## Offline / air-gapped networks

```sh
# connected side
cheval sync
cheval bundle create /media/usb/2026-11-13.tar     # first time: full; later: only changes

# isolated side (same cheval.toml, or --to DIR)
cheval bundle apply /media/usb/2026-11-13.tar
cheval verify --full
```

Bundles are plain tar files ordered so that applying them keeps the destination
consistent, and they carry deletions. The baseline is `state/bundle-manifest.tsv`; keep
one `--manifest` per destination if you feed several sites. Apply bundles in order; if
one is lost, send a `--full` one.

## Scheduling

[`contrib/`](contrib) has a systemd service and timer. With cron:

```cron
17 3 * * *  cheval -c /etc/cheval/cheval.toml sync --no-tui >/dev/null || echo "cheval failed, see /srv/cheval/log/cheval.log"
```

A lock file prevents overlapping runs.

## Filtering

`include_packages` / `exclude_packages` (regex on package names) and `exclude_paths`
(regex on index or pool paths) reduce what is downloaded. The signed indices cannot be
edited, so clients still *see* filtered packages and get a 404 when installing one —
use filters for things nobody installs (debug symbols, old kernels, other flavours).

## Limits and caveats

* HTTP and HTTPS upstreams only (no rsync/ftp); APT repositories only (no RPM).
* Signature checks are cryptographic against the keys in `keyring`; key expiry and
  revocation are not evaluated — keep keyrings current.
* A package replaced upstream under the same file name is swapped atomically, but
  between that moment and the index publish old indices reference the new bytes.
  Repositories that do this habitually (GitLab) are safe when mirrored one distribution
  per repository, as shown above.
* `recheck = "size"` (default) does not notice same-size corruption of files already on
  disk; schedule an occasional `sync --recheck hash` or `verify --full`.

## Development

```sh
cargo test          # unit tests + end-to-end tests against a local fixture server
cargo clippy --all-targets
```

The end-to-end tests cover: consistency after upstream failures, resume/retry,
corruption (upstream and local), by-hash, sources, flat and unsigned repositories,
signature enforcement (needs `gpg` to create test keys), credential handling across
redirects, hostile paths, stale/expired upstreams, cleaning rules, filters and bundles.

## License

MIT — see [LICENSE](LICENSE).
