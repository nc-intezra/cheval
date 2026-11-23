# Changelog

## v0.9.0

Package registries, experimental: a chosen set of packages, with everything they depend
on, mirrored under the upstream host names so stock clients work when internal DNS
points those names at the mirror. APT and RPM behaviour is unchanged.

- `format = "crates"`: a sparse cargo index (index.crates.io) and its crate files
  (static.crates.io). `packages` take the newest non-yanked version matching a
  requirement and follow normal, build, optional and target-specific dependencies;
  `lockfiles` read `Cargo.lock`. Crate files are checked against the index's SHA-256;
  index files are rewritten to list only mirrored versions; `config.json` is published
  last
- `format = "go"`: a Go module proxy (proxy.golang.org). `go.sum` input enforces the
  `h1:` hashes of zips and `go.mod` files; `packages` (`module@version`, `@latest`) walk
  `require` lines and take the zips minimal version selection picks; `@v/list` per module
- `format = "maven"`: a Maven 2 repository (repo.maven.apache.org/maven2). POMs,
  artifacts and their `.sha1` (checked), parent POMs, imported BOMs, compile and runtime
  dependencies with exclusions and dependency management; `mvn dependency:list` and
  `dependency:resolve-plugins` output as lock files; `maven-metadata.xml` per artifact;
  Gradle `.module` files when a POM announces them
- Registries are additive: mirrored versions stay listed until their files are deleted.
  Listings are only replaced once every file they name is in place
- An entry may write into several host directories (crates: index and downloads):
  bundles with `--only`, cleanup and repository grouping cover all of them
- `verify` (`--full`), `check` and `sources` (cargo, `GOPROXY` and Maven settings) handle
  the new formats
- `examples/registries.toml`, and `examples/apache-registries.conf` with HTTPS virtual
  hosts for index.crates.io, static.crates.io, proxy.golang.org and repo.maven.apache.org
- New crate `cheval-registry`. Checked against the real clients: `cargo fetch --locked`
  and `cargo generate-lockfile` against a mirror of crates.io, and `go get`/`go run`
  against a mirrored proxy, with the hashes Go records matching cheval's

## v0.8.0

RPM repositories and installer ISOs, experimental. APT behaviour is unchanged.

- `format = "rpm"`: yum/dnf repositories mirrored verbatim. Every metadata file
  `repomd.xml` lists is fetched and checked, packages are checked against `primary.xml`,
  source packages are skipped, and `repomd.xml` is published last. A repository with a
  missing package keeps its previous state; the previous metadata generation stays one
  run for clients mid-update
- Trust: `repomd.xml.asc` with `keyring`, or a Fedora `metalink` checksum (EPEL), or HTTPS
  with a warning; `verify = "require"` needs a keyring or metalink
- `format = "files"`: folders listed in a checksum file (GNU or BSD style; detached or
  clear-signed signature, the signed copy wins), `include` patterns, identical files
  stored once, replaced when upstream changes them. For installer ISOs
- `{release}`, `{repo}`, `{arch}` placeholders with `releases`, `repos`, `arches`: one
  entry covers several repositories; each is published, or fails, on its own
- `verify`, `check`, `sources` (yum `.repo` stanzas), `probe` and `ingest` handle the new
  formats
- Downloads pinned by a checksum may exceed the 4 GiB limit for files of unknown size
- `examples/rpm-targets.toml`: Rocky 9, CentOS Stream 8/9, CentOS 6/7 vaults, EPEL 6-9
  and their DVD ISOs
- New crate `cheval-rpm`; parsers tested against output of the real `createrepo_c`
- The `cross` workflow keeps its binaries and .debs as artifacts for 14 days

## v0.7.1

- Progress on stderr for the long operations outside `sync` (stdout is unchanged;
  `--no-progress` turns it off). On a terminal a bar with share done, bytes, time left,
  files and speed; in a log or pipe one line every 30 seconds, so short runs log nothing
  extra:
  - `bundle apply` (by bytes of the bundle read, exact for zstd too), and `ingest` while it
    checks and applies a bundle
  - `bundle create`: running counts while scanning, then a bar while writing
  - `verify` / `verify --full`: per repository, by files or by bytes hashed
  - `snapshot create`: running counts of files linked (and bytes, if it has to copy)
- `snapshot create` says when it cannot hard-link (snapshot directory on another
  filesystem) and is copying every file instead
- `verify` lists a repository's index problems before its package problems (it now reads
  all of a repository's indices before checking packages, to know the totals)
- Fix: `bundle apply` without `--to` released the mirror lock before applying, so a sync
  could run at the same time; the lock is now held until the apply finishes

## v0.7.0

Two parts: `cheval ingest` and its bundle additions (built after 0.6.2, first released
here; second list below), and a restructuring of the code that changes no behavior. The
restructuring was checked by running the build before it (`db99df6`) and 0.7.0 on the same
repository: mirror, snapshot and ingested trees byte for byte; bundle entries and header;
logs; status stream; every HTTP API endpoint; every command's `--help`.

- The code is now a Cargo workspace: `cheval-core`, `cheval-status`, `cheval-apt`,
  `cheval-bundle`, `cheval-tui`, and the `cheval` binary (see README, Development). This
  prepares a second repository format (RPM) as its own backend crate
- The run summary, run lock and daemon schedule moved into `cheval-core` (unchanged, still
  reachable under their old paths)
- New `cross` workflow: the static release builds and .deb on every push, without
  publishing, so a tag is only pushed on a commit known to build for all three targets
- `examples/apache-cheval.conf`: Apache 2.4 site for serving the mirror, shipped in the .deb
  beside the nginx example

### Also new in 0.7.0 since 0.6.2

- `cheval ingest DROP`: the receiving end of a data diode. Watches a drop folder and
  applies bundles once they have arrived completely (SHA-256 checksum file, or unchanged
  for `--settle`), each read end to end first; applies them by sequence number whatever
  order they arrive in, sets repeats aside, waits `--gap-wait` for missing ones and
  records gaps; moves bundles to `done/` or `failed/` (with a `.reason`); verifies the
  changed repositories; keeps `<state>/ingest/ingest.json` for monitoring. `--once` for
  timers. New unit `cheval-ingest.service`
- `bundle create` writes `OUT.sha256` beside each bundle (`--no-checksum-file` to skip) and
  numbers bundles per manifest (`chain` and `sequence` in `info.json`, counter in
  `<manifest>.seq`). Bundles from older senders are still accepted
- `bundle create` creates the output folder if it does not exist
- `examples/nginx-cheval.conf`: read-only nginx site with cache headers for APT
- README: what a bundle contains, and why `bundle apply` rather than `tar -x`

## v0.6.2

- Bundles keep hard links: files that are links of each other in the mirror (by-hash
  indices, snapshots) are stored once and sent as tar link entries. An Ubuntu security
  bundle went from 431 MiB to 184 MiB. `--no-hard-links` restores full copies. Links can
  only point inside the bundle's scope, and only files of 4 KiB or more are linked
- `bundle create --compress[=LEVEL]`: multithreaded zstd (level 1–19, default 3);
  `bundle apply` detects compressed bundles by itself
- Bundle scans hash files in parallel (up to 8 threads) and hash each inode once
- Bundle format 2 (`info.json`); cheval refuses bundles from a newer format instead of
  applying them partly
- `cheval sync` with the TUI sends the final status (`end` message, syslog summary) when
  the run finishes, not when the TUI is closed
- Repositories whose mirror directories overlap (two suites of one upstream as separate
  `[[repo]]` entries) now sync one after another instead of at the same time, which could
  fetch the same file twice into one place and fail one of them. Other repositories still
  run in parallel
- README artwork: a woodcut-style horse rearing before a cheval mirror, rendered in
  Blender 5.2 from `assets/art/cheval_woodcut.py` (still and animated GIF in `assets/`)
- The README shows the artwork instead of the text logo; the text logo stays in the
  TUI and in `cheval version`

## v0.6.1

- `cheval bundle create --only NAME` (repeatable): bundle single repositories instead of
  the whole mirror. One manifest still records what the destination has; a bundle reads
  and updates only its own part, so per-repository and whole-mirror bundles can be mixed.
  Repositories that share a mirror directory must be named together
- `cheval bundle apply` refuses files, and ignores deletions, outside the directories a
  per-repository bundle says it covers
- Manual page `cheval(1)` with examples; installed by the `.deb`, included in the tarballs
  together with `docs/`

## v0.6.0

Status reporting for monitoring, built for one-way links (data diodes). Mirroring and
bundle-based file transfer are unchanged.

- `cheval daemon`: runs syncs on `[daemon] schedule` (daily times or an interval), starts
  a run on SIGUSR1, re-reads the configuration before each run, sends heartbeats between
  runs. New unit `cheval-daemon.service`
- Status sinks (`[[status.sink]]`): JSON and RFC 5424 syslog over UDP (preferred) or
  write-only TCP. Every message is a full snapshot of at most 1200 bytes with a sequence
  number; optional repeat and HMAC-SHA256 signing. A dead or slow sink never delays a
  sync. `cheval sync` reports to the same sinks
- Read-only HTTP API (`[status.http]`): `/v1/status`, `/v1/repos`, `/v1/events`,
  `/v1/stream`, `/healthz`, `/metrics` (Prometheus)
- `cheval status listen`: receiver for the far side. Progress screen, the same HTTP
  API, loss and duplicate counters, staleness detection, `--forward`, signature check.
  New unit `cheval-status-listen.service`
- `state/last-run.json` gains the `end` object; `cheval check` lists status settings
- Reference: `docs/status-stream.md`
- Logo: framed block logo in the README and in the TUI header (terminals of 34+ rows),
  four-row stencil in the TUI title bar (26+ rows), the version in the TUI footer, and
  `cheval version` (alias `about`) for the stencil and build target. ASCII-only
  fallback where the locale is not UTF-8; `--logo auto|unicode|ascii|off` and
  `CHEVAL_LOGO` override it. `--version` output is unchanged
- Releases now include `.deb` packages for amd64, arm64 and armhf (static binary, systemd units, example
  configuration) and a `SHA256SUMS` file; the release workflow can be re-run for
  an existing tag
- Taking the run lock now retries for two seconds before reporting that another
  instance is running

## v0.5.0 — 2026-11-12

First release.

- Staged, all-or-nothing publishing per suite (by-hash first, `InRelease` last);
  a failed suite keeps its previous state
- Built-in OpenPGP verification of `InRelease` / `Release.gpg`
- Checksum-verified downloads with resume, retries, stall detection, rate limiting
- Classic and flat repositories; sources, udebs, pdiffs, i18n/dep11/cnf/Contents
- Basic / Bearer / header / client-certificate authentication; `user_agent = "apt"`
- Credential-safe redirect handling (object-store and CDN backed repositories)
- Conservative cleaning with a deletion guard and `clean = "report"`
- TUI (ratatui) and plain log mode
- Commands: `sync`, `verify`, `probe`, `import`, `sources`, `snapshot`, `bundle`,
  `check`, `example`

Known limits: HTTP(S) upstreams only; key expiry/revocation is not evaluated;
only archive.ubuntu.com has been exercised as a real upstream so far.
