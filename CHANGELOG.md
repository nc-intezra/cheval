# Changelog

## v0.6.2 (not yet released)

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
