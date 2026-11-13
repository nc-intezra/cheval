# Changelog

## Unreleased

- Releases now include a `.deb` package (static binary, systemd units, example
  configuration) and a `SHA256SUMS` file; the release workflow can be re-run for
  an existing tag

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
