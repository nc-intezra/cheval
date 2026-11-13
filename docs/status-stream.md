# cheval status stream reference (schema version 1)

Monitoring only. The stream carries small status messages: progress, results and
heartbeats. It never carries mirror content; files cross an air gap with
`cheval bundle create` / `cheval bundle apply`.

## Transport

| Sink | Framing |
|---|---|
| `udp://`, `format = "json"` | one JSON object per datagram |
| `udp://`, `format = "syslog"` | one RFC 5424 message per datagram (RFC 5426) |
| `tcp://`, `format = "json"` | newline-delimited JSON, written only, never read |
| `tcp://`, `format = "syslog"` | RFC 6587 octet counting (`LEN SP MESSAGE`) |

Guarantees:

- Every datagram is at most **1200 bytes**, so it is never fragmented. Long text is cut
  and ends in `…`; a shortened list sets `"truncated": true`.
- The sender never reads from a sink and never waits for one. What cannot be delivered
  is dropped and counted (`dropped` in `run` and `heartbeat`).
- Every message is a complete snapshot. A lost message is repaired by the next one of
  its type; nothing depends on having seen an earlier message.
- `repeat = N` sends each datagram N times. Copies carry the same `seq`; ignore any
  message whose `seq` is not greater than the last one seen for its `sid`.
- The `end` message is sent three times, 150 ms apart.

## Envelope (every JSON message)

| Field | Meaning |
|---|---|
| `v` | schema version, `1`. New fields may be added without changing it: ignore unknown fields |
| `sid` | sender session, new whenever the sending process starts |
| `seq` | counts up by one per message within a `sid`; a gap means loss |
| `run` | id of the run the message belongs to (`r20261113T031700Z`); absent between runs |
| `ts` | sender clock, UTC, RFC 3339 |
| `host` | sender host name (`status.host`) |
| `type` | `run`, `repo`, `event`, `end` or `heartbeat` |
| `mac` | only with `hmac_key_file`: see Signing |

## Message types

### `run`: overall progress, every `interval_ms` during a run

```json
{"v":1,"sid":"2c2c97a7","run":"r20261113T031700Z","seq":41,"ts":"2026-11-13T03:21:40Z","host":"mirror01",
 "type":"run","state":"running","dry_run":false,"elapsed_s":280,
 "files_total":20114,"files_present":18230,"files_fetched":911,"files_failed":0,
 "bytes_total":30708000000,"bytes_done":12992000000,"speed_bps":32505856,"eta_s":545,
 "warnings":1,"errors":0,"active":8,"repos_total":5,"repos_done":2,"repos_failed":0,
 "dropped":0,"events_suppressed":0}
```

`bytes_*` count what this run has to transfer; `files_present` were already on disk.
`eta_s` is absent while it cannot be estimated.

### `repo`: one repository

Sent when a repository's numbers change (at most 8 per interval), one unchanged
repository per interval as a refresher, every repository once at the end of a run, and a
few per heartbeat while idle.

```json
{"type":"repo","name":"debian","phase":"downloading",
 "files_total":9120,"files_present":8800,"files_fetched":210,"files_failed":0,
 "bytes_total":8100000000,"bytes_done":5200000000,"warnings":0,"errors":0}
```

`phase`: `queued`, `release`, `indices`, `scanning`, `downloading`, `publishing`,
`cleaning`, `done`, `failed`, `partial`, `cancelled`, `skipped`, or `unknown` (daemon has
not run yet). After the run: `suites_ok`, `suites_failed`. While idle: `release_age_s`,
the age of the repository's oldest published Release file on the mirror.

### `event`: something happened

```json
{"type":"event","level":"error","kind":"suite_failed","repo":"gitlab-ee",
 "text":"suite trixie: 3 package file(s) could not be fetched"}
```

`level`: `info`, `warning`, `error`. `kind`: `suite_ok` (published or already up to
date), `suite_failed`, `daemon` (started, stopping, run requested, configuration reload
failed) or `log` (any other log line). At most 20 events are sent per interval, warnings
and errors first; the rest are counted in `run.events_suppressed` and remain in
`log/cheval.log`.

### `end`: result of a run

```json
{"type":"end","state":"failed","exit_code":1,"dry_run":false,"elapsed_s":1386,
 "repos_ok":4,"repos_failed":1,"repos_skipped":0,"failed":["gitlab-ee"],
 "files_fetched":911,"bytes_fetched":19541000000,"files_failed":3,
 "cleaned_files":40,"cleaned_bytes":812000000,"warnings":1,"errors":4}
```

| `state` | `exit_code` | Meaning |
|---|---|---|
| `finished` | 0 | every suite published |
| `failed` | 1 | one or more suites failed and kept their previous state |
| `cancelled` | 130 | interrupted |
| `error` | 2 | the run could not start; see `error` |

The same object is stored as `end` in `state/last-run.json`.

### `heartbeat`: the daemon is alive and idle, every `heartbeat_secs`

```json
{"type":"heartbeat","state":"idle","uptime_s":86400,
 "last_run":{"run":"r20261113T031700Z","state":"failed","exit_code":1,
             "finished_at":"2026-11-13T03:40:11Z","repos_ok":4,"repos_failed":1},
 "next_run":"2026-11-14T03:17:00+01:00","oldest_release_age_s":21600,
 "repos_total":5,"dropped":0}
```

Only `cheval daemon` sends heartbeats. No message at all for several heartbeat periods
means the sender or the link is down; that silence is the only way the far side can tell.

## Signing

With `hmac_key_file`, the sender appends `"mac":"<hex>"` as the **last** member. The value
is HMAC-SHA256, keyed with the first line of the key file, over the JSON text as it would
be without that member. To verify: cut the text at the last `,"mac":"`, append `}`,
compute the HMAC over that and compare it with the hex value.

Without a key, anything that can send a datagram to the receiver's port can feed it
false status or make it ignore the real sender. Use signing unless the receiving network
is closed.

A signed message is still ordinary JSON, so tools that do not verify can simply ignore
`mac`. Signing proves a message came from a holder of the key and was not altered. It
does not hide the content, and it does not stop a recorded message from being replayed
beyond the `sid`/`seq` rule above.

## Syslog lines

`<PRI>1 TIMESTAMP HOST cheval PID MSGID - TEXT`, with MSGID one of `run`, `event`, `end`,
`heartbeat`. Severity is info (6), warning (4) or error (3); the facility is configurable.

```
<134>1 2026-11-13T03:17:05Z mirror01 cheval 2211 run - sync running 42.3% 12.1 GiB / 28.6 GiB 31.0 MiB/s ETA 08:52 files 19141/20114 failed=0
<134>1 2026-11-13T03:21:40Z mirror01 cheval 2211 event - [debian] suite trixie published (212 metadata files updated)
<131>1 2026-11-13T03:22:02Z mirror01 cheval 2211 event - [gitlab-ee] suite trixie: 3 package file(s) could not be fetched
<131>1 2026-11-13T03:40:11Z mirror01 cheval 2211 end - sync finished WITH ERRORS in 23:06: 4 repos ok, 1 failed, 18.2 GiB fetched (911 files), 3 files failed
<134>1 2026-11-13T04:40:11Z mirror01 cheval 2211 heartbeat - idle, last run 2026-11-13T03:40:11Z FAILED (repos failed: 1), next run 2026-11-14T03:17:00+01:00
```

Progress (`run`) lines are limited to one per `syslog_progress_secs`; events, results and
heartbeats are always sent. Per-repository progress is not sent to syslog.

## HTTP API

Served by `cheval daemon` (`[status.http]`) and by `cheval status listen --http`.
Read-only: GET and HEAD. With a token configured, send `Authorization: Bearer TOKEN`
(`/healthz` is exempt).

| Endpoint | Returns |
|---|---|
| `GET /v1/status` | `status`: the latest `run`, `end` or `heartbeat`; `last_end`; and `sender` (sink counters) or `receiver` (see below) |
| `GET /v1/repos`, `/v1/repos/NAME` | latest `repo` message(s) |
| `GET /v1/events?since=ID` | up to 500 recent events, each with an `id`; pass the returned `next` as `since` to get only newer ones |
| `GET /v1/stream` | every message as it is sent or received, newline-delimited JSON, until the client disconnects |
| `GET /healthz` | `ok` |
| `GET /metrics` | Prometheus text format |

On the receiving side `/v1/status` adds:

```json
"receiver":{"stale":false,"age_s":1,"stale_after_s":180,
            "received":2210,"accepted":1105,"duplicates":1105,"lost":0,"bad_mac":0,"malformed":0}
```

`stale` turns true when nothing was accepted for `--stale-after` seconds. `lost` counts
sequence gaps, `duplicates` the repeats that were ignored, `bad_mac` messages that failed
the signature check.
