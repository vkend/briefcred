# briefcred

A local, biometric-gated credential broker for AI agents and developer tooling.
It hands subprocesses short-lived, narrowly scoped credentials, swaps
placeholder keys for real ones at a local proxy, and records every mint,
request, and revoke in an append-only audit log.

This is a greenfield build in progress. See `ROADMAP.md` for the plan,
`ARCHITECTURE.md` for the shape, and `THREAT_MODEL.md` for what each phase does
and does not guarantee.

**Status: Phase 1.** The workspace, the profile schema, the minter contracts,
and a working PostgreSQL dynamic-role minter exist as a library, and the daemon
now runs: a per-user LaunchAgent (or systemd user unit) with a private Unix
socket, an append-only audit log, and a Prometheus endpoint. No credential work
goes through it yet; that is Phase 3.

## Requirements

- Rust 1.95 or newer, stable.
- macOS 26 for the full feature set. Linux paths compile and are unit-tested.
- PostgreSQL server binaries to run the end-to-end tests. Any 14 or newer
  installation works; the tests never touch a running cluster.

## Build and test

```sh
just check    # cargo fmt --check, then clippy with warnings denied
just test     # the whole workspace, unit and end-to-end
just e2e      # only the end-to-end tests, with output shown
just fmt      # rewrite formatting in place
```

Without `just`:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

### End-to-end tests

`cargo test --workspace` starts a throwaway PostgreSQL cluster per test on a
free loopback port, under a temporary directory, and stops it afterwards. It
never connects to a cluster you are already running.

Server binaries are discovered in this order:

1. `BRIEFCRED_PG_BIN`
2. `/opt/homebrew/opt/postgresql@14/bin`
3. `PATH`

A directory only qualifies if it holds `initdb`, `pg_ctl`, **and** the
`postgres` server, which is what rejects client-only installations such as
`libpq`. If no installation is found the end-to-end tests print the reason and
skip rather than fail.

```sh
BRIEFCRED_PG_BIN=/usr/lib/postgresql/16/bin cargo test --workspace
```

## Install and run

`briefcred install` provisions the directory layout, writes a starter
`daemon.toml`, installs the service unit, and starts the daemon. It is
idempotent, and it never overwrites a `daemon.toml` you have edited.

```sh
briefcred install --dry-run   # print every file and command, change nothing
briefcred install --trust-ca  # also add the root CA to the system trust store
briefcred daemon status
briefcred ca show
curl -s 127.0.0.1:9317/metrics
briefcred uninstall
```

`--trust-ca` is the only part of an install that needs `sudo`. Without it the
CA is still generated and `ca.pem` still written; only the system trust store
is left alone, and `briefcred ca show` prints the command to run later.

On macOS the unit is a LaunchAgent at
`~/Library/LaunchAgents/dev.briefcred.daemon.plist` with `RunAtLoad`,
`KeepAlive`, and `ProcessType Interactive`, bootstrapped into `gui/<uid>`. It is
never a system-wide LaunchDaemon: a daemon outside the Aqua session cannot
show a biometric prompt, so one would hang the moment Phase 3 asks for Touch ID.
On Linux the unit is `~/.config/systemd/user/briefcred.service`.

`briefcred daemon start | stop | restart` go through `launchctl` or
`systemctl --user`. The CLI never spawns the daemon itself, so the service
manager and the process tree cannot disagree about who owns it. Each of them,
and `install`, waits for the daemon to actually reach the requested state
before returning: the service manager reports success once it has accepted the
job, which is well before the socket exists. If the daemon
is down, `briefcred daemon status` prints
`daemon is not running; run 'briefcred daemon start'` and exits **3**, which is
distinct from the generic failure code 1.

`briefcred uninstall` boots the agent out and deletes the unit file. It leaves
the audit log, profiles, configuration, and the CA in place; deleting the audit
trail on the way out is the one thing an audit trail must not do, and deleting
the CA would break the trust the machine has already granted it.

## The root CA

briefcred terminates TLS locally, so it needs a certificate authority this
machine trusts. `install` generates one: ECDSA P-256, common name
`briefcred local CA <hostname>`, ten years, and `pathlen:0` so it can sign
leaves and never an intermediate. The certificate is `ca/ca.pem`, mode `0644`
because every runtime that reads it does so as you. The private key never
touches that file: it goes to the macOS login keychain as a generic password
under service `dev.briefcred.ca`, or to `ca/ca.key` at mode `0600` elsewhere.

```sh
briefcred ca show                    # subject, fingerprint, validity, trust state
briefcred ca regenerate --trust-ca   # replace it, and trust the replacement
briefcred ca untrust                 # remove it from the trust store, keep the files
```

`regenerate` untrusts the old certificate before replacing it, because the
macOS trust store matches on content and there would be nothing left to match
afterwards. Every certificate the old CA issued stops being trusted.

Leaves are issued on demand for the hostnames a subprocess is talking to, are
valid for 24 hours, and are cached in memory per hostname list.

### Choosing where the key lives

| `daemon.toml` | Backend |
| --- | --- |
| absent | keychain on macOS, file elsewhere |
| `[ca]`<br>`keystore = "keychain"` | macOS login keychain |
| `[ca]`<br>`keystore = "file"` | `ca/ca.key`, mode `0600` |

Asking for `keychain` off macOS is an error rather than a silent fallback to a
file: a configuration that says "keychain" must not quietly write the key to
disk instead.

### Trust environment

Not every runtime reads the system trust store, so `briefcred exec` also
points the ones that do not at `ca.pem`:

`AWS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`,
`REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`.

A profile may narrow that list with `trust_env:`, and an empty list opts out
of it entirely. A name briefcred does not set is rejected when the profile is
loaded rather than ignored, so a typo cannot leave a runtime silently
uncovered.

Clients that pin a certificate rather than checking the trust store fail
loudly, and are out of scope. See [docs/ca-pinning.md](docs/ca-pinning.md) for
what those failures look like and how to tell pinning apart from a CA that is
simply not trusted yet.

## The daemon

The daemon listens on a Unix socket at mode `0600` inside a `0700` directory,
and checks the connecting process's uid. A peer that is not the owning user has
its connection closed and an `auth_reject` audit row written.

The wire protocol is one JSON message per frame behind a 4-byte big-endian
length prefix, capped at 16 MiB so a four-byte header cannot be turned into a
large allocation. It speaks `Ping`, `Status`, `Shutdown`, `ListProfiles`,
`ShowProfile`, `OpenSession`, and `CloseSession`; requests reach async handlers
through a dispatch table keyed by the request's own wire name, and the table is
asserted in a test to cover every request the protocol defines.

`SIGTERM`, `SIGINT`, and `Request::Shutdown` all stop the daemon the same way:
it stops accepting, gives in-flight connections five seconds to finish, removes
the socket file, and writes a `daemon_stop` row.

### Configuration

`daemon.toml` lives at the root of the briefcred home. Every key is optional.

| Key | Default | Meaning |
| --- | --- | --- |
| `retention_days` | `90` | Audit logs older than this are deleted |
| `metrics_port` | `9317` | Loopback port for `/metrics`; `0` asks for a free one |
| `metrics_enabled` | `true` | Whether to serve `/metrics` at all |
| `session_idle_secs` | `1800` | Seconds a session may go untouched before it is wiped |
| `master_source` | platform default | `"keychain"`, `"file"`, or `"env"` |
| `ca.keystore` | platform default | `"keychain"` or `"file"`; where the CA key lives |

An unknown key is an error rather than a silent no-op, so a typo cannot switch
a control off.

### Audit log

`audit/audit-YYYY-MM-DD.jsonl`, one JSON object per line, opened `O_APPEND` and
`fsync`ed after every row. Rotation is by filename, so no rename dance and no
lost rows. A retention sweep runs at startup and every hour, deleting files
whose filename date falls outside `retention_days`. It never touches the file
currently being written, and ignores any filename it did not write.

### Metrics

`GET /metrics` on `127.0.0.1` returns Prometheus text format.

| Series | Type | Meaning |
| --- | --- | --- |
| `briefcred_uptime_seconds` | gauge | Seconds since the daemon started |
| `briefcred_ipc_requests_total{request}` | counter | IPC requests by kind |
| `briefcred_audit_write_errors_total` | counter | Audit rows that failed to write |

Every request series is seeded at zero, so a counter that has never fired is
distinguishable from a scrape that failed.

## Profiles

A profile is the work envelope: what to mint, how the user unlocks it, what may
run, and how the minted material reaches the environment. Profiles live in
`profiles/*.yaml` under the briefcred home directory.

```yaml
name: analytics
description: read-only analytics shell
unlock:
  policy: biometric        # biometric (default) | passcode | none
credentials:
  - name: db
    kind: postgres-dynamic
    ttl_secs: 900          # default
    config:
      host: db.internal
      port: 5432           # default
      dbname: app
      user: briefcred_master
      sslmode: require     # default; disable | prefer | require
      role_template:
        grants:
          - privileges: [USAGE]
            on: SCHEMA public
          - privileges: [SELECT]
            on: ALL TABLES IN SCHEMA public
exec:
  allow_argv0: [psql]
  allow_args: ['^-c$', '^SELECT ']
trust_env:                 # optional; absent means all six
  - SSL_CERT_FILE
  - REQUESTS_CA_BUNDLE
env:
  PGUSER: ${minted.db.PGUSER}
  PGPASSWORD: ${minted.db.PGPASSWORD}
  PGHOST: ${minted.db.PGHOST}
```

Unknown keys are errors at every level, so a typo cannot silently switch a
control off. `${minted.<credential>.<field>}` must name a credential the
profile declares; `${config.<key>}` is resolved at exec time. Every regex in
`exec.allow_args` is compiled at load, and every `trust_env` name is checked
against the six briefcred sets.

The master credential is never written in a profile. `user` names the master
role; its password comes from a master source, described below.

Profiles hot-reload. The daemon watches `profiles/` and reloads 250 ms after
the last change, so an editor's save burst is one reload rather than five. A
file that does not parse leaves the previous set in force, logs, and writes a
`profile_load_error` audit row: a typo in one profile must not cost you the
others.

## Master credentials

Each credential's master is fetched by key when a session opens. The key is the
credential's `source_key`, or its `name` when `source_key` is absent, so
several credentials can share one master by naming the same key.

| `master_source` | Where it looks |
| --- | --- |
| `keychain` | The login keychain, service `dev.briefcred.master`, key as the account. The default on macOS. |
| `file` | `secrets/<key>` under the briefcred home, mode `0600`. The default elsewhere. |
| `env` | `BRIEFCRED_MASTER_<KEY>`, upper-cased with `-` as `_`. Development only. |

The file backend refuses a file readable by group or other rather than using
it, and the environment backend warns once per process that every child
inherits what it reads. A master that is simply missing is reported with the
key and the place that was searched, so the fix is obvious.

## Sessions and the unlock gate

`OpenSession` proves presence, then fetches the masters, in that order — a
refused prompt leaves no master in the daemon's memory at all. On macOS the
prompt is Touch ID falling back to the login password, shown on a dedicated
thread so the daemon keeps serving while it is up. It is skipped entirely for
a profile with `unlock.policy: none`.

A successful unlock is cached per profile for `unlock.cache_secs`, 300 seconds
by default, so a shell running briefcred in a loop prompts once rather than
once a second. The cache is per profile, so unlocking a low-value profile never
opens a high-value one, and a profile reload clears it. Within that window a
local caller running as you opens a session without a prompt. That is the
trade the cache exists to make; set `cache_secs: 0` to prompt every time.

Over SSH, or anywhere else with no graphical session to draw the prompt in,
`OpenSession` is refused with `no_aqua_session` rather than falling back to
something weaker, and the refusal happens before the cache is consulted, so a
warm cache from a desktop login does not carry an SSH shell through. If a
profile is genuinely meant to run unattended, say so with
`unlock.policy: none`; briefcred will not infer it.

That refusal is best-effort, and it is worth knowing exactly how. Two
independent checks feed it: the daemon inspects its own security session, and
the client declares its own in the request. Both are needed, because neither
sees the whole picture — the daemon is started by launchd and cannot tell an
SSH client from a local one, and the client cannot tell whether the daemon is
in a background session. The client's half is a declaration rather than a
proof: a program running as you can send `client_headless: false` and get a
prompt on the console user's screen. briefcred cannot prevent that, because
such a program is already inside every boundary briefcred has. What the check
buys is that an honest client on SSH gets an accurate refusal instead of a
prompt nobody is standing in front of.

A session is wiped when it is closed, when it has gone `session_idle_secs`
without being used, and at shutdown. Every one of those writes a
`session_close` audit row naming which of the three it was.

## Filesystem layout

macOS:

```
~/Library/Application Support/briefcred/
  sock  profiles/  audit/  ca/  secrets/  logs/  state/  daemon.toml
```

Every directory is mode `0700` and the socket is `0600`. The service unit lives
outside this tree, under `~/Library/LaunchAgents` or
`~/.config/systemd/user`, because launchd and systemd have to read it.

Linux uses `$XDG_DATA_HOME/briefcred` (default `~/.local/share/briefcred`) with
the socket at `$XDG_RUNTIME_DIR/briefcred/sock`.

`BRIEFCRED_HOME` relocates the entire layout, socket included. Tests always set
it, so they never touch real user directories.

## The PostgreSQL minter

`briefcred_core::minters::PostgresDynamicMinter` mints a `LOGIN` role named
`briefcred_t_<12 hex>` with a 32-byte random password and a `VALID UNTIL`
matching the requested TTL, then applies the profile's grants — all in one
transaction, so a failed grant leaves no role behind. It returns `PGUSER`,
`PGPASSWORD`, `PGHOST`, `PGPORT`, `PGDATABASE`, and `DATABASE_URL`.

Revoke replays the same grant template as a `REVOKE` loop first, then attempts
`DROP OWNED BY`, then `DROP ROLE`. That order matters and is asserted in the
tests: `DROP OWNED BY` on its own is not a revoke when the master does not own
schema `public`, which is the managed-PostgreSQL default. A revoke that cannot
complete reports `RevokeOutcome::Failed` with the backend's SQLSTATE and
message; a role that was already gone reports `AlreadyGone`.

## Licence

MIT OR Apache-2.0.
