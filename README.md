# briefcred

A local, biometric-gated credential broker for AI agents and developer tooling.
It hands subprocesses short-lived, narrowly scoped credentials, swaps
placeholder keys for real ones at a local proxy, and records every mint,
request, and revoke in an append-only audit log.

![An agent calls the API with a placeholder token; the API server receives the real key.](docs/media/key-swap.gif)

*The agent's key is a placeholder; briefcred's local proxy swaps in the real one (green, below) on the way out.*
[Watch the 4-minute demo](https://youtu.be/7N9MCX-hCrQ): creating a profile, Touch ID, a leaked token, and a Postgres role that lasts one command.

## Why

An agent that can run commands can read its own environment, and an API key
in an environment variable is a key the agent can send anywhere. briefcred
keeps the real credential in a daemon on your machine and gives the agent
something that is only useful on your terms:

- **A placeholder, not the key.** The agent's `OPENAI_API_KEY` is a token that
  only briefcred's local proxy accepts. The proxy swaps in the real key on the
  way out, and only for requests the profile's Cedar policy allows.
- **Credentials that end.** Postgres roles, AWS STS sessions and SSH
  certificates are minted for one session and revoked when it closes. Where a
  backend cannot withdraw a credential at once, its lifetime is short and
  [`THREAT_MODEL.md`](THREAT_MODEL.md) says how short.
- **A fingerprint, and a record.** A profile can require Touch ID before
  anything is minted, and every mint, request, denial and revoke is a row in an
  append-only audit log.

## Quick start

macOS, from source (there is no packaged release yet):

```sh
for crate in cli daemon hook helper-postgres helper-sts; do
    cargo install --locked --path crates/briefcred-$crate
done
briefcred install --trust-ca          # start the daemon, trust its local CA
briefcred profile bootstrap           # e.g. an "openai" profile for an API key; the key goes in the keychain
briefcred exec --profile=openai -- python agent.py
```

[Install and run](#install-and-run) has the details, and
[`examples/profiles/`](examples/profiles/) has ready-made profiles for OpenAI,
Anthropic, GitHub, Stripe, a Postgres warehouse and an SSH bastion.

See `ROADMAP.md` for the plan, `ARCHITECTURE.md` for the shape, and
`THREAT_MODEL.md` for what is and is not guaranteed.

**Status: alpha, unreleased.** Every roadmap phase is implemented and tested,
but there is no tagged release yet, the configuration format and the CLI may
still change before 1.0, and it has not had an outside security review. In one
sentence each, what is implemented:

- **Minting.** `postgres-dynamic` roles, `aws-sts` sessions and `ssh-cert`
  certificates, each minted for one session and revoked when it closes, behind
  a Touch ID gate with a per-profile unlock cache.
- **The HTTP proxy.** A local TLS-terminating proxy that swaps a synthetic
  token for the real API key, over HTTP/1.1, HTTP/2, server-sent events,
  WebSocket and gRPC, with the profile's Cedar policy deciding every request
  and a per-session quota bounding how many there may be.
- **The PostgreSQL proxy.** The same handoff for databases: the subprocess
  holds a token, the daemon completes the real authentication, and a connection
  does not outlive the grant it was opened under.
- **Operations.** An append-only JSONL audit log, a Prometheus endpoint, a
  persistent revoke queue with a reconciler behind it, signed profile
  distribution over three registry schemes, MCP tools for an agent, an agent
  hook, and `briefcred daemon upgrade`, which replaces a running daemon without
  closing a socket or dropping a stream.

Three reference pages sit alongside this one:
[`docs/profile-schema.md`](docs/profile-schema.md), generated from the types
the loader uses; [`docs/compatibility.md`](docs/compatibility.md), which says
what each runtime needs; and
[`docs/cb4a-conformance.md`](docs/cb4a-conformance.md), which says how much of
a credential each kind lets a subprocess see.

## Requirements

- Rust 1.95 or newer, stable.
- macOS 26 for the full feature set. Linux paths compile and are unit-tested.
- PostgreSQL server binaries to run the end-to-end tests. Any 14 or newer
  installation works; the tests never touch a running cluster.

## Build and test

```sh
just check    # fmt, clippy with warnings denied, cargo deny, cargo vet
just test     # the whole workspace, unit and end-to-end
just e2e      # only the end-to-end tests, with output shown
just fmt      # rewrite formatting in place
```

`just check` runs two supply-chain gates as well as the lints, so install them
once:

```sh
cargo install cargo-deny cargo-vet --locked
```

`cargo deny` enforces `deny.toml`: permissive licences only, nothing from a
registry other than crates.io, and no open advisory. `cargo vet check --locked
--frozen` is offline: `--frozen` forbids the network and requires `--locked`
alongside it, which is why both are passed. `supply-chain/` imports no
third-party audit sets, so the check asserts that the exemption list still
covers the lockfile — which turns a new dependency into a diff somebody has to
look at.

Without `just`:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo deny check
cargo vet check --locked --frozen
cargo build --workspace
cargo test --workspace
```

`cargo build --workspace` before `cargo test` is not optional on a clean
checkout: `cargo test` does not build a package's binaries unless a test target
asks for them, so the daemon and the `briefcred-helper-*` binaries the
end-to-end tests spawn would simply be absent. The harness refuses to start
when one is missing and says which.

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

There is no packaged release yet, so install from source. All five binaries
must land in the same directory, because `briefcred` finds the daemon beside
itself and the daemon finds its helpers beside itself:

```sh
for crate in cli daemon hook helper-postgres helper-sts; do
    cargo install --locked --path crates/briefcred-$crate
done
```

A Homebrew formula is ready (see [Releases and packaging](#releases-and-packaging))
and will be published with the first release.

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

Run `briefcred install --trust-ca` yourself, without `sudo`; the CLI asks for
your password itself for that one step, and running the whole thing as root
provisions root's home instead of yours.

On macOS the unit is a LaunchAgent at
`~/Library/LaunchAgents/io.github.vkend.briefcred.plist` with `RunAtLoad`,
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
under service `io.github.vkend.briefcred.ca`, or to `ca/ca.key` at mode `0600` elsewhere.

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

### Upgrading without downtime

`briefcred daemon upgrade` replaces the running daemon with a new binary
without closing a socket. It starts the new daemon with `--takeover <socket>`,
and the old one passes it the four listening descriptors over `SCM_RIGHTS`
together with a signed blob of every open session — masters encrypted to the
new daemon's ephemeral X25519 key, so no plaintext master ever touches the disk
or an unencrypted channel. The old daemon stands down only once the new one has
confirmed it is serving, and then drains what it was already handling.

```console
$ briefcred daemon upgrade
upgrading pid 4102 to /opt/briefcred/bin/briefcred-daemon
daemon upgraded: pid 4102 handed 3 session(s) to pid 4188
the sockets never closed; pid 4102 is draining what it had in flight
```

A session handle a client already holds keeps working against the new process,
the ports do not move, and an event stream or WebSocket that was open before
the upgrade runs to its end. New sessions and new mints are refused for the
length of the handoff — the retry lands on the new daemon — because anything
opened in that window would be adopted by nobody. Every failure before the
confirmation leaves the running daemon exactly as it was. On Linux, `briefcred install` also writes a
`briefcred.socket` unit so systemd can hold the listeners across an ordinary
restart. `docs/upgrade.md` has the whole sequence, what it does and does not
guarantee, and how the service manager fits around it.

### Configuration

`daemon.toml` lives at the root of the briefcred home. Every key is optional.

| Key | Default | Meaning |
| --- | --- | --- |
| `retention_days` | `90` | Audit logs older than this are deleted |
| `metrics_port` | `9317` | Loopback port for `/metrics`; `0` asks for a free one |
| `metrics_enabled` | `true` | Whether to serve `/metrics` at all |
| `proxy_port` | `9318` | Loopback port for the HTTP proxy; `0` asks for a free one |
| `proxy_enabled` | `true` | Whether to run the HTTP proxy at all |
| `pg_proxy_port` | `9319` | Loopback port for the Postgres proxy; `0` asks for a free one |
| `pg_proxy_enabled` | `true` | Whether to run the Postgres proxy at all |
| `pgproxy.tls` | `false` | Answer a client's `SSLRequest` with a leaf from briefcred's CA |
| `pgproxy.allow_md5` | `false` | Permit MD5 when an upstream database asks for it |
| `upstream_roots` | none | **For tests.** A PEM bundle of extra CAs the proxy trusts upstream |
| `session_idle_secs` | `1800` | Seconds a session may go untouched before it is wiped |
| `mcp_query_timeout_secs` | `30` | `statement_timeout` for a `briefcred_db_query` |
| `mcp_exec_timeout_secs` | `300` | Seconds a `briefcred_exec` command may run before it is killed |
| `handoff_drain_secs` | `30` | Seconds a replaced daemon gives its in-flight requests and streams |
| `master_source` | platform default | `"keychain"`, `"file"`, or `"env"` |
| `ca.keystore` | platform default | `"keychain"` or `"file"`; where the CA key lives |
| `profiles.trust_roots` | `[]` | Minisign public key lines whose signatures vouch for a registry profile |
| `profiles.registries` | `[]` | `{ name, url }` entries `briefcred profile sync` fetches |
| `profiles.dev_mode` | `false` | Load registry profiles that fail verification, loudly |

An unknown key is an error rather than a silent no-op, so a typo cannot switch
a control off. A `profiles.trust_roots` entry that is not a well-formed
minisign public key stops the daemon starting, rather than leaving it running
with a trust root it silently ignores. `pg_proxy_enabled` needs `proxy_enabled`: both proxies verify
synthetic tokens with the same signing key, and a daemon configured with one
and not the other refuses to start rather than failing every `postgres-proxy`
mint at the point of use.

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
| `briefcred_mint_duration_seconds{kind}` | histogram | Time to mint one credential, by minter kind |
| `briefcred_revoke_duration_seconds{kind}` | histogram | Time for one revoke attempt, by minter kind |
| `briefcred_revoke_failures_total{kind}` | counter | Revoke attempts that failed, by minter kind |
| `briefcred_proxy_requests_total{decision,status_class}` | counter | Proxied requests, by decision and status class |
| `briefcred_proxy_latency_seconds{kind}` | histogram | Time for one proxied request, by policy decision |
| `briefcred_proxy_streams_total{kind}` | counter | Long-lived streams that have ended, `sse` or `ws` |
| `briefcred_proxy_stream_duration_seconds{kind}` | histogram | How long a stream stayed open, by kind |
| `briefcred_pgproxy_connections_total{outcome}` | counter | Postgres connections, by outcome |
| `briefcred_pgproxy_bytes_total{direction}` | counter | Bytes relayed by the Postgres proxy, by direction |
| `briefcred_quota_saturation{profile}` | gauge | How full a profile's session quota is, 0 to 1, where 1 is empty |
| `briefcred_quota_rejections_total{profile,surface}` | counter | Charges a quota refused, by profile and by `http`/`postgres`/`exec`/`mcp` |

`briefcred_proxy_stream_duration_seconds` has bucket bounds of its own, running
from a second to two hours: a stream is not a latency, and measured on the
request scale every one of them would land in `+Inf`. It is counted when a
stream *closes*, because that is the only moment its duration exists.

The mint and revoke histograms time failures as well as successes: a backend
that takes thirty seconds to refuse is exactly what they exist to show. A rising
`briefcred_revoke_failures_total` is the series to alert on — a revoke that
keeps failing is a credential that is still live.

Every request series is seeded at zero, so a counter that has never fired is
distinguishable from a scrape that failed. `briefcred_quota_saturation` is the
exception and is deliberately unseeded: a series that exists is a profile
somebody put a `quota:` on, and one that does not is a profile running
unmetered. A refused charge pins it at exactly 1, so `== 1` is an alert
expression that works.

## Running a command

```sh
briefcred exec --profile=db-ro -- psql -c "SELECT 1"
```

That one line does the following, in this order:

1. **Opens a session.** The unlock gate runs first, so a refused prompt leaves
   no master credential in the daemon's memory at all.
2. **Checks the command.** `exec.allow_argv0` and `exec.allow_args` are enforced
   *before* anything is minted, so a command the profile forbids never causes a
   role to be created. A violation exits **4** and names the offending value.
3. **Mints.** One helper process per minter kind, spoken to over stdio, so the
   code that holds a database password is not in the daemon's address space.
4. **Runs the child** with `env_clear()`, then the passthrough list, then the
   profile's composed environment.
5. **Revokes.** `briefcred exec` returns with the child's exit code the moment
   the child exits; the revoke is queued and happens behind it.

The exit code is the child's, so a script that wraps `briefcred exec` behaves as
if briefcred were not there. Two codes are briefcred's own: **4** for a command
the profile refuses, **5** for a refused unlock.

| flag | meaning |
| --- | --- |
| `--profile <name>` | Which profile to run under. Required. |
| `--cred a,b` | Mint only these credentials. Defaults to all of them. |
| `-- <cmd> [args]` | The command. Everything after `--` belongs to the child. |

### The subprocess environment

The child starts from **nothing**. `env_clear()` runs first, so a credential
that happens to be in your shell does not travel into a process briefcred is
meant to be constraining. It then gets, in order:

1. the trust environment (`SSL_CERT_FILE` and the rest) pointing at the local
   CA, and — where the profile has HTTP credentials or asks for it — the proxy
   environment (`HTTPS_PROXY` and the rest) pointing at the local proxy;
2. the passthrough list — `PATH`, `HOME`, `TERM`, `LANG`, `TMPDIR`, plus
   anything the profile's `env_passthrough` names — copied from your own
   environment, and only when you actually have it;
3. the profile's `env` block, with `${minted...}` substituted.

Later steps win, so a profile can override a passed-through variable.

The **daemon** composes that environment and the **client** applies it. The
daemon is the only side holding the profile, the minted fields, and the CA path
at once, so the template grammar has one implementation rather than two that can
drift. The client's half is mechanical: clear, copy the named variables, apply
what it was given, spawn. The one thing the daemon cannot see is the client's
own environment, which is why the passthrough list crosses the socket as names
rather than values.

## Reading one field

```sh
briefcred get --profile=db-ro --cred=db --field=PGPASSWORD | pbcopy
```

`get` mints, prints one field, and queues the revoke. It **refuses to write to a
terminal** unless you pass `--force`: a short-lived credential that has landed in
a scrollback buffer is a long-lived one. There is no trailing newline, so a file
redirect gets exactly the value.

**A value from `get` stays valid for the credential's `ttl_secs`, not for the
length of the command.** `briefcred exec` revokes as soon as its child exits,
because the child is finished with the credential. `get` cannot: it hands the
value to you, and revoking on return would print something that was dead on
arrival. So the revoke is queued and scheduled for the credential's own expiry.
Two things follow. Set `ttl_secs` on a profile you use with `get` to the
shortest window the work needs, because that is how long the value lives. And a
`get` value is not revoked early by anything short of the expiry itself —
stopping the daemon does not bring it forward, because the queue is persisted
and the entry simply resumes its schedule on the next start. If you need a
credential gone as soon as the work is done, use `exec`.

`get` is exempt from `exec.allow_argv0`, because it spawns nothing. That is not
a hole in the allowlist — the allowlist constrains what briefcred is willing to
run with a credential attached, and `get` hands the credential to you, who could
always run whatever you liked with it. `THREAT_MODEL.md` says this at length.

## Everything else the CLI does

| command | what it does |
| --- | --- |
| `briefcred profiles` | The loaded profiles, their unlock policy, and their credentials. |
| `briefcred health` | Daemon, profiles, CA trust, and outstanding revokes, with the command that fixes each. |
| `briefcred audit [--since 24h] [--json]` | Audit rows, read straight off the disk so it works with the daemon stopped. |
| `briefcred profile bootstrap` | An interactive interview that writes a profile and stores its master. |
| `briefcred profile show <name>` | One profile, as the daemon parsed it, and where it came from. |
| `briefcred profile keygen --out <dir>` | A minisign signing key pair for publishing profiles. |
| `briefcred profile sign <file> --key <path>` | Sign a profile, writing `<file>.minisig` beside it. |
| `briefcred profile verify <file> --pub <path>` | Check a profile against its `.minisig`. Accepts signatures from stock `minisign` too. |
| `briefcred profile sync` | Fetch every registry in `daemon.toml`, verifying as it goes. |
| `briefcred profile schema` | The profile schema as a JSON Schema document, generated from the types the loader uses. |
| `briefcred mcp` | Serve the Model Context Protocol tools on stdin and stdout, for an agent. |
| `briefcred daemon upgrade [--binary <path>]` | Replace the running daemon in place, keeping every socket and session. |

`briefcred profile bootstrap` asks for the master credential **last**, after the
unlock gate has said yes, and writes it straight to the platform key store. The
master never crosses the daemon's socket: routing the write through the daemon
would put a copy of the most valuable secret on the machine into the most
valuable process on the machine, for a task the daemon has no part in.

## Revoking, and the three nets under it

A minted credential is caught by whichever of these gets to it first.

1. **The queue.** `briefcred exec` reports the child's exit and the daemon
   enqueues the revoke. The queue is persisted to
   `state/revoke-queue.jsonl` (mode `0600`, metadata only — no master and no
   minted secret) *before* it is acknowledged, so a daemon restart resumes it.
   Failures retry with exponential backoff: 1 s, 2 s, 4 s, up to a one-minute
   ceiling, eight attempts, then it gives up with a final `failed` audit row.
2. **The session.** A wrapper that was killed never reports back. Closing the
   session — by request, by idle eviction, or at shutdown — queues whatever it
   had minted and nobody accounted for.
3. **The reconciler.** A `SIGKILL` runs none of the above. Every
   `reconcile_interval_secs` (300 by default) and once at startup, each helper
   sweeps its backend for principals that are briefcred's *and* past their
   expiry, and removes them. The expiry check is what keeps the sweep from
   racing a live `briefcred exec` elsewhere.

Every attempt from any of the three writes a `revoke` audit row with its
outcome, so a credential cleaned up by reconciliation is as findable as one its
owner revoked.

## The agent hook

`briefcred-hook` reads an agent's `PreToolUse` payload on stdin and answers on
stdout. A rule file routes; the daemon enforces. It can turn an `allow` into a
`deny`, never the other way round, and it answers `ask` rather than blocking
when the daemon is not running. See `docs/hook.md` for the rules, the
`updatedInput` caveats, and how to wire it into Claude Code.

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
  allow_argv0: [psql]      # matched on the basename, or on a full path
  allow_args: ['^-c$', '^SELECT ']
env_passthrough:           # on top of PATH, HOME, TERM, LANG, TMPDIR
  - PGSSLMODE
trust_env:                 # optional; absent means all six
  - SSL_CERT_FILE
  - REQUESTS_CA_BUNDLE
env:
  PGUSER: ${minted.db.PGUSER}
  PGPASSWORD: ${minted.db.PGPASSWORD}
  PGHOST: ${minted.db.PGHOST}
```

`allow_argv0` matches the **basename** of an absolute path as well as the path
itself, so a profile that permits `psql` permits `/opt/homebrew/bin/psql`
without knowing where it is installed. It never matches the other way round: an
entry that is a path permits only that path, which is how you pin a binary. An
empty list means "any", for both allowlists, and is worth narrowing before an
agent uses the profile.

`allow_args` is a list of regular expressions, and each argument has to match at
least one of them. **The match is unanchored**: a pattern matches if it occurs
anywhere in the argument, so `DROP` also permits `--x=DROP` and `SELECT` also
permits `NOT SELECT`. Anchor the patterns yourself wherever the whole argument
is what you mean:

```yaml
exec:
  allow_args: ['^-c$', '^SELECT ']   # `-c` exactly, then a statement
```

An unanchored pattern is not a bug in a profile that meant one — `'^SELECT '`
above is anchored at the front only, on purpose, because the rest of the
statement follows. It is a bug in a profile that wrote `DROP` expecting an
argument that *is* `DROP`.

Three more keys govern the HTTP proxy, described under **The HTTP proxy**:

```yaml
policy: |                  # Cedar source; absent means deny everything
  permit(principal, action == Action::"GET", resource)
  when { resource.host == "api.openai.com" };
policy_mode: enforce       # enforce (default) | observe
proxy: auto                # auto (default) | always
```

`policy` is compiled and validated against briefcred's fixed Cedar schema when
the profile is loaded, so a typo is an error next to the file rather than a
request that is quietly denied later. `docs/policy.md` is the guide, and
`docs/policy-cookbook.md` has five worked policies that each ship as a profile
under `examples/profiles/`.

One more key bounds *how much* a session may do, which no policy can express:

```yaml
quota:
  rate: 2                  # tokens per second, sustained; may be fractional
  burst: 20                # tokens the bucket holds, and how many at once
  total: 400               # optional hard cap for the whole session
```

One token is spent per HTTP proxy request, per Postgres proxy connection, per
`briefcred exec` or `briefcred get` that mints, and per `briefcred_db_query` or
`briefcred_exec` MCP tool call. The bucket is created when
the session opens and dies with it, so two concurrent runs of the same profile
get a budget each rather than competing for one; nothing is persisted across a
daemon restart.

When the bucket is empty the HTTP proxy answers `429` with
`{"error":"briefcred quota exceeded"}` and a `Retry-After` header, the Postgres
proxy refuses the connection with SQLSTATE `53300` (`too_many_connections`)
before it opens an upstream one, and `briefcred exec` and the MCP tools fail
with an error naming the profile and how long to wait. A spent `total` gets no
`Retry-After`, because no wait would help: close the session and open a new one.

Two things about the charge are worth knowing. It happens **before** the policy
is evaluated, so a request the policy denies still costs a token — the expensive
thing to defend against is a loop, and a loop that is being denied is still a
loop. And a policy refusal and a quota refusal are deliberately
distinguishable: `403` against `429`, `decision: "deny"` against
`decision: "quota"` in the audit log. Widening the policy will not fix a quota
rejection, and raising the quota will not fix a denial. `policy_mode: observe`
does not soften a quota refusal either: observe mode is for trialling a rule,
and a quota is a resource bound rather than a rule.

Unknown keys are errors at every level, so a typo cannot silently switch a
control off. `${minted.<credential>.<field>}` must name a credential the
profile declares; `${config.<key>}` is resolved at exec time. Every regex in
`exec.allow_args` is compiled at load, and every `trust_env` name is checked
against the six briefcred sets.

The master credential is never written in a profile. `user` names the master
role; its password comes from a master source, described below.

Profiles hot-reload. The daemon watches `profiles/` and everything under it,
and reloads 250 ms after the last change, so an editor's save burst is one
reload rather than five. A file that does not parse leaves the previous set in
force, logs, and writes a `profile_load_error` audit row: a typo in one profile
must not cost you the others.

### Where a profile came from

Profiles you write live in `profiles/*.yaml`. Profiles fetched from a registry
live in `profiles/registry/<name>/*.yaml`, and **a registry profile is dropped
unless a minisign signature beside it verifies against a trust root you named
in `daemon.toml`**. A profile you did not write names the hosts a subprocess
may reach and the credentials briefcred will mint, so an unsigned one is an
instruction from whoever last had write access to a web server.

```console
$ briefcred profile sync
briefcred profile sync
  platform         4 profile(s) into .../profiles/registry/platform
    ! draft.yaml: no .minisig alongside it

$ briefcred profiles
PROFILE             UNLOCK      CACHE   SOURCE              SIGNATURE CREDENTIALS
analytics           biometric   300s    registry(platform)  verified  db (postgres-dynamic, 900s)
```

A local profile of the same name overrides a registry one, and
`briefcred profile show` says so — which is what makes a registry usable: take
the set somebody publishes, and change the one profile you need to.

Last-good protects a typo, not a bad signature. A profile whose signature stops
verifying is dropped on the next reload rather than kept from the previous one.
`[profiles] dev_mode = true` suspends verification for writing a registry, and
is loud about it: a warning on every daemon start, a warning above the
`briefcred profiles` table, and a `profile_trust_warning` audit row per file.

The full story, including the three registry URL schemes and the signature
format, is in [`docs/profile-distribution.md`](docs/profile-distribution.md).

## Master credentials

Each credential's master is fetched by key when a session opens. The key is the
credential's `source_key`, or its `name` when `source_key` is absent, so
several credentials can share one master by naming the same key.

| `master_source` | Where it looks |
| --- | --- |
| `keychain` | The login keychain, service `io.github.vkend.briefcred.master`, key as the account. The default on macOS. |
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
without being used, at shutdown, when it is handed to a successor daemon, when
the MCP connection holding it goes away, and when a profile's quota refuses the
first call it was opened for. Every one of those writes a `session_close` audit
row naming which it was:

| `reason` | What happened |
| --- | --- |
| `request` | a client sent `CloseSession` |
| `idle` | nothing touched it for `session_idle_secs` |
| `shutdown` | the daemon stopped |
| `handoff` | it moved to a successor daemon, with its mints |
| `mcp_disconnect` | the MCP connection holding it went away |
| `quota` | the quota refused the first call, so the session just opened was closed again |

## Filesystem layout

macOS:

```
~/Library/Application Support/briefcred/
  sock  profiles/  audit/  ca/  secrets/  logs/  state/  daemon.toml
```

Profiles you write live directly in `profiles/`. Profiles fetched from a
registry live in `profiles/registry/<registry name>/`, each beside its
`.minisig`, and are replaced wholesale by the next `briefcred profile sync`.

Every directory is mode `0700` and the socket is `0600`. The service unit lives
outside this tree, under `~/Library/LaunchAgents` or
`~/.config/systemd/user`, because launchd and systemd have to read it.

Linux uses `$XDG_DATA_HOME/briefcred` (default `~/.local/share/briefcred`) with
the socket at `$XDG_RUNTIME_DIR/briefcred/sock`.

`BRIEFCRED_HOME` relocates the entire layout, socket included. Tests always set
it, so they never touch real user directories.

## Minters and where they run

| `kind` | What it mints | Master (`source_key`) | Runs in |
| --- | --- | --- | --- |
| `postgres-dynamic` | A `LOGIN` role with a random password and a `VALID UNTIL` | The master role's password | `briefcred-helper-postgres-dynamic` |
| `aws-sts` | An `sts:AssumeRole` session | `AKIA...:secret`, or the ambient chain | `briefcred-helper-aws-sts` |
| `ssh-cert` | An OpenSSH user certificate and the key it belongs to | The CA private key, OpenSSH PEM | The daemon itself |
| `http-bearer` | A synthetic token; the real key stays in the daemon | The API key | The daemon's HTTP proxy |
| `http-header` | The same, sent under a header the profile names | The header's value | The daemon's HTTP proxy |
| `http-basic` | The same, sent as HTTP basic auth | `user:password` | The daemon's HTTP proxy |
| `postgres-proxy` | A synthetic token; the master stays in the daemon | The upstream role's password | The daemon's Postgres proxy |

The third column is not decoration. A minter that opens a network connection
with a master credential gets a process of its own, so a bug in its parser
costs one backend rather than every master the daemon holds. `ssh-cert` talks
to nothing — it signs a certificate and writes two files — so a helper would
buy only the cost of a process. `THREAT_MODEL.md` records what that costs.

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

## The PostgreSQL connection proxy

`postgres-dynamic` needs `CREATEROLE` on the master. Plenty of real databases
do not offer it — a managed cluster on a locked-down plan, a database owned by
another team — and there the master password is the only thing that will ever
authenticate. `postgres-proxy` is for those: instead of minting a credential, the
daemon **becomes** the database as far as the subprocess is concerned.

```yaml
credentials:
  - name: warehouse
    kind: postgres-proxy
    ttl_secs: 3600
    config:
      host: db.internal
      port: 5432
      dbname: analytics
      user: reporting
      sslmode: require
env:
  DATABASE_URL: ${minted.warehouse.DATABASE_URL}
```

The master filed under the credential's `source_key` is the **password of the
`user` named in `config`**, and nothing else — not `user:password`, because the
role is already in the config and having it in two places is a way for them to
disagree.

The mint publishes six fields, all of them pointing at loopback and none of them
carrying the master:

| Field | Value |
| --- | --- |
| `DATABASE_URL` | `postgresql://<session>:<token>@127.0.0.1:9319/<dbname>` |
| `PGHOST` | `127.0.0.1` |
| `PGPORT` | the `pg_proxy_port` |
| `PGDATABASE` | the configured `dbname` |
| `PGUSER` | the session id |
| `PGPASSWORD` | the synthetic token |

### The upstream connection is encrypted

`sslmode` governs the connection the **daemon** opens to the real server, which
is the one that carries the master password. It is not the subprocess's
connection to the proxy: that one is loopback and carries only the synthetic
token.

| `sslmode` | What the daemon does |
| --- | --- |
| `require` (default) | Sends `SSLRequest`, refuses the connection if the server answers `N`, and does not verify the certificate |
| `verify-full` | The same, and additionally verifies the chain against the system trust store and that the certificate names `host` |
| `disable` | No `SSLRequest`; the master crosses the network in plaintext |

There is deliberately no `prefer` or `allow`. A mode that silently falls back to
plaintext is a mode whose security depends on something nobody looks at, and the
thing it would be putting on the wire is the master password.

Use `verify-full` wherever the server's certificate chains to a CA the machine
trusts. Use `disable` only when the path to the database is already private — a
loopback address, a tunnel, a unix-domain forward — and never as a way to get
past a handshake error.

So this works, and `psql` never sees a password:

```sh
briefcred exec --profile=warehouse -- psql -c 'SELECT current_user'
 current_user
--------------
 reporting
```

### What the daemon does with the connection

It asks the client for a cleartext password, which is the synthetic token; it
checks the signature, the expiry, and the revocation; it checks that the startup
packet's `user` is the session the token names and that its `database` is the
one the credential configures. Only then does it open its own connection to the
real server, authenticate with the master over **SCRAM-SHA-256**, and relay the
server's own greeting back. After that it copies bytes in both directions
without parsing them.

The cleartext password is deliberate and is safe for one reason: the listener is
bound to `127.0.0.1` and nothing else, so it is the same channel the token
already arrived over in the subprocess's environment. Set `pgproxy.tls = true`
for a client that will not connect without TLS; it gets a leaf from briefcred's
own CA, which `briefcred install --trust-ca` has already installed.

MD5 is refused upstream unless `pgproxy.allow_md5 = true`, which logs a
deprecation warning once. `SCRAM-SHA-256-PLUS` is never downgraded to its
unbound variant. A master password outside printable ASCII is refused rather
than hashed without SASLprep and reported as a wrong password.

### What it records, and what it cannot

One `PgConnection` audit row per connection, written when the connection closes:
the mint id, the upstream role, when it started and ended, and the bytes each
way. There is no query in it, and there is no field a query could go in — after
authentication the proxy does not parse the protocol at all.

A connection the proxy refuses before opening one upstream gets a
`pg_connection_refused` row instead: the database the client asked for and a
reason (`revoked`, `expired`, `bad_signature`, `wrong_session`,
`wrong_database` and so on). The client is only ever told `28000`; the row is
where the reason goes. It never holds the token.

### A connection does not outlive its grant

The credential is checked when the connection opens, and a database connection
then lives for as long as the client keeps it — so the proxy keeps checking.
Every live connection is re-examined once a second, and closed when the token
expires, when the grant is revoked, or when the session ends. A `postgres-proxy`
connection outlives its grant by at most one second.

The client is told why: an `ErrorResponse` under SQLSTATE `57P01`
(`admin_shutdown`), which is what PostgreSQL sends when an administrator
terminates a backend. If the connection is mid-message when the moment comes,
the sockets are closed without it rather than corrupting the client's parse.

So `briefcred exec` finishing really does end the access, `briefcred session
close` really does end it, and `ttl_secs` is a lifetime rather than a lifetime
for new connections only.

### The limit, stated plainly

A `postgres-proxy` credential is **not** bounded by the profile's Cedar policy.
The policy vocabulary is HTTP's, and a connection has no method, host, or path;
the only thing that could be checked per statement is the statement, which this
proxy deliberately never sees. What bounds it is the upstream role's own
privileges, the credential's `ttl_secs`, and the session it is tied to. Where
`postgres-dynamic` is possible it is still the better answer, because a minted
role can be granted less than the master has.

What *does* apply is the profile's `quota`: one token per connection, charged
before the upstream connect, so a client opening connections faster than the
profile budgeted for is refused with SQLSTATE `53300` and the database never
sees a login the client did not get.

## The AWS STS minter

Assumes a role and returns the session as `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, and `AWS_REGION`. The
`RoleSessionName` is the mint id, so every CloudTrail event the session
produces carries `briefcred_t_...` and resolves to a briefcred audit row rather
than to a shared human.

```yaml
credentials:
  - name: aws
    kind: aws-sts
    ttl_secs: 900
    source_key: aws-briefcred
    config:
      role_arn: arn:aws:iam::123456789012:role/briefcred-dev
      region: eu-west-1
      duration_secs: 900
      # Optional: an inline policy that can only take permissions away.
      session_policy: |
        {"Version":"2012-10-17","Statement":[
          {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*"}]}
```

`source: static` (the default) reads the master as `AKIA...:secret`, split on
the first colon, and builds the client from that and nothing else — no shared
config file, no environment, no instance metadata. `source: ambient` asks for
the SDK's default provider chain instead, which is weaker on purpose: whatever
the chain finds is not in the key store and is not bounded by the session.

A session policy over **2,048 plaintext characters** is refused when the
profile is loaded rather than by AWS after the request has been signed, because
AWS's own complaint names a percentage of a compressed budget rather than the
limit you exceeded.

> **Revoke is blunt, and it is blunt in a way you have to design around.**
> STS sessions cannot be withdrawn. briefcred does what the console's "Revoke
> sessions" button does: it attaches one rolling inline policy to the *role*,
> named `briefcred-revoke-older-sessions`, denying everything to any session
> issued before that moment. Revoking one briefcred mint therefore denies
> **every** session of that role issued before now, including other people's.
> Give briefcred a role nothing else uses. The outcome is reported as
> `eventually_consistent` with a five-second estimate, because IAM is.

Both `sts:AssumeRole` on the role and `iam:PutRolePolicy` on it are needed by
the master credential; without the second, revoke reports `failed` and the
session simply expires on its own.

## The SSH certificate minter

Generates a fresh ed25519 key pair, signs a user certificate for it with the
profile's CA, and writes both into a `0700` directory under `$TMPDIR` with the
key at `0600`. It returns `SSH_IDENTITY_FILE`, `SSH_CERT_FILE`, and a
ready-made `GIT_SSH_COMMAND`.

```yaml
credentials:
  - name: bastion
    kind: ssh-cert
    ttl_secs: 600
    source_key: ssh-ca
    config:
      principals: [deploy]
      extensions: [permit-pty, permit-port-forwarding]
      critical_options:
        source-address: "203.0.113.0/24"
```

The master is the CA private key in OpenSSH format **with no passphrase** —
briefcred has no passphrase to give it, and the key is protected by the
platform key store instead. Extensions default to `permit-pty` alone; a
certificate needs `permit-port-forwarding` to open a tunnel, and asking for it
explicitly is the point. `examples/profiles/kubectl-bastion.yaml` is a worked
example of `kubectl` reaching a private cluster through a bastion this way.

Revoke deletes the key directory and appends the certificate's serial to
`<home>/state/ssh-krl`, an OpenSSH key revocation list. Deleting the key is
immediate and is the half briefcred owns; the KRL only matters on servers you
have pointed at it with `RevokedKeys`. **`docs/ssh-krl.md` is required reading
before relying on this** — it explains what a revoke does and does not achieve,
and why a short `ttl_secs` is doing most of the work.

A daemon killed mid-`exec` leaves a key directory behind, so the reconciler
sweeps `$TMPDIR/briefcred-*` for mints whose certificate has passed its
`valid_before`. A directory whose certificate cannot be read is left alone.

## The HTTP proxy

The three `http-*` credential kinds work differently from every other minter,
because there is nothing to mint. An OpenAI API key is the only credential
OpenAI will accept; briefcred cannot create a short-lived one. What it can do
is make sure the subprocess never holds it.

So `briefcred exec` hands the subprocess a **synthetic token** —
`bc.<payload>.<signature>` — and points it at a proxy on loopback:

```sh
briefcred exec --profile=openai -- \
  curl https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"
```

The subprocess believes it has a key. What it has is a signed statement naming
a session and a credential, which is worth nothing to anything except
briefcred's proxy on this machine.

### What happens to one request

1. `curl` sends `CONNECT api.openai.com:443` to `127.0.0.1:9318`.
2. The proxy answers `200` and terminates the TLS the client then starts, with
   a leaf issued by briefcred's own CA. The client trusts it because
   `briefcred exec` set the CA-bundle variables (see **Trust environment**).
3. The proxy reads the inner HTTP/1.1 request and finds the synthetic token.
   It checks the signature, the expiry, and whether the grant has been revoked.
   A token that fails any of these is refused with a `proxy_token_rejected`
   audit row naming the method, host, path and reason (`revoked`, `expired`,
   `bad_signature` and so on), so a replayed or stolen token leaves a trace.
   The row never holds the token.
4. It takes one token off the session's quota bucket, if the profile set one.
   Before the policy, so a denied request is still counted.
5. It asks the profile's Cedar policy whether this session may make this
   request, passing the session's own totals and the clock as `context`.
   Default deny; see `docs/policy.md` and `docs/policy-cookbook.md`.
6. It replaces the token with the real credential, rendered for the kind, and
   forwards the request over its own TLS connection to the real vendor —
   verified against the system trust store, with no way to weaken that.
7. Bodies stream through in both directions. Nothing is buffered whole.
8. One `ProxyRequest` audit row is written when the response ends: method,
   host, path, status, byte counts, latency, decision. No headers, no body,
   and no query string.

A request the policy refuses never reaches the vendor at all, and no
credential is attached to it.

`decision` says who refused, which matters because two of its values are not
policy outcomes:

| `decision` | meaning | `status` |
| --- | --- | --- |
| `allow` | permitted and forwarded | the upstream's |
| `deny` | the policy refused it, or the token did not authorise | absent |
| `would_deny` | the policy refused it and the profile is observing | the upstream's |
| `quota` | the session's budget was spent; the policy was never asked | absent |
| `bad_request` | the request was malformed; nothing decided it | absent |
| `swap_error` | the policy allowed it; the credential would not go in | absent |
| `upstream_error` | the policy allowed it; the upstream was unreachable | absent |

`status` is the *upstream's* code, so it is absent wherever the request never
got one. That is what keeps "briefcred is broken" and "the vendor is down"
apart on a dashboard, and it is why a `502` briefcred generated is not recorded
as though a vendor had sent it.

### The three kinds

| `kind` | Master | What the upstream receives |
| --- | --- | --- |
| `http-bearer` | the token | `Authorization: Bearer <master>` |
| `http-header` | the value | `<config.name>: <master>` |
| `http-basic` | `user:password` | `Authorization: Basic <base64(master)>` |

Each publishes two fields: `TOKEN`, the synthetic token, and `PROXY_URL`, the
address it has to be sent through — for a runtime that ignores `HTTPS_PROXY`
and has to be told explicitly.

```yaml
credentials:
  - name: openai
    kind: http-bearer
    ttl_secs: 900
env:
  OPENAI_API_KEY: ${minted.openai.TOKEN}
```

`examples/profiles/openai.yaml` is a complete one.

### Placeholders

For a tool that already speaks the `__name__` convention, any header value
containing `__<credential name>__` gets the real value substituted, for every
credential **this run minted** — a `--cred openai` run substitutes `__openai__`
and forwards a `__stripe__` untouched, even on a profile that declares both:

```yaml
env:
  MY_TOOL_HEADER: "X-Api-Key: __openai__"
```

The request still has to carry a synthetic token somewhere, because that is how
the proxy knows which session it belongs to.

### The proxy environment

`briefcred exec` sets `HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY` — three
spellings because there is no agreement on which one a runtime reads — whenever
the profile declares at least one `http-*` credential. A profile whose value is
the *policy* rather than a credential can ask for them anyway:

```yaml
proxy: always
```

That points a subprocess at the proxy with a Cedar allowlist and no credentials
at all, which is a usable egress control on its own.

A request with no token is refused, because a token is how the proxy knows whose
session — and so whose policy, quota and audit trail — a request belongs to. So
for a `proxy: always` profile that declares no `http-*` credential, `exec` issues
a **policy-only** token and publishes it as `BRIEFCRED_PROXY_TOKEN` alongside the
three proxy variables:

```sh
briefcred exec --profile=egress -- \
  curl -H "Proxy-Authorization: Bearer $BRIEFCRED_PROXY_TOKEN" https://example.com
```

The token names no credential. There is no master behind it, nothing is
substituted into any header, and it authorises nothing beyond "this request
belongs to this session" — which is all the policy needs to decide it. It is
retired when the command exits, like every other grant.

### Streaming: server-sent events and WebSocket

Both go through the proxy, and both go through the same checks first. A
streaming response is still one request: the token is verified, the quota is
charged, and the policy decides it before a byte of it exists.

**Server-sent events.** A response whose `Content-Type` is `text/event-stream`
is forwarded chunk by chunk as the upstream produces it. Nothing is collected:
an event reaches the subprocess when it is sent, keep-alive comments
(`: still here`) are passed through untouched, and the upstream closing closes
the client's stream. The proxy drops any `Content-Length` the upstream put on
it, because the length of a stream that ends when its upstream ends is not a
number anyone can state in advance.

**WebSocket.** A request carrying `Upgrade: websocket` and `Connection:
Upgrade` is a `GET`, and the policy decides it as one — a profile that does not
permit the handshake's path does not get a WebSocket. If it is permitted, the
credential is swapped in, the handshake is completed with the upstream, and the
upstream's `101` is checked: briefcred forwards the client's own
`Sec-WebSocket-Key` and will not relay unless the accept token comes back
correct. After that the two halves are byte-forwarded in both directions.

Each stream gets a `proxy_stream` audit row when it ends, alongside the
`proxy_request` row for the response or the `101` that started it:

```json
{"event":"proxy_stream","kind":"sse","host":"api.openai.com",
 "path":"/v1/responses","started":"...","ended":"...",
 "events_or_frames":412,"bytes_up":390,"bytes_down":88213}
```

`events_or_frames` counts framing and nothing else: blank-line-terminated event
blocks that carried a `data:` field, or WebSocket frame headers in both
directions. No event's data and no frame's payload is read to produce it, and a
WebSocket payload is never unmasked.

`Sec-WebSocket-Extensions` is passed through as the client and upstream
negotiated it, and briefcred does not read what it says. If they agree on
`permessage-deflate`, the payloads on the wire are compressed and briefcred goes
on counting frame headers and wire bytes without noticing: `bytes_up` and
`bytes_down` are bytes as they crossed the connection, not bytes as the
application saw them, and `events_or_frames` is frame headers rather than
messages, which a fragmented message makes more than one of.

A WebSocket also spends the session's byte budget. The bytes running towards the
client are added to the session's running total as the socket carries them, once
a second or every 64 KiB, so a Cedar `context.resp_bytes_so_far` sees a
long-lived socket spending its budget while it is still open rather than only
once it closes.

A stream does not outlive its grant. The same one-second liveness poll the
Postgres proxy uses runs for as long as a stream is open, and expiry,
revocation, or the session closing ends both halves within about a second.

### HTTP/2 and gRPC

The client-facing side of a `CONNECT` tunnel advertises ALPN `h2` and
`http/1.1`, and a client that picks `h2` is served HTTP/2. The upstream
negotiates **separately**, on its own connection: an HTTP/2 client whose vendor
only speaks HTTP/1.1 still gets its request forwarded, and an HTTP/1.1 client
whose vendor speaks HTTP/2 gets the benefit without knowing about it. A plain
`http://` request with an absolute URI stays HTTP/1.1, and so does a WebSocket
handshake, which has no HTTP/2 spelling briefcred speaks.

Nothing else changes. **A stream is a request**: the token is verified, the
quota is charged, and the Cedar policy decides each stream on its own, so a
connection carrying a hundred calls is a hundred decisions and a hundred
`proxy_request` rows.

An upstream HTTP/2 connection is kept and multiplexed, keyed on the session,
the credential, and the destination together. Nothing looser: two sessions hold
two different masters, and an upstream that treats a connection as
authenticated must never be handed one session's stream on another's. It is
dropped when the grant is revoked or the session closes, so nothing stays open
at a vendor for a grant that has ended. Dialling is serialised per destination
and bounded at ten seconds, so a host that never answers delays only the
requests headed for it.

**gRPC works over this with nothing gRPC-specific in the proxy.** A gRPC call is
a `POST` whose path is the service and method, so a policy names it as one:

```yaml
policy: |
  permit(principal, action == Action::"POST", resource)
  when { resource.host == "api.vendor.com" &&
    resource.path like "/vendor.v1.Embeddings/*" };
```

Bodies are never buffered, so all four call shapes work: unary,
server-streaming, client-streaming, and bidirectional. Trailers are relayed
frame for frame, which is what makes gRPC work at all — `grpc-status` and
`grpc-message` arrive after the body, and a proxy that dropped the trailer frame
would deliver every byte of every response and then fail every call. briefcred
forwards trailers without reading them. A vendor that does not speak HTTP/2
cannot carry a gRPC call, and one is refused with a reason rather than
downgraded into a response the client cannot parse.

A gRPC call does not outlive its grant. Every HTTP/2 response whose length the
upstream did not state is watched by the same one-second poll an event stream
gets, so expiry, revocation, or the session closing ends a server-streaming or
bidirectional call within about a second and writes a `proxy_stream` row of
kind `h2-stream`. Its `events_or_frames` is `0`: nothing inside the body is
parsed, because a gRPC message's own framing is the call's content.

When a client's HTTP/2 connection closes it gets one `proxy_h2_connection` row,
alongside the per-stream rows, which each name it:

```json
{"event":"proxy_h2_connection","connection_id":"h2-9f31c0a2b4de",
 "host":"api.vendor.com","started":"...","ended":"...",
 "streams":140,"bytes_up":81204,"bytes_down":2140338}
```

There is no path and no status on it, because a connection has many of each.
`briefcred_proxy_h2_connections_total` and `briefcred_proxy_h2_streams_total`
count the same two things; the ratio between them is how you tell a client that
is multiplexing from one that has fallen back to a connection per call.

### Revoking

`briefcred exec` finishing revokes the grant: the daemon stops honouring any
token naming that session and credential, at once, and the proxy answers `403`.
There is nothing at a vendor to undo, so the revoke cannot fail. It is held in
memory only, which is correct rather than a shortcut — every entry is
discardable exactly when the token it names would have expired anyway, so a
daemon restart loses nothing a token could still be used with.

### The limit, stated plainly

A gRPC call's trailers are opaque to the policy. briefcred relays
`grpc-status` and `grpc-message` untouched and never reads them, so a policy
decides whether a method may be called and never what it answered.

A WebSocket is opaque to the policy after its handshake. briefcred decides
whether the connection may be opened, and then forwards bytes; it does not
read, decode, or rule on the messages that cross it. A profile that permits a
WebSocket path permits everything an agent chooses to say over it.

A token bound to a session key can be proved: a client that signs a `DPoP`
header demonstrates possession of the key the token's `cnf.jkt` names, and the
proxy checks it. `briefcred exec` cannot do that, because the credential
reaches the subprocess as an environment variable and the subprocess is `curl`.
So the proxy also accepts a bare token, and on that path **the token is a bearer
credential**: anything that can read the subprocess's environment can use it,
for as long as it lives, from this machine. `THREAT_MODEL.md` says what that
does and does not buy.

## Model Context Protocol tools

`briefcred mcp` exposes briefcred to an agent as an MCP server. Point your
client at it:

```json
{ "mcpServers": { "briefcred": { "command": "briefcred", "args": ["mcp"] } } }
```

The command itself does nothing but copy bytes: the server is the daemon, which
is where the profiles, the session, the unlock gate and the helper processes
already are. `briefcred mcp` connects to the socket, upgrades the connection,
and pumps stdin and stdout through it.

Three tools, and the shape of them is the whole idea:

| Tool | What it takes | What it gives back |
| --- | --- | --- |
| `briefcred_list_profiles` | nothing | Profile names, credential kinds, TTLs, allowed commands |
| `briefcred_db_query` | `profile`, `sql`, `max_rows` | Rows as JSON, read-only |
| `briefcred_exec` | `profile`, `argv` | `stdout`, `stderr`, `exit_code` |

**No tool returns a credential.** An agent handed a connection string has that
string in a transcript, a context window, and a model provider's
infrastructure, and briefcred's revoke is racing all of them. So the tools are
verbs: the credential is minted in the daemon, used in the daemon, and revoked
by the daemon, and there is never a value for the agent to leak.

One MCP connection opens one session and mints once. A tool call naming a
second profile is refused rather than opening a second session. When the
connection closes — cleanly, or because the client was killed — the session
closes with it and everything it minted goes on the revoke queue.

`briefcred_exec` enforces `exec.allow_argv0` and `exec.allow_args` before
anything is minted, exactly as `briefcred exec` does, and captures at most 1
MiB of each stream, saying so when it truncates. `briefcred_db_query` runs one
statement as the minted role and returns at most `max_rows` rows (100 by
default, 10,000 at most). A column type briefcred cannot represent comes back
as a note telling you to cast it to text.

A statement is bounded at both ends, and by the **server** rather than by the
daemon reading less than it asked for. `max_rows` becomes a portal row limit,
so a `SELECT` over a billion rows produces the rows asked for and stops;
`mcp_query_timeout_secs` in `daemon.toml` (30 seconds by default) becomes the
connection's `statement_timeout`, so a runaway query is cancelled at the
database. A command that writes without stopping is killed at the output cap
rather than buffered, and one that writes nothing and never exits is killed at
`mcp_exec_timeout_secs` (300 seconds by default). The kill goes to the child's
whole process group, so a command that started something of its own does not
leave it attached to the daemon, and the tool call returns an error naming the
bound rather than never returning.

A portal needs a transaction, and that transaction is **rolled back**, so
`briefcred_db_query` cannot write. This is deliberate and not a side effect of
the mechanism: a partially fetched `INSERT ... RETURNING` has inserted the rows
it produced and not the rest, and committing that would let a display limit
decide how much of a write survived. The tool says so in its own description,
so a model does not discover it by having a write disappear. A profile that
needs to write should grant `SELECT` only and route writes through
`briefcred_exec`, where the command owns its own transaction.

Every call writes an `mcp_call` audit row carrying an `mcp_call_id`, the tool,
the profile, the mints it used, and the outcome — never the SQL or the command
line, which are exactly the free-form text an audit row must not hold. Where a
failure quotes the caller's input back, the two are deliberately different
strings: a rejected statement tells the caller `42P01: relation "salaries" does
not exist` and tells the audit log only `42P01`. A `briefcred_exec` also writes
the same `exec_start` and `exec_end` rows a `briefcred exec` does.

An MCP profile is the widest grant briefcred makes. `exec.allow_argv0` is not
optional on one; see `THREAT_MODEL.md`.

## Helper processes

The daemon does not mint. It spawns `briefcred-helper-<kind>` — for
`kind: postgres-dynamic`, `briefcred-helper-postgres-dynamic` — and talks to it
over stdio with JSON-RPC 2.0, one object per line, with the methods `mint`,
`revoke`, `reconcile`, and `shutdown`.

That boundary is the point. The code that opens a database connection, parses a
backend's replies, and holds a master password runs where the daemon's own
memory is not: a panic costs one backend, and a memory-disclosure bug exposes
one master rather than every master. One process per `(profile, kind)`, started
on first use and stopped when the session closes.

Helpers are looked for next to the daemon's own executable first, then in
`BRIEFCRED_HELPER_DIR`. That order is deliberate — preferring the environment
variable would let anything that can set the daemon's environment choose what
code the daemon runs. The variable exists for `cargo run` and the tests.

## Memory hygiene

The daemon claims a master credential lives for the length of the session that
needed it and no longer. `just mem-hygiene` checks the claim: it builds a daemon
with the `debug-heapscan` feature, uses a random 32-byte marker as a master,
asserts the daemon holds it while a session is open, closes the session, and
asserts it is gone.

The request takes a SHA-256 digest rather than the marker, so the needle never
crosses the socket and cannot be found as a copy of itself. The feature is never
built into a shipping daemon: a same-uid caller who could ask a daemon to search
its own memory for a digest would have a confirmation oracle for guessed
secrets.

## Releases and packaging

A tag matching `v*` runs `.github/workflows/release.yml` on a macOS runner. It
builds every binary for `aarch64-apple-darwin` and `x86_64-apple-darwin`, joins
each pair with `lipo` into one universal Mach-O, signs and notarises them when
Apple credentials are configured, and publishes a tarball with its SHA-256 sum
as a GitHub release. The three steps are ordinary scripts under
`release/scripts/`, so a release can be built by hand.

**Without Apple credentials the release still happens, unsigned.** That is
deliberate: a release only one person can build is one that stops being built.
The release notes say which kind it is, and an unsigned build is quarantined by
macOS on first launch. The signing path wants six secrets —
`APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`,
`APPLE_API_KEY`, `APPLE_API_KEY_ID`, `APPLE_API_ISSUER` — and skips cleanly
when any is missing.

Note that a notarisation ticket cannot be stapled to a bare command line
executable: stapling applies to bundles, disk images and installer packages.
A notarised briefcred binary is checked against Apple's service the first time
it runs.

`release/Formula/briefcred.rb` is the Homebrew formula. It installs all five
binaries — `briefcred` and `briefcred-daemon`, the two helper processes the
daemon spawns to mint, and `briefcred-hook` for the agent — and carries a
`service` block so `brew services start briefcred` runs the daemon as a
LaunchAgent, equivalently to what `briefcred install` writes.

Its `url` and `sha256` in the tree are placeholders, because the checksum of a
release that has not been built yet does not exist. The workflow runs
`release/scripts/stamp-formula.sh`, which rewrites exactly those two lines from
the tarball it just built, and uploads the stamped formula as a release asset
named `briefcred.rb`.

**Publishing the tap is a separate, manual step.** The tap is its own
repository, created out of band, and the release workflow holds no token for
it: updating it means copying the `briefcred.rb` asset from the release into
the tap and committing it. That is one deliberate manual act per release rather
than a release workflow with write access to a second repository.

### Cutting a release

The workflow is the release; this is the order the human part goes in.

1. **Bump the version** in the workspace `Cargo.toml` (`workspace.package
   .version`) and run `cargo update --workspace` so `Cargo.lock` follows. Every
   crate inherits it, so there is one number to change.
2. **Write the CHANGELOG section.** Rename `## Unreleased` to the new version
   with today's date, and open a fresh `## Unreleased` above it.
3. **Run the gates.** `just check && cargo test --workspace --locked`. The
   supply-chain half of `just check` is the one that fails at release time if
   it has not been run since the last dependency was added.
4. **Commit and tag.** The tag is the version with a `v` prefix and nothing
   else: `v0.2.0` for version `0.2.0`. The workflow triggers on `v*` and the
   release notes are built from the tag.
5. **Watch the first workflow run**, because it is the live test of the release
   path. An unsigned release is a successful run, not a failed one — check the
   notes say which kind it produced.
6. **Audit the formula before publishing the tap.** Download the `briefcred.rb`
   asset and run `brew audit --strict --formula ./briefcred.rb` on a machine
   with a working Homebrew. Then copy it into the tap repository and commit;
   nothing automates that step, and deliberately so.

## Security

Report vulnerabilities privately, as described in [`SECURITY.md`](SECURITY.md).

## Licence

MIT OR Apache-2.0, at your option. The texts are `LICENSE-MIT` and
`LICENSE-APACHE` in this repository, and the release tarball ships both.
