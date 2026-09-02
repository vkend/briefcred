# Architecture

briefcred is a local credential broker for AI agents and developer tooling. It
has two halves that share one daemon, one policy engine, and one audit log.

- **Identity broker.** Mints real, short-lived backend credentials — dynamic
  PostgreSQL roles today, AWS STS sessions and SSH certificates later — and
  takes them away again when the work is done.
- **Credential-exchange proxy.** Terminates TLS locally so a subprocess can
  hold a synthetic placeholder while the real secret is substituted on the
  wire.

Neither half is the product on its own. Placeholder-swap proxies are
commoditised; hosted brokers mint but are not local. The combination — local
minting plus locally enforced policy plus biometric presence — is the wedge.

## Credential-handoff models

Every credential path is classified by how much of the real secret the
subprocess can see.

| Model | What the subprocess holds | Strength |
| --- | --- | --- |
| **A** | A synthetic token. The proxy injects the real credential. | Strongest |
| **B** | A short-lived credential minted for this run. | Middle |
| **C** | The real credential, revoked afterwards. | Weakest |

Model C is a stepping stone, never a destination. Where a phase ships Model C,
`THREAT_MODEL.md` says so explicitly and names the phase that closes it.

| Phase | Capability | Model |
| --- | --- | --- |
| 0 | Postgres dynamic role minting (library only) | B |
| 1 | Daemon foundation: IPC, lifecycle, audit, metrics | n/a |
| 2 | Per-machine root CA, trust install | n/a |
| 3 | Daemon-orchestrated minting, biometric gate, `exec` wrapper | C |
| 4 | Thin TLS-terminating proxy, placeholder swap for HTTP APIs | A |
| 10 | Postgres connection-auth injection at the proxy | A |
| 5 | Cedar policy engine | n/a |
| 6 | Agent hook integration | inherits |
| 7 | AWS STS and SSH certificate minters | B |
| 8 | Reconciliation, retention, and operational hardening | n/a |
| 9 | Packaging and distribution | n/a |

Phase 3 hands a minted Postgres role to the subprocess through environment
variables, which is Model C for that credential: the process can read
`PGPASSWORD`. Phase 10 moves PostgreSQL to Model A with the `postgres-proxy`
kind, where the daemon completes the authentication handshake itself and the
subprocess holds a synthetic token instead of any password. That is why Phase 10
is sequenced immediately after the thin proxy rather than at the end.

The two Postgres kinds are alternatives rather than a replacement.
`postgres-dynamic` (Model B) is still the better answer where the master has
`CREATEROLE`: the credential the subprocess holds is real, short-lived, and
revocable at the backend independently of briefcred. `postgres-proxy` (Model A)
is for the databases where that is impossible — a managed cluster with no
`CREATEROLE`, a database owned by another team — and it buys a stronger
handoff at the cost of every connection depending on a live daemon.

Phase 4 is what makes Model A real for HTTP. The `http-*` kinds hand the
subprocess a **synthetic token** and keep the API key in the daemon, so the
process can read its whole environment and still not have the credential. What
it holds is a bearer token for briefcred's own loopback proxy, bounded by the
session it was issued to, the profile's Cedar policy, and its own expiry.

## Crate map

```
briefcred-core      types, profile schema, minter contracts, audit rows, minters
briefcred-proto     wire types for daemon IPC                        (Phase 1)
briefcred-daemon    the per-user daemon                              (Phase 1)
briefcred-cli       the `briefcred` binary                           (Phase 1)
briefcred-hook      the `briefcred-hook` agent shim                  (Phase 6)
briefcred-helper-postgres  the PostgreSQL minting helper              (Phase 3)
briefcred-helper-sts       the AWS STS minting helper                 (Phase 7)
briefcred-e2e       test-only: Postgres and daemon harnesses, e2e tests
```

A helper's **binary** is
named for the minter kind it serves rather than for its crate —
`kind: postgres-dynamic` means `briefcred-helper-postgres-dynamic` — because
the kind string is all the daemon holds when it goes looking, and a lookup table
in between would be a third place for the name to drift. One crate can grow a
second kind and a second binary.

`briefcred-core` depends only on `briefcred-proto`, and does so for one module:
`helper_adapter`, which runs a `Minter` behind the daemon-to-helper protocol.
Three places need that conversion — each helper binary, and the daemon for the
one kind it hosts itself — and a second copy of it would be a second chance to
turn a refused revoke into a protocol error. Everything else depends on
`briefcred-core`, because the profile schema and the minter contract are the
two things every crate has to agree on.

## Module map inside `briefcred-core`

| Module | Responsibility |
| --- | --- |
| `paths` | The only place that knows where files live. `BRIEFCRED_HOME` overrides everything. |
| `profile` | The profile schema, its YAML loader, and the `${...}` env template grammar. |
| `types` | `MintId`, `MintCtx`, `RevokeCtx`, `MintedCredential`, `RevokeOutcome`. |
| `traits` | `MasterSource` and `Minter`. |
| `audit` | `AuditEntry` and argument hashing. |
| `minters` | Concrete minters, each registering itself with the registry. `aws_sts` registers only a schema; its minter is in `briefcred-helper-sts`. |
| `helper_adapter` | One `Minter` behind the helper protocol, shared by every helper and by the daemon. |
| `registry` | `MinterFactory` and the `inventory`-collected `Registry` that resolves a profile's `kind`. |
| `source` | The `MasterSource` backends: keychain, file, and environment. |
| `session_env` | Whether the calling process has a screen. Read by the daemon *and* the CLI. |
| `keystore` | The `KeyStore` trait, the macOS keychain backend, and the file backend. |
| `ca` | The root CA, leaf issuance, and the runtime trust environment. |
| `exec` | The two pure decisions behind `briefcred exec`: is the command allowed, and what environment does it get. |
| `policy` | The fixed Cedar schema, the request context, the compiled form of a profile's `policy`, and the enforce/observe split. |
| `minisign` | Minisign-compatible Ed25519 keys and detached signatures. Verifies both the legacy `Ed` and the prehashed `ED` form; only ever produces `Ed`. |
| `distribution` | The `[profiles]` config, the three registry URL schemes, the fetch, and the trusted profile set with its precedence rules. |

`minters::http` and `minters::postgres_proxy` are the two modules that register
a schema and no minter at all: both are `Hosting::Proxy`, meaning the "mint" is
a signed token and the real work happens in one of the daemon's two proxies.

## Data flow: one `briefcred exec`

```
  user                CLI              daemon            minter        backend
   |                   |                 |                 |              |
   |-- exec <profile> ->|                 |                 |              |
   |                   |-- OpenSession -->|                 |              |
   |                   |                 |-- unlock (LAContext) ---> [Touch ID]
   |                   |                 |<- ok ------------|              |
   |                   |                 |-- fetch master (Keychain)       |
   |                   |                 |-- mint(MintCtx) ->|              |
   |                   |                 |                 |-- CREATE ROLE ->|
   |                   |                 |                 |-- GRANT ...  ->|
   |                   |                 |<- MintedCredential               |
   |                   |                 |== audit: Mint ==>  (JSONL)       |
   |                   |<- bundle --------|                 |              |
   |                   |-- spawn child with a constructed env              |
   |                   |== audit: ExecStart ==>                            |
   |<-- child stdio ---|                 |                 |              |
   |                   |-- child exits -->|                 |              |
   |                   |== audit: ExecEnd ==>                              |
   |                   |                 |-- revoke(RevokeCtx) ->|          |
   |                   |                 |                 |-- REVOKE ... ->|
   |                   |                 |                 |-- DROP OWNED ->|
   |                   |                 |                 |-- DROP ROLE  ->|
   |                   |                 |<- RevokeOutcome -|              |
   |                   |                 |== audit: Revoke ==>              |
```

The CLI returns as soon as the child exits. Revoke runs in the background on a
retrying queue, and a periodic reconciliation sweep scans `pg_roles` for stale
`briefcred_t_%` principals so a `SIGKILL` mid-exec still converges.

## Who composes the subprocess environment

The daemon composes it; the client applies it.

The daemon is the only side that holds the profile, the minted fields, and the
CA path at once, so putting the `${minted.<credential>.<field>}` substitution
there means one implementation of that grammar rather than two that can
disagree about it. `Response::Minted` therefore carries a finished `env` map.

The client's half is mechanical and has no judgement in it:

1. `Command::env_clear()`,
2. copy each name in `passthrough` from its own environment, if it has it,
3. apply the daemon's `env` on top,
4. spawn.

The passthrough list crosses the socket as **names**, not values, because the
client's own environment is the one thing the daemon cannot see. Step 3 is last
so a profile can override a passed-through variable.

Clearing rather than adding is the security-relevant half. An agent's shell is
full of things briefcred did not put there, including credentials the user
already had; starting from empty means the subprocess gets what the profile
granted it and nothing else.

## The three nets under a minted credential

Each catches a failure the one before it cannot.

| net | catches | cannot catch |
| --- | --- | --- |
| The revoke queue | A normal exit, and a daemon restart: entries are fsynced to `state/revoke-queue.jsonl` before being acknowledged. | A `SIGKILL` between the mint and the enqueue. |
| The session | A wrapper that died without reporting: closing, evicting, or shutting down queues whatever it minted. | A daemon that is killed with the session in memory. |
| The reconciler | Everything else. Runs at startup and every `reconcile_interval_secs` against each profile's backend. | A backend that is unreachable, until it is not. |

The reconciler identifies a stray as "named `briefcred_t_%` **and** past its
`VALID UNTIL`". Both halves matter: the prefix is what makes it ours, and the
expiry is what stops the sweep removing a role a live `briefcred exec` on
another machine is still using.

## Why revoke is shaped the way it is

`DROP OWNED BY` alone is not a revoke. It only removes privileges the current
role is entitled to revoke, and on managed PostgreSQL the master role does not
own schema `public`. So revoke replays the mint's grant template as a symmetric
`REVOKE` loop **first**, then attempts `DROP OWNED BY` to clear objects the
role created, then `DROP ROLE`. PostgreSQL 18 additionally made `DROP OWNED BY`
delete `pg_auth_members` rows, which would strip the master's membership of the
minted role — another reason the `REVOKE` loop cannot run second.

The ordering is asserted directly: `revoke_plan` builds the statement list as a
value, and a unit test checks that every `REVOKE` precedes `DROP OWNED BY`.

## On-disk layout

macOS:

```
~/Library/Application Support/briefcred/
  sock            daemon Unix socket, mode 0600
  profiles/       *.yaml work envelopes you wrote
  profiles/registry/<name>/   *.yaml fetched from a registry, each with a .minisig
  audit/          append-only JSONL, daily rotation
  ca/             ca.pem (0644) and, on the file backend, ca.key (0600)
  logs/           daemon stdout and stderr, written by the service manager
  state/          daemon state that survives a restart
  daemon.toml     daemon configuration
```

Every directory is mode `0700`. The service unit lives outside this tree, at
`~/Library/LaunchAgents/dev.briefcred.daemon.plist` or
`~/.config/systemd/user/briefcred.service`, because launchd and systemd have to
read it. `BRIEFCRED_HOME` relocates that too, which is what keeps tests out of
the real `~/Library/LaunchAgents`.

Linux uses `$XDG_DATA_HOME/briefcred` (default `~/.local/share/briefcred`) with
the socket at `$XDG_RUNTIME_DIR/briefcred/sock`. `BRIEFCRED_HOME` relocates the
whole layout, including the socket; tests always set it.

## Profile distribution

Two directories, two standards.

```
profiles/*.yaml                     local; no signature required
profiles/registry/<name>/*.yaml     fetched; dropped unless a .minisig verifies
```

`briefcred profile sync` fetches each registry named in `daemon.toml` into a
staging directory beside the target and moves it into place at the end, so a
failed sync leaves the previous contents rather than a mix of two. It refuses
to write a file no trust root vouches for. The daemon then checks again at
load, because the CLI's check is feedback for a person and the daemon's is the
one that decides what runs — and a file that reaches the registry directory by
some other route still has to pass it.

`ProfileSet::load` builds the set the daemon serves: registry profiles first,
in alphabetical order of registry name, then local ones over the top. A local
profile that shadows a registry one records which. The wire type carries all of
it — `source`, `signature`, `signer_key_id`, `overrides` — so a client deciding
whether to run a profile can see who chose its allowlist.

Two failure modes, deliberately handled differently:

| What went wrong | What happens |
| --- | --- |
| A file does not parse or does not validate | The whole reload fails; the previous set stays in force; `profile_load_error` |
| A registry file does not verify | That file is dropped; the rest of the set loads; `profile_trust_warning` |
| A fetch yields no profiles over a registry that has some | The swap is refused; the previous set stays; `sync` exits non-zero |

Last-good exists so one typo does not cost you every profile. Applying it to a
signature failure would mean continuing to run a profile *because* its
signature had just gone bad, so it does not.

`dev_mode` inverts the second row — the file loads, marked `dev_mode` — and
pays for it in noise: stderr at every load, a banner above
`briefcred profiles`, and a `profile_trust_warning` row per file with
`action: "loaded_dev_mode"`.

## Invariants

1. Secret material lives in `Zeroizing<String>`. `Debug` is hand-written to
   redact it, and secret-bearing types are not `Serialize`.
2. Audit rows are metadata only. Arguments are recorded as SHA-256 digests.
3. Free-form profile text never reaches SQL. Identifiers are quoted with the
   PostgreSQL escaping helpers and grant clauses are restricted to keywords and
   dotted identifiers.
4. Policy is typed and compiled, never string-interpolated.
5. A failed revoke always carries a non-empty detail. A row with
   `outcome=failed` and no detail is a bug.
6. The CA private key is never written to `ca.pem` and never reaches a `Debug`
   output. `ca.pem` holds the public half alone.
7. Anything that needs `sudo` is built as a plan and executed separately, so
   `--dry-run` can print it and no test can ever run it.
8. The unlock gate runs before any master is fetched. A refused prompt leaves
   no master in the daemon's memory at all.
9. A gate that cannot run fails closed. With no graphical session there is no
   weaker fallback, only `NoAquaSession` — and that check runs before the
   unlock cache, so a warm cache cannot carry a headless caller through it.
   The check is the union of the daemon's own and the client's declared
   answer, because neither process can see the other's session. The client's
   half is advisory; see `THREAT_MODEL.md`.
10. A session is the lifetime of the masters it holds. There is no "closed"
    flag: closing, evicting, and shutting down all drop the session, and
    dropping it zeroises every master in it.
11. Profiles cross the socket as a `ProfileSummary` built by hand, never as the
    daemon's own `Profile`, so a future profile field cannot leak by default.
12. The allowlist is checked before anything is minted. A command the profile
    forbids must never cause a principal to be created.
13. The daemon does not mint. Every minter runs in a helper process, so the
    code holding a master password is not in the daemon's address space.
14. The revoke queue is written and fsynced before a revoke is acknowledged.
    An entry that reached the file is one the reconciler does not have to find.
15. The revoke queue file holds metadata only: an identifier, a kind, a profile
    name, and connection settings. Never a master, never a minted secret.
16. `SecretString` is the only serialisable secret type, it exists only on the
    daemon-to-helper pipe and the `Minted` reply, and it prints `<redacted>`.

## The helper protocol

JSON-RPC 2.0, one object per line, on the child's stdin and stdout. Four
methods and no more: `mint`, `revoke`, `reconcile`, `shutdown`. `stderr` is
inherited so a helper's diagnostics reach the daemon's log without a helper
being able to corrupt the protocol stream by printing to it.

```
daemon                          briefcred-helper-postgres-dynamic
  |-- {"method":"mint",...} ------->|
  |                                 |-- CREATE ROLE / GRANT ------> backend
  |<-- {"result":{"fields":...}} ---|
  |-- {"method":"shutdown"} ------->|   (at session close)
  |<-- {"result":{"stopping":true}}-|
```

The master credential has to reach the helper somehow, and the pipe is the only
channel. `briefcred_proto::SecretString` is the one type in briefcred that is
deliberately `Serialize`; it holds `Zeroizing<String>`, prints `<redacted>`,
and appears nowhere but this wire and the `Minted` reply.

A minter registered as `Hosting::Daemon` answers the same four methods from
inside the daemon, through `MinterAdapter`. Nothing above the `MintChannel`
trait knows the difference, so moving a minter into a helper — or out of one —
is a change to its own registration and to nothing else.

A helper that stops answering is killed rather than waited on: it is holding a
master, and nothing it could still be doing is worth that. Replies are capped at
the same 16 MiB the client socket enforces, so both of the daemon's inputs are
bounded by one number.

Helper lifetime follows what owns the set. A **session's** helpers live as long
as the session, because a burst of `briefcred exec` calls against one profile
should pay one process start. The **reconciler's** and the **revoke queue's** are
stopped at the end of every pass: both are idle almost all of the daemon's life,
and a helper kept between passes is a master credential resident in a process
with nothing to do.

## The minter registry

A minter registers itself with `inventory::submit!` in the same file as its
implementation:

```rust
inventory::submit! {
    MinterFactory {
        kind: KIND,
        hosting: Hosting::Helper,
        validate: |config| { /* parse and check */ },
        construct: Some(|| Arc::new(MyMinter::new())),
    }
}
```

`Registry::discover()` collects whatever the binary was linked with, and
`Profile::validate(&Registry)` resolves every credential's `kind` and calls its
`validate` with that credential's `config`. Both failures therefore happen when
the profile is loaded, while the user is still looking at the file, rather than
at the first mint. An unknown kind names every kind that *is* registered, which
is the only thing that makes the message actionable.

`validate` and `construct` are separate for two reasons, each with a minter
that needs it.

**Every binary that reads a profile must be able to reject a bad one, but only
the binary that mints needs the minter.** `aws-sts` drags in the AWS SDK, which
the daemon, the CLI, and the hook would otherwise pay for to use none of it. So
`briefcred-core` registers `aws-sts` with a `validate` and `construct: None`,
and `briefcred-helper-aws-sts` constructs the minter directly. A daemon asked
to build one says which binary mints it rather than pretending it cannot.

**`hosting` says whether the daemon spawns a helper or runs the minter
itself.** `Hosting::Helper` is the default and the safe answer;
`Hosting::Daemon` is correct only for a minter that talks to no backend, since
the master is then resident in the daemon. `ssh-cert` is the only one. Both
shapes answer the same `MintChannel` trait in the daemon, so `exec` and
`reconcile` never branch on which they have. See `CONTRIBUTING.md`.

## The HTTP proxy

The `http-*` credential kinds have no backend to mint at: an API key is the
only credential the vendor accepts. So the proxy is the mechanism, and the
`briefcred-daemon::proxy` module is where every part of it lives.

| Module | Question it answers |
| --- | --- |
| `token` | Who sent this, and is the token still within its lifetime? |
| `issuer` | And has the grant it names been revoked? |
| `policy` | Is this session allowed to make this request? (cached compiles) |
| `swap` | What does the outgoing request carry instead? |
| `tls` | Terminating the client's TLS, and re-encrypting upstream. |
| `stream` | What happens after the head, when a response is long-lived. |
| `listener` | The loop that puts all of it in order. |
| `revocation` | The `(session, credential)` pairs no longer honoured. |

Alongside it, `briefcred-daemon::quota` answers the question the policy cannot:
*how much*. One token bucket per open session, built from the profile's
`quota:` when the session opens and dropped with it, charged by all four
surfaces that spend a credential — the HTTP proxy per request, the Postgres
proxy per connection, `exec` per run that mints, and the MCP server per
`briefcred_db_query` or `briefcred_exec` call. Per session rather than
per profile, so two concurrent runs get a budget each; and never persisted,
because a quota bounds one session's blast radius and a session does not
survive a restart.

### One request, in order

```
  subprocess          proxy                        upstream
      |                 |                             |
      |  CONNECT host:443                             |
      |---------------->|                             |
      |  200            |                             |
      |<----------------|                             |
      |  TLS (leaf from briefcred's CA)               |
      |<===============>|                             |
      |  GET /v1/models                               |
      |  Authorization: Bearer bc.…                   |
      |---------------->|                             |
      |                 | 1. verify signature, expiry |
      |                 | 2. revoked?                 |
      |                 | 3. DPoP proof, if present   |
      |                 | 4. quota: one token         |
      |                 | 5. Cedar: allow / deny      |
      |                 | 6. swap in the real key     |
      |                 |  TLS (system trust store)   |
      |                 |<===========================>|
      |                 |  GET /v1/models             |
      |                 |  Authorization: Bearer sk-… |
      |                 |---------------------------->|
      |  streamed response body, counted as it passes |
      |<----------------|<----------------------------|
      |                 | 7. ProxyRequest audit row   |
```

The order is the design. The signature is checked before the payload is parsed,
so a forged token never reaches a JSON parser. The policy runs before the swap,
so a refused request never has a credential attached to it. And the audit row
is written when the response body *ends*, because that is when the byte counts
are known — streaming a gigabyte and reporting zero would make them worse than
useless.

The quota is charged *before* the policy, which is the one step whose position
looks wrong and is not. A request the policy denies still spends a token: the
expensive thing to defend against is a loop, and a loop being denied is still a
loop — one that would otherwise get an unmetered retry channel precisely
because it is doing something forbidden. A throttled request is answered `429`
with a `Retry-After` and audited as `decision: "quota"`, kept distinct from
`deny` because widening a policy does not fix a quota and raising a quota does
not fix a denial.

Step 5 also carries a `context` the policy can match on: `hour` and `weekday`
in UTC, and the session's own `requests_so_far` and `resp_bytes_so_far`, both
counting what happened *before* this request. That is what lets a policy
express a time window or a per-session budget, which a per-request vocabulary
of method, host and path cannot.

### Streaming, and where it diverges

Two responses do not end when their head does, and `proxy::stream` is the whole
of the difference. Everything above still happens first: a stream is one
request, and it is authorised, charged, and decided exactly as any other.

An event stream — `Content-Type: text/event-stream` — keeps the ordinary
streamed body and puts a line scanner over it. The scanner holds at most the
first five bytes of the line in flight, which is enough to tell a `data:` field
from any other and not enough to hold an event's value, and it counts blocks
that a blank line dispatched. The `Content-Length` the upstream may have sent is
dropped, because the body the client is about to receive ends when the upstream
stops rather than at a count stated in advance.

A WebSocket handshake is a `GET` with `Upgrade: websocket` and `Connection:
Upgrade`, and the policy decides it as a `GET` on that path. After the swap the
handshake goes upstream intact; briefcred forwarded the client's own
`Sec-WebSocket-Key`, so the upstream's `101` is only accepted if
`Sec-WebSocket-Accept` is the token derived from it. The client then gets a
`101` built field by field from the upstream's, and both halves are taken over
and byte-forwarded. The frame parser reads opcode, mask bit, and length, steps
over the payload, and never unmasks one.

`Sec-WebSocket-Extensions` is forwarded as negotiated and never parsed, so under
`permessage-deflate` the bytes counted are wire bytes and the frames counted are
frame headers rather than messages.

Each stream writes a `ProxyStream` row when it closes, in addition to the
`ProxyRequest` row for the head that opened it. A stream that ran for an hour
would otherwise be one row written at the start with nothing after it. A
WebSocket also feeds the session's `HttpCounters` as it runs — once a second or
every 64 KiB, with the tail flushed from a `Drop` so a relay briefcred cut off
is still charged for what it carried. Without that, `context.resp_bytes_so_far`
would be a budget an agent could step around by asking for a socket.

Neither outlives its grant. `until_stale` is the same one-second poll
`pgproxy` runs on a live connection, mirrored rather than shared so that
neither proxy's liveness rules can be changed by an edit aimed at the other,
and it ends both halves on expiry, revocation, or the session closing.

### What never happens

- **A synthetic token is never forwarded upstream.** After the swap, every
  header value is checked again, and a request still carrying anything
  token-shaped is refused rather than sent.
- **Upstream TLS is never weakened.** There is no "accept any certificate" path
  in the module. The only way to add a root is `upstream_roots` in
  `daemon.toml`, which exists for the test suite and says so in its own
  documentation.
- **No header value is ever logged, formatted, or audited.** The errors name
  headers and credentials; the values are the secrets.
- **No query string reaches a policy or an audit row.** It routinely carries an
  API key.

### Where the destination comes from

Inside a `CONNECT` tunnel the request line is origin-form, so the host and port
come from the `CONNECT` line and nowhere else. A request that could name its own
destination would be one that could obtain a certificate for one vendor and a
connection to somewhere else entirely.

### Lazy loading, and why

Both the CA and the token-signing key live in the platform key store. Reading
either at daemon start would prompt for keychain access at every login,
regardless of whether anything on the machine ever proxies. So the signing key
is read on the first token and the CA on the first tunnel, and a daemon nobody
proxies through touches neither.

The proxy **loads** a CA; it never generates one. `briefcred install` does that.
A generated one would be a certificate nothing on the machine trusts, so the
honest failure is to say the CA is missing and name the command that makes it.

## The Postgres proxy

The `postgres-proxy` kind exists for the same reason the `http-*` kinds do —
there is no backend to mint at, and the master is the only thing that will
authenticate — but a database connection is not a request, so the mechanism is
different. There is no header to swap. The credential is exchanged once, at the
start of a session that then runs for minutes, by a protocol with two parties in
it. So the daemon does not rewrite anything: it performs **both**
authentications itself and then splices the two sockets together.

`briefcred-daemon::pgproxy` is where every part of it lives.

| Module | Question it answers |
| --- | --- |
| `startup` | What did this client open with, and what may be passed on? |
| `wire` | How is a message framed, and what does briefcred write itself? |
| `scram` | How does the daemon prove the master to the real server? |
| `forward` | Opening the upstream connection, and relaying bytes. |
| `audit` | The one row a connection leaves behind. |
| `listener` | The loop that puts all of it in order. |

### One connection, in order

```
  subprocess         pgproxy                       database
      |                 |                             |
      |  SSLRequest     |                             |
      |---------------->|                             |
      |  N              |                             |
      |<----------------|                             |
      |  StartupMessage user=<sid> database=analytics |
      |---------------->|                             |
      |  AuthenticationCleartextPassword              |
      |<----------------|                             |
      |  bc.<token>     |                             |
      |---------------->|                             |
      |                 | 1. verify signature, expiry |
      |                 | 2. revoked?                 |
      |                 | 3. user == sid?             |
      |                 | 4. database == config?      |
      |                 |  StartupMessage user=master |
      |                 |---------------------------->|
      |                 |  SCRAM-SHA-256, both ways   |
      |                 |<===========================>|
      |                 |  AuthenticationOk           |
      |                 |<----------------------------|
      |  AuthenticationOk                             |
      |<----------------|                             |
      |  the upstream's own ParameterStatus,          |
      |  BackendKeyData and ReadyForQuery, verbatim   |
      |<----------------|<----------------------------|
      |  bytes, both directions, counted not parsed   |
      |<===============>|<===========================>|
      |                 | 5. PgConnection audit row   |
```

The order is the design, and the fifth arrow is the part that matters: the
upstream authentication completes **before** the client is told anything. A
client is therefore never sent `AuthenticationOk` for a connection that does not
exist, and a wrong token never causes a connection to the database at all.

### Why the client sends a cleartext password

Because what it sends is not a password. It is a signed token that names one
session and expires with it, and the point of MD5 and SCRAM is to keep a
*reusable* secret off the wire. SCRAM would also be impossible to arrange here:
the proxy would need the token's salted verifier before the client connected,
and the token is minted per `exec`.

What makes it acceptable is the address. The listener is bound to `127.0.0.1`
and nothing else, so the wire is a loopback socket on the user's own machine —
the same channel the token already arrived over, in the subprocess's
environment. `pgproxy.tls = true` puts TLS underneath it, with a leaf from
briefcred's own CA, for a client that will not connect without one.

### What never happens

- **The master never crosses the wire.** SCRAM proves it without sending it, and
  the one method that would send it — `AuthenticationCleartextPassword` from the
  *upstream* — is refused outright. MD5 is refused too unless
  `pgproxy.allow_md5` is set, and `SCRAM-SHA-256-PLUS` is never downgraded to
  its unbound variant.
- **The server's signature is always checked.** A server that cannot produce it
  does not hold the master, and the connection is abandoned rather than relayed.
- **The client's startup parameters are not passed through.** Only
  `application_name` and `client_encoding`. `options` in particular can set
  arbitrary session configuration, and the upstream connection is authenticated
  with a master the client does not hold.
- **No statement is ever seen.** After `ReadyForQuery` the proxy copies bytes
  through a fixed 16 KiB buffer without parsing them, so the audit row's silence
  about queries is structural rather than a policy that could be changed.

### And it keeps checking

`relay` does not run until a socket closes. It runs until a socket closes **or**
a liveness check fires, and the check asks three questions on a one-second timer:
has the token's `exp` passed, has the `(session, credential)` pair been revoked,
is the session still open. Without it the proxy would be a chokepoint that
checks a credential once and then relays for as long as the client likes, which
is worth very little.

On termination the client gets an `ErrorResponse` under `57P01`
(`admin_shutdown`), but only if the server-to-client stream is between messages.
To know that, the relay tracks frame boundaries in that one direction —
arithmetic on the tag-and-length header, never a body — so "no statement is ever
seen" survives intact. Mid-message, the sockets simply close.

### What it does not do

The profile's Cedar policy is not applied. The policy vocabulary is HTTP's —
method, host, path — and a connection has none of those. What bounds a
`postgres-proxy` credential is the upstream role's own privileges, the
credential's `ttl_secs`, and the session it is bound to. `THREAT_MODEL.md` says
so plainly rather than leaving it to be discovered.

The profile's `quota` *is* applied, one token per connection, charged before
the upstream connect so that a refusal never leaves a real connection open
behind it. A throttled client gets an `ErrorResponse` under SQLSTATE `53300`
(`too_many_connections`) rather than the `28000` every other refusal uses,
because the credential is not the problem and a driver that treated it as one
would stop retrying when retrying is exactly right.

### One issuer, two proxies

Both proxies verify tokens with the *same* `ProxyIssuer`: one signing key per
daemon, one revocation set, one place that decides a token is no longer good.
Two issuers would mean a revoke that retired a grant in one and not the other.
A `daemon.toml` that sets `pg_proxy_enabled` without `proxy_enabled` is
therefore refused at startup rather than started half-working.

## The MCP upgrade

Everything on the daemon's socket is one framed request and one framed reply,
answered from a dispatch table. `Request::Mcp` is the exception, and it is the
exception because MCP is not request/response: a server sends notifications
nothing asked for, and a client sends notifications that get no reply.

```
briefcred mcp                           daemon
  |-- frame: {"request":"mcp"} ----------->|
  |<-- frame: {"response":"mcp_ready"} ----|
  |=== newline-delimited JSON-RPC =========|   (until either end closes)
```

After the acknowledgement the daemon stops framing and hands the stream to the
MCP server. `serve_connection` intercepts an upgrade before the dispatch table,
which is why `dispatch_table()` covers `Request::NAMES` *minus*
`Request::UPGRADE_NAMES` and a test asserts exactly that: a handler for `mcp`
could never run, so having one would be a lie about the protocol.

The CLI's half is a byte pump with no understanding of MCP at all. Parsing the
JSON-RPC there would be a second framing implementation that has to agree with
the daemon's, and wrapping each message in a request/response pair would mean
inventing replies for notifications that have none.

The socket is still mode `0600` in a `0700` directory and the peer's uid is
still checked before the upgrade request is read, so the boundary is unchanged.
What changes is capability, which `THREAT_MODEL.md` states.

## Sessions, and where the dangerous state lives

The daemon holds exactly one kind of dangerous state: the master credentials of
open sessions. Everything about the session model exists to bound how long that
state lives.

```
OpenSession(profile, client_headless)
  |
  |-- profile loaded?            no -> Error
  |-- policy != none AND (client_headless OR daemon has no screen)?
  |        yes -> Locked{no_aqua_session}, audit UnlockDenied
  |-- unlock cached for it?      no -> UnlockGate::unlock
  |                                     |-- cancelled / failed -> Locked{...}, audit UnlockDenied
  |                                     `-- ok                 -> cache for unlock.cache_secs
  |-- fetch a master per distinct source_key   (any failure -> Error, nothing retained)
  `-- Session { masters: Zeroizing<String> }   -> SessionOpened{session_id, expires_at}

wiped by: CloseSession | idle sweep every 30 s | daemon shutdown
```

The idle sweep and the unlock cache both read a `Clock` rather than
`Instant::now`, so their boundaries are tested against a stopped clock instead
of a sleep. The clock is monotonic: a session must not become immortal, or
instantly stale, because the laptop resynchronised NTP.

## The root CA

`briefcred install` generates a per-machine root CA: ECDSA P-256, common name
`briefcred local CA <hostname>`, ten years, `pathlen:0`. The constraint is the
point — the CA signs leaves and can never issue an intermediate that signs on
its behalf, so a stolen key cannot delegate onward.

The certificate goes to `ca/ca.pem`. The private key goes to a `KeyStore`:

| Platform | Backend | Where |
| --- | --- | --- |
| macOS | `KeychainKeyStore` | login keychain, generic password, service `dev.briefcred.ca` |
| Linux and fallback | `FileKeyStore` | `ca/ca.key`, mode `0600` |

The choice is made in exactly one place, `ca::CaConfig::open_keystore`, which
reads the `[ca] keystore` key out of `daemon.toml` and otherwise takes the
platform default. Everything downstream takes a `&dyn KeyStore` and does not
know which backend it got, which is what lets the tests run the real code
against a temporary directory instead of the developer's keychain.

Leaves are issued on demand for a hostname list, live 24 hours, carry
`serverAuth` and `CA:FALSE`, and are backdated five minutes against clock
skew. They are cached in memory keyed on the whole hostname list, so a leaf
issued for one host is never handed out for another.

Trust has two halves, because one is not enough. The system trust store covers
anything that reads it: `security add-trusted-cert` on macOS,
`/usr/local/share/ca-certificates` plus `update-ca-certificates` on Linux. The
six trust environment variables cover the runtimes that do not. A client that
pins past both fails loudly and is out of scope; see `docs/ca-pinning.md`.
