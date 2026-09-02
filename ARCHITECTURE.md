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
`PGPASSWORD`. Phase 10 moves the same credential to Model A by having the proxy
complete the PostgreSQL authentication handshake itself. That is why Phase 10
is sequenced immediately after the thin proxy rather than at the end.

## Crate map

```
briefcred-core      types, profile schema, minter contracts, audit rows, minters
briefcred-proto     wire types for daemon IPC                        (Phase 1)
briefcred-daemon    the per-user daemon                              (Phase 1)
briefcred-cli       the `briefcred` binary                           (Phase 1)
briefcred-hook      the `briefcred-hook` agent shim                  (Phase 6)
briefcred-helper-postgres  the PostgreSQL minting helper              (Phase 3)
briefcred-e2e       test-only: Postgres and daemon harnesses, e2e tests
```

`briefcred-helper-sts` joins them with the STS minter. A helper's **binary** is
named for the minter kind it serves rather than for its crate —
`kind: postgres-dynamic` means `briefcred-helper-postgres-dynamic` — because
the kind string is all the daemon holds when it goes looking, and a lookup table
in between would be a third place for the name to drift. One crate can grow a
second kind and a second binary.

`briefcred-core` depends on nothing else in the workspace. Everything else
depends on it. That is deliberate: the profile schema and the minter contract
are the two things every other crate has to agree on.

## Module map inside `briefcred-core`

| Module | Responsibility |
| --- | --- |
| `paths` | The only place that knows where files live. `BRIEFCRED_HOME` overrides everything. |
| `profile` | The profile schema, its YAML loader, and the `${...}` env template grammar. |
| `types` | `MintId`, `MintCtx`, `RevokeCtx`, `MintedCredential`, `RevokeOutcome`. |
| `traits` | `MasterSource` and `Minter`. |
| `audit` | `AuditEntry` and argument hashing. |
| `minters` | Concrete minters, each registering itself with the registry. |
| `registry` | `MinterFactory` and the `inventory`-collected `Registry` that resolves a profile's `kind`. |
| `source` | The `MasterSource` backends: keychain, file, and environment. |
| `session_env` | Whether the calling process has a screen. Read by the daemon *and* the CLI. |
| `keystore` | The `KeyStore` trait, the macOS keychain backend, and the file backend. |
| `ca` | The root CA, leaf issuance, and the runtime trust environment. |
| `exec` | The two pure decisions behind `briefcred exec`: is the command allowed, and what environment does it get. |

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
  profiles/       *.yaml work envelopes
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
    MinterFactory { kind: KIND, build: |config| { /* validate, construct */ } }
}
```

`Registry::discover()` collects whatever the binary was linked with, and
`Profile::validate(&Registry)` resolves every credential's `kind` and calls its
`build` with that credential's `config`. Both failures therefore happen when
the profile is loaded, while the user is still looking at the file, rather than
at the first mint. An unknown kind names every kind that *is* registered, which
is the only thing that makes the message actionable. See `CONTRIBUTING.md`.

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
