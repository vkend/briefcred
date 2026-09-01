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
briefcred-e2e       test-only: ephemeral Postgres harness and e2e tests
```

Two more crates appear when minting moves into helper processes:
`briefcred-helper-postgres` and `briefcred-helper-sts`. Helpers are short-lived
processes spoken to over stdio JSON-RPC, so a minter crash cannot take the
daemon with it and a minter never inherits the daemon's memory.

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
| `minters` | Concrete minters. Phase 0 ships `postgres`. |
| `keystore` | The `KeyStore` trait, the macOS keychain backend, and the file backend. |
| `ca` | The root CA, leaf issuance, and the runtime trust environment. |

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
