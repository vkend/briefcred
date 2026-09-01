# briefcred

A local, biometric-gated credential broker for AI agents and developer tooling.
It hands subprocesses short-lived, narrowly scoped credentials, swaps
placeholder keys for real ones at a local proxy, and records every mint,
request, and revoke in an append-only audit log.

This is a greenfield build in progress. See `ROADMAP.md` for the plan,
`ARCHITECTURE.md` for the shape, and `THREAT_MODEL.md` for what each phase does
and does not guarantee.

**Status: Phase 0.** The workspace, the profile schema, the minter contracts,
and a working PostgreSQL dynamic-role minter exist as a library. There is no
daemon and no CLI yet; both binaries are stubs that say so.

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
env:
  PGUSER: ${minted.db.PGUSER}
  PGPASSWORD: ${minted.db.PGPASSWORD}
  PGHOST: ${minted.db.PGHOST}
```

Unknown keys are errors at every level, so a typo cannot silently switch a
control off. `${minted.<credential>.<field>}` must name a credential the
profile declares; `${config.<key>}` is resolved at exec time. Every regex in
`exec.allow_args` is compiled at load.

The master credential is never written in a profile. `user` names the master
role; its password comes from a `MasterSource`, which is the Keychain from
Phase 3.

## Filesystem layout

macOS:

```
~/Library/Application Support/briefcred/
  sock  profiles/  audit/  ca/  daemon.toml
```

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
