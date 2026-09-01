# Changelog

All notable changes to briefcred are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Cargo workspace with `briefcred-core`, `briefcred-proto`, `briefcred-daemon`,
  `briefcred-cli`, `briefcred-hook`, and the test-only `briefcred-e2e`. The
  daemon, CLI, and hook binaries are stubs that report the phase that
  implements them.
- `briefcred_core::paths`: the single definition of the on-disk layout for
  macOS and Linux, with `BRIEFCRED_HOME` overriding the whole layout including
  the socket.
- `briefcred_core::profile`: the `Profile` schema and its YAML loader.
  Unknown keys are errors at every level, `exec.allow_args` regexes are
  compiled at load, and `${minted.<credential>.<field>}` templates must name a
  declared credential. `Profile::from_yaml_str` and `Profile::load_dir`.
- `briefcred_core::types`: `MintId` (`briefcred_t_<12 hex>` from the OS CSPRNG,
  documented against PostgreSQL's 63-byte `NAMEDATALEN` ceiling), `MintCtx`,
  `RevokeCtx`, `MintedCredential`, and `RevokeOutcome`. Secrets are held in
  `Zeroizing<String>`, and every `Debug` impl is hand-written to redact them.
- `briefcred_core::traits`: the `MasterSource` and `Minter` contracts.
- `briefcred_core::audit`: `AuditEntry` with `Mint`, `ExecStart`, `ExecEnd`,
  and `Revoke` variants, and SHA-256 argument hashing. Rows are metadata only,
  and a `failed` revoke row always carries a detail.
- `briefcred_core::minters::PostgresDynamicMinter`: transactional minting of
  short-lived PostgreSQL login roles with a `VALID UNTIL` and a grant template,
  returning `PGUSER`, `PGPASSWORD`, `PGHOST`, `PGPORT`, `PGDATABASE`, and
  `DATABASE_URL`. Revoke runs a symmetric `REVOKE` loop, then a best-effort
  `DROP OWNED BY`, then `DROP ROLE`, and reports SQLSTATE and message on
  failure. TLS via rustls with `sslmode` defaulting to `require`.
- `briefcred-e2e::pg_harness`: an ephemeral PostgreSQL cluster per test on a
  free loopback port, with a superuser `master` and a non-owning `CREATEROLE`
  role `master_limited` that mirrors managed-PostgreSQL defaults. Tests skip
  with a printed reason when no server installation is found.
- End-to-end tests covering mint, connect, and revoke; five cycles under a
  non-owning master where each minted role creates a table; and a forced
  revoke failure that must report a non-empty detail.
- `ARCHITECTURE.md`, `THREAT_MODEL.md`, `README.md`, and a `Justfile` with
  `check`, `test`, `fmt`, and `e2e`.
