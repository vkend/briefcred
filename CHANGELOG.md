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
- `briefcred_proto`: the daemon IPC wire protocol. `Request` (`Ping`, `Status`,
  `Shutdown`) and `Response` (`Pong`, `Status`, `ShuttingDown`, `Error`) as
  tagged JSON, behind a 4-byte big-endian length prefix with a 16 MiB frame
  ceiling enforced on both sides. `Request::name` gives the daemon its
  dispatch-table key, so the table and the wire format cannot drift apart.
- `briefcred-daemon`: the per-user daemon. A Unix listener at `paths::sock()`
  with the socket at `0600` inside a `0700` directory, a peer-UID check that
  closes mismatched connections and writes an `auth_reject` audit row, and
  stale-socket cleanup that refuses to displace a daemon still answering.
  Requests reach handlers through a `HashMap` dispatch table rather than one
  large `match`. `SIGTERM`, `SIGINT`, and `Request::Shutdown` all stop
  accepting, drain in-flight connections for five seconds, and remove the
  socket file.
- The JSONL audit writer: `audit/audit-YYYY-MM-DD.jsonl`, `O_APPEND` with an
  `fsync` per row, daily rotation by filename, and a retention sweep at startup
  and hourly that deletes by the date in the filename. It never removes the
  file it is writing to and ignores filenames it did not write.
- A Prometheus text endpoint on `127.0.0.1`, serving `briefcred_uptime_seconds`,
  `briefcred_ipc_requests_total{request}`, and
  `briefcred_audit_write_errors_total`, with every request series seeded at zero.
- `daemon.toml`: `retention_days` (90), `metrics_port` (9317; `0` asks the OS
  for a free port), and `metrics_enabled` (true). An absent or empty file is
  valid; an unknown key is an error.
- `briefcred-cli`: the `briefcred` binary. `install [--dry-run]` and
  `uninstall`, both idempotent, and `daemon status | start | stop | restart`.
  Lifecycle goes through `launchctl bootstrap gui/$UID` or
  `systemctl --user`; the CLI never spawns the daemon itself. `daemon status`
  exits 3 with `daemon is not running; run 'briefcred daemon start'` when the
  socket is absent. `uninstall` removes the unit and boots the agent out, and
  deliberately retains the audit log, profiles, and configuration.
- LaunchAgent plist and systemd user unit generation as pure, snapshot-tested
  functions. The plist sets `RunAtLoad`, `KeepAlive`, and
  `ProcessType Interactive`, pins `BRIEFCRED_HOME`, and redirects stdout and
  stderr into `paths::log_dir()`. XML metacharacters in paths are escaped.
- `briefcred_core::paths`: `log_dir()`, `state_dir()`, `config_dir()`,
  `service_dir()`, `service_file()`, `service_label()`, `platform()`, and
  `ensure_layout()`. `BRIEFCRED_HOME` relocates the service unit too, so a test
  can never write into the real `~/Library/LaunchAgents`.
- `install`, `daemon start`, `daemon stop`, and `daemon restart` wait for the
  daemon to reach the requested state before returning. `launchctl` and
  `systemctl` report success once they have accepted the job, which is before
  the socket exists, so without the wait a `daemon status` typed immediately
  afterwards would race the daemon and report it down.
- `briefcred_core::audit`: `DaemonStart`, `DaemonStop`, and `AuthReject`
  variants. `AuditEntry::mint_id` now returns `Option<&MintId>`, because these
  rows describe the daemon rather than a minted principal.
