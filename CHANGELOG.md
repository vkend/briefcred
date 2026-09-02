# Changelog

All notable changes to briefcred are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- **The `aws-sts` minter** (`briefcred-helper-sts`, binary
  `briefcred-helper-aws-sts`): one `sts:AssumeRole` session per mint, with
  `RoleSessionName` set to the mint id so every CloudTrail event resolves to a
  briefcred audit row. Returns `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
  `AWS_SESSION_TOKEN`, and `AWS_REGION`. `source: static` reads the master as
  `AKIA...:secret` and builds the client from that alone — no shared config
  file, no environment, no instance metadata; `source: ambient` asks for the
  SDK's default provider chain and has to be named explicitly. A session policy
  over 2,048 plaintext characters is refused when the profile is loaded, before
  anything is signed or sent. Revoke attaches one rolling inline policy per
  role, `briefcred-revoke-older-sessions`, denying everything to sessions
  issued before that instant, and reports `eventually_consistent` with a
  five-second estimate. **This denies every session of the role, not only
  briefcred's**; give briefcred a role nothing else uses. Tested against replayed
  HTTP with the real signer, serialiser, and parser; a live test runs only under
  `BRIEFCRED_AWS_LIVE=1`.
- **The `ssh-cert` minter**: generates an ed25519 key pair, signs a user
  certificate with the profile's CA, and writes both to a `0700` directory
  under `$TMPDIR` with the key at `0600`. Returns `SSH_IDENTITY_FILE`,
  `SSH_CERT_FILE`, and a ready-made `GIT_SSH_COMMAND`. Principals are required,
  extensions default to `permit-pty`, and critical options such as
  `source-address` are supported. Revoke deletes the key directory and appends
  the serial to an OpenSSH key revocation list at `<home>/state/ssh-krl`, whose
  format is checked against the real `ssh-keygen` in the test suite. The
  reconciler sweeps key directories left by a killed daemon once their
  certificate has expired. See `docs/ssh-krl.md` for what a revoke does and does
  not achieve.
- **Model Context Protocol tools**: `briefcred mcp` bridges an MCP client's
  stdio to a server hosted inside the daemon, over a new `Request::Mcp` upgrade
  that hands the socket over after one acknowledgement. Three tools —
  `briefcred_list_profiles`, `briefcred_db_query { profile, sql, max_rows }`,
  and `briefcred_exec { profile, argv }` — and **none of them returns a
  credential**: the mint is created, used, and revoked inside the daemon. One
  connection binds to one profile and mints once; closing it revokes. `exec`
  enforces the profile's allowlists before minting and caps each output stream
  at 1 MiB; `db_query` streams and stops at `max_rows` (100 by default) and runs
  under a `statement_timeout` of `mcp_query_timeout_secs` (30 by default).
  Every call writes an `mcp_call` audit row carrying an `mcp_call_id`, never
  the SQL or the command line.
- **`examples/profiles/kubectl-bastion.yaml`**: a worked profile reaching a
  private Kubernetes cluster through an SSH bastion on a ten-minute
  certificate, checked by a test that loads and validates every example.
- **`briefcred_core::MinterAdapter`**: one implementation of "run a `Minter`
  behind the helper protocol", shared by every helper binary and by the daemon.

- **`briefcred exec`**: run a subprocess with freshly minted, short-lived
  credentials. Opens a session, enforces `exec.allow_argv0` and
  `exec.allow_args` *before* minting, mints through a helper process, spawns the
  child with `env_clear()`, and returns the child's exit code. A policy refusal
  exits 4 naming the offending value; a refused unlock exits 5.
- **`briefcred get --profile --cred --field`**: print one field of one minted
  credential. Refuses a terminal unless `--force`, and writes no trailing
  newline.
- **`briefcred profiles`, `briefcred health`, `briefcred audit`**: a profile
  table, a checklist that names the command fixing each failure, and an audit
  reader that works with the daemon stopped.
- **`briefcred profile bootstrap`**: an interactive interview (`dialoguer`) that
  writes a validated profile and stores its master credential directly in the
  platform key store. The master never crosses the daemon's socket; presence is
  proved first with the new `Unlock` request.
- **Helper processes**: `briefcred-proto::helper`, a JSON-RPC 2.0 protocol over
  newline-delimited stdio with `mint`, `revoke`, `reconcile`, and `shutdown`,
  and the `briefcred-helper-postgres` crate whose binary is named for the minter
  kind it serves (`briefcred-helper-postgres-dynamic`). The daemon looks next to
  its own executable, then in `BRIEFCRED_HELPER_DIR`, and keeps one process per
  `(profile, kind)` for the life of the session.
- **`Minter::reconcile`** and `PostgresDynamicMinter`'s implementation of it:
  drop every `briefcred_t_%` role whose `VALID UNTIL` has passed. The expiry
  check is what keeps a sweep from racing a live exec.
- **Persistent revoke queue** at `state/revoke-queue.jsonl`, mode `0600`,
  written and fsynced before a revoke is acknowledged and replayed at startup.
  Exponential backoff of 1 s, 2 s, 4 s to a 60 s ceiling, eight attempts, then
  a final `failed` audit row. Every attempt writes a `revoke` row.
- **Reconciler**: sweeps each profile's backend at startup and every
  `reconcile_interval_secs` (300 by default), writing a `revoke` row per stray
  and a `reconcile` summary row per sweep.
- **`briefcred-hook`**: reads a Claude Code `PreToolUse` payload on stdin,
  matches `hook-rules.yaml`, asks the daemon `HookCheck` (which validates
  argv0 and args without minting), and answers `allow`, `deny`, or `ask` with an
  optional `updatedInput` rewrite. Documented in `docs/hook.md`.
- **`env_passthrough`** on a profile, on top of the always-passed `PATH`,
  `HOME`, `TERM`, `LANG`, and `TMPDIR`.
- **`[audit] raw_args`** in `daemon.toml`: record command arguments verbatim
  alongside their digests. Off by default.
- **`reconcile_interval_secs`** in `daemon.toml`.
- **`just mem-hygiene`**: builds a daemon with the `debug-heapscan` feature and
  asserts a master is gone from its address space once its session is closed.
  The request carries a SHA-256 digest, never the marker.
- `briefcred_mint_duration_seconds{kind}` and
  `briefcred_revoke_duration_seconds{kind}` histograms, and
  `briefcred_revoke_failures_total{kind}`, wired from the exec mint path and the
  revoke queue.
- **`briefcred-e2e::daemon_harness`**: runs the real daemon binary under a
  temporary `BRIEFCRED_HOME`, with end-to-end tests for a role stranded by
  `SIGKILL`, a normal exec revoking through the queue, and a session close
  sweeping up what it minted.

### Changed

- **`MinterFactory` splits `build` into `validate` and `construct`.** Every
  binary that reads profiles must be able to reject a bad one, but only the
  binary that mints needs the minter, so a minter whose implementation drags in
  a vendor SDK registers its schema in `briefcred-core` with `construct: None`
  and lives in its own crate. `aws-sts` is the first. `Registry::build` on such
  a kind names the binary that mints it.
- **`MinterFactory` gains `hosting`.** `Hosting::Helper` is the default and
  means the daemon spawns `briefcred-helper-<kind>`; `Hosting::Daemon` means the
  daemon runs the minter itself, and is correct only for a minter that talks to
  no backend. `ssh-cert` is the only one, and the cost — the CA private key
  resident in the daemon — is recorded in `THREAT_MODEL.md`.
- The daemon's `HelperSet` is now `MinterSet` and holds `MintChannel`s, which a
  helper process and an in-daemon minter both implement, so `exec` and
  `reconcile` never branch on where a kind runs.
- `briefcred-core` now depends on `briefcred-proto`, for `MinterAdapter` alone.
- `briefcred get` no longer revokes the credential it just printed. `ExecDone`
  gained `hold_until_expiry`; `get` sets it, and the daemon schedules the first
  revoke attempt for the mint's own expiry, so the value is usable for its
  `ttl_secs` and is still cleaned up promptly afterwards rather than left to the
  reconciler.
- The reconciler's and the revoke queue's helper processes are stopped at the
  end of every pass. Both sets are idle almost all of the time, and a helper
  kept between passes is a master credential resident in a process with nothing
  to do.
- Replies on the helper pipe are capped at `MAX_FRAME_BYTES`, the same 16 MiB
  ceiling the client socket enforces, so a helper that never emits a newline
  cannot make the daemon allocate without bound.
- `briefcred profile bootstrap` writes the profile first, waits for the daemon
  to load it, and only then runs the unlock gate and asks for the master. The
  gate previously treated "no such profile" as success, which made it a no-op on
  the first bootstrap of any profile. Any failure after the write removes the
  file again.
- The audit log moved from a `std::sync::Mutex<AuditLog>` held across `fsync` to
  a dedicated writer task on a blocking thread, fed by a channel. Appends no
  longer block a request handler on the disk; `fsync`-per-row and the write-error
  counter are unchanged, and `AuditHandle::flush` is available where a row has to
  be durable before the next step.
- `AuditEntry::ExecStart` and `ExecEnd` carry `session_id` and `mint_ids: Vec<_>`
  rather than a single `mint_id`, because one `briefcred exec` may carry several
  credentials. `AuditEntry::mint_id()` became `mint_ids()`.
- `SessionStore::close`, `evict_idle`, and `close_all` return the sessions
  themselves, so the caller can stop their helper processes and queue any mints
  no `ExecDone` accounted for.
- `PostgresDynamicMinter` keeps its master connection open across calls and
  reopens it when it closes or its configuration changes.
- `State::new` takes a `StateParts` struct rather than nine positional
  arguments.
- `cli::run` returns an exit code, so `briefcred exec` can exit with its
  child's.
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
- `briefcred_core::keystore`: the `KeyStore` trait with two backends.
  `KeychainKeyStore` stores a generic password in the macOS login keychain
  under service `dev.briefcred.ca`; `FileKeyStore` writes a `0600` file,
  created with that mode rather than chmodded afterwards, and `fsync`ed. The
  backend is chosen in exactly one place, `ca::CaConfig::open_keystore`.
  Asking for the keychain off macOS is an error, never a silent fallback to a
  file.
- `briefcred_core::ca`: the per-machine root CA. `CertificateAuthority::generate`
  produces an ECDSA P-256 root with common name `briefcred local CA <hostname>`,
  ten years of validity, and a critical `basicConstraints` of `CA:TRUE,
  pathlen:0`. `save` writes the public half to `ca/ca.pem` at `0644` and hands
  the private key to the key store; `load` treats a certificate without its key
  as an error rather than regenerating over it. `ensure` is idempotent, so a
  reinstall keeps the CA the machine already trusts.
- `CertificateAuthority::issue_leaf`: 24-hour `serverAuth` leaves for a
  hostname list, backdated five minutes against clock skew, cached in memory
  keyed on the whole list. Neither the CA nor a leaf ever prints its private
  key: both have hand-written `Debug` impls that redact it.
- `briefcred_core::ca::trust_env`: `AWS_CA_BUNDLE`, `CURL_CA_BUNDLE`,
  `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, and
  `SSL_CERT_FILE` pointing at `ca.pem`, narrowed by a profile's optional
  `trust_env` list. An empty list opts the profile out entirely; a name
  briefcred does not set is rejected when the profile is loaded.
- `briefcred install --trust-ca`: generates the CA during provisioning and
  adds it to the system trust store. macOS runs `security add-trusted-cert -d
  -r trustRoot -k /Library/Keychains/System.keychain`; Linux installs the
  certificate into `/usr/local/share/ca-certificates` and runs
  `update-ca-certificates`. Like the service-manager commands, the privileged
  step is built as a plan and executed separately, so `--dry-run` prints it and
  the tests never run `sudo`. A failed trust step is reported without failing
  the install.
- `briefcred ca show | regenerate [--trust-ca] | untrust`. `show` prints the
  subject, SHA-256 fingerprint, validity, key location, and trust state.
  `regenerate` untrusts the old certificate before replacing it, because the
  macOS trust store matches on content and afterwards there would be nothing
  left to match.
- `daemon.toml` gains `[ca] keystore = "file" | "keychain"`, defaulting to the
  keychain on macOS and a file elsewhere.
- `uninstall` now also retains `ca/`, so a reinstall stays trusted.
- `docs/ca-pinning.md`: what a pinning failure looks like in each ecosystem,
  the known offenders, how to tell pinning apart from a CA that is merely
  untrusted, and why disabling verification is worse than the problem.
- End-to-end proof that the CA works outside briefcred's own assumptions: a
  `tokio-rustls` server on loopback holding an issued leaf, and the system
  `curl --cacert ca.pem` accepting it. Skips with a printed reason where there
  is no `curl`.
- `briefcred_core::source`: the `MasterSource` backends. `KeychainSource`
  reads generic passwords under the service `dev.briefcred.master` with the
  key as the account; `FileSource` reads `0600` files under
  `paths::secrets_dir()` and refuses a file that is readable by group or
  other; `EnvSource` reads `BRIEFCRED_MASTER_<KEY>` for development and warns
  once per process that every child inherits it. Every key is validated
  against the same character set, so a key that works against the keychain
  cannot become a path traversal against a file. A master that is simply
  absent is `Error::MasterNotFound`, which names the key and where the backend
  looked, rather than a generic failure.
- `briefcred_core::registry`: the minter registry. A minter registers itself
  with `inventory::submit!` next to its own implementation, and
  `Registry::discover` collects whatever the binary was linked with.
  `Profile::validate(&Registry)` resolves every credential's `kind` and builds
  its minter, so a typo or a malformed `config` block fails when the profile is
  loaded rather than at the first mint. An unknown kind reads
  `unknown minter kind "X" (registered: a, b, c)`.
- `CredentialSpec::source_key`: the master-source key a credential's master is
  filed under, defaulting to the credential's own name. Naming it explicitly
  lets several credentials share one master.
- `Unlock::cache_secs`: how long a successful unlock is honoured for a profile,
  defaulting to 300 seconds. Zero means every session prompts.
- `briefcred_daemon::unlock`: the presence gate. `UnlockGate::unlock` runs
  `LAContext` with `LAPolicyDeviceOwnerAuthentication` on macOS — Touch ID
  falling back to the login password — on a dedicated OS thread with its own
  run loop, returning through a oneshot so the prompt never blocks the reactor.
  `UnlockPolicy::None` skips the gate entirely. A session with no graphical
  subsystem to draw in fails closed with `NoAquaSession` rather than falling
  back to something weaker; the check is `SessionGetInfo`'s
  `sessionHasGraphicAccess`, plus `SSH_CONNECTION` and `SSH_TTY`. Every other
  platform reports `Unsupported` for anything but `none`. `UnlockCache` is
  keyed per profile, so unlocking a low-value profile never opens a
  high-value one.
- `briefcred_daemon::profiles`: the loaded profile set and its watcher.
  `notify` with a 250 ms debounce turns an editor's save burst into one
  reload, and a reload that fails leaves the previous set in force, logs, and
  writes a `ProfileLoadError` audit row — a typo in one file must not cost the
  user every profile. Reloading clears the unlock cache, because the file that
  was unlocked for is not necessarily the file on disk now.
- `briefcred_daemon::session`: open sessions. `OpenSession` runs the unlock
  gate, then fetches the master for each credential's `source_key`, and answers
  with an unguessable 128-bit session handle and an expiry. Masters live in
  `Zeroizing<String>`, so `CloseSession`, idle eviction, and shutdown all wipe
  them by dropping the session. An idle sweep runs every 30 seconds against
  `session_idle_secs`, which defaults to 1800.
- `briefcred_daemon::clock`: the `Clock` the session and unlock deadlines read,
  so their expiry rules are tested against a stopped clock rather than a sleep.
- `briefcred-proto`: `ListProfiles`, `ShowProfile`, `OpenSession`, and
  `CloseSession` requests, answered with `Profiles`, `Profile`,
  `SessionOpened`, `SessionClosed`, and `Locked`. Profiles cross the socket as
  a `ProfileSummary` of their own rather than as the daemon's `Profile`, so a
  future profile field cannot leak across the socket by default.
- `daemon.toml` gains `session_idle_secs` and `master_source`.
- `paths::secrets_dir()`: the `0700` directory `FileSource` reads, created by
  `ensure_layout`.
- `CONTRIBUTING.md`, with the "Adding a minter" section describing the registry
  contract.
- The daemon's dispatch table now maps a request name to an async handler
  taking the deserialised `Request` and `Arc<State>`, rather than a synchronous
  `fn(&State) -> Response`. Requests carry payloads now, and opening a session
  prompts the user and reads a keychain. The table is still asserted to cover
  `Request::NAMES` exactly.
- `Profile::load_dir` takes a `&Registry` and validates every profile against
  it.
- `briefcred_core::session_env`: the "does this process have a screen?" check,
  shared because two processes have to answer it and they get different
  answers. The daemon sits in launchd's session and cannot tell an SSH client
  from a local one; the client can. So `Request::OpenSession` carries
  `client_headless`, the client fills it in from its own check, and the daemon
  refuses when either side reports headless. The field has no serde default: a
  client that has not considered the question fails to serialise rather than
  quietly declaring it has a screen.
- The headless refusal now runs before the unlock cache is consulted, so a warm
  cache from a desktop login cannot carry an SSH shell through it. `README.md`
  and `THREAT_MODEL.md` now state what the check is and is not: it is
  best-effort and advisory, worth real money against an honest client on SSH
  and nothing at all against a hostile same-uid caller.
- `briefcred-core` uses `deny(unsafe_code)` rather than `forbid`, for the one
  `extern "C"` call into the Security framework in `session_env`. Every other
  module is unsafe-free, and `deny` still fails the build on any `unsafe` not
  explicitly allowed and justified at the site.
- `source::MemorySource` is compiled only under `cfg(test)` or the new
  `test-util` feature, holds its masters in `Zeroizing<String>`, and redacts
  its own `Debug`. It is test scaffolding and can no longer reach a production
  binary.
