# briefcred roadmap implementation plan

Spec: `ROADMAP.md` (repo root). This plan turns each roadmap phase into
one or two implementation tasks, in the roadmap's execution order.

## Global Constraints

- Language: Rust 2021, stable toolchain (1.95). Cargo workspace at repo
  root. `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  and `cargo test --workspace` must pass at the end of every task.
- Commits: one-line subject, no body, no trailers, no co-author lines.
- Never reference, link to, or copy from any other repository or prior
  codebase. This is greenfield.
- Secrets in memory: every master credential and minted secret lives in
  `zeroize::Zeroizing<String>` (or a newtype wrapping it). Never log,
  `Debug`-print, or serialise a secret. Implement `Debug` manually to
  redact.
- Platform: macOS 26 first. Linux code paths compile under `cfg(target_os
  = "linux")` and are unit-tested where possible but need not be
  integration-tested here.
- Postgres integration tests: no Docker on this machine. Use an ephemeral
  cluster started with `initdb` + `pg_ctl` (binaries discovered from
  `BRIEFCRED_PG_BIN`, then `/opt/homebrew/opt/postgresql@14/bin`, then
  `PATH`) on a free localhost port under a temp dir, torn down after the
  test. Tests auto-skip with a printed reason if no server binary is
  found. Local server available: PostgreSQL 14.23.
- Filesystem layout (macOS): `~/Library/Application Support/briefcred/`
  with `sock`, `profiles/`, `audit/`, `ca/`, `daemon.toml`. Linux:
  `$XDG_DATA_HOME/briefcred` (default `~/.local/share/briefcred`) and
  `$XDG_RUNTIME_DIR/briefcred/sock`. Centralise this in
  `briefcred_core::paths`.
- Tests never touch the real user directories: every test sets
  `BRIEFCRED_HOME=<tempdir>` which overrides the whole layout.
- Networking in tests: localhost only.
- Audit rows are metadata only: never headers, bodies, query strings,
  or secrets. Args hashed (SHA-256) by default.
- Crate names: `briefcred-core`, `briefcred-proto`, `briefcred-daemon`,
  `briefcred-cli` (binary `briefcred`), `briefcred-hook` (binary
  `briefcred-hook`), `briefcred-e2e` (tests only), plus
  `briefcred-helper-postgres`, `briefcred-helper-sts` when introduced.
- Every task updates `README.md` (usage) and `CHANGELOG.md`
  (`## Unreleased` section) for what it adds.

## Task 1 — Phase 0: workspace, core types, Postgres minter

Implements ROADMAP Phase 0 in full.

- Workspace `Cargo.toml` with members `briefcred-core`, `briefcred-proto`,
  `briefcred-daemon`, `briefcred-cli`, `briefcred-hook`, `briefcred-e2e`.
  Stub crates may be near-empty but must build. Shared `[workspace.
  dependencies]` and `[workspace.package]` (version `0.1.0`, license
  `MIT OR Apache-2.0`, edition 2021).
- `briefcred-core`:
  - `paths` module (see Global Constraints).
  - `Profile` schema (serde + `serde_yaml`): `name`, `description`,
    `unlock: { policy: biometric | passcode | none }` (default
    `biometric`), `credentials: Vec<CredentialSpec>` where
    `CredentialSpec { name, kind, ttl_secs (default 900), config:
    serde_yaml::Value }`, `exec: { allow_argv0: Vec<String>,
    allow_args: Vec<String /* regex */> }`, `env: BTreeMap<String,
    String>` with `${minted.<cred>.<field>}` and `${config.<key>}`
    templates. Loader `Profile::from_yaml_str`, `Profile::load_dir(dir)`.
    Unknown top-level keys are errors. ≥6 unit tests.
  - Traits: `MasterSource { async fn fetch(&self, key: &str) ->
    Result<Zeroizing<String>> }`, `Minter { fn kind(&self) -> &'static
    str; async fn mint(&self, ctx: MintCtx) -> Result<MintedCredential>;
    async fn revoke(&self, ctx: RevokeCtx) -> RevokeOutcome }`. Types
    `MintCtx { mint_id: MintId, profile: String, credential: String,
    config: Value, master: Zeroizing<String>, ttl: Duration }`,
    `RevokeCtx { mint_id, config, master, revoke_token: String }`,
    `MintedCredential { mint_id, fields: BTreeMap<String,
    Zeroizing<String>>, expires_at, revoke_token }`,
    `RevokeOutcome { Revoked, EventuallyConsistent { propagation_estimate:
    Duration }, Failed { detail: String }, AlreadyGone }`, `AuditEntry`
    enum with variants `Mint`, `ExecStart`, `ExecEnd`, `Revoke`,
    `ProxyRequest`, `PgConnection` (later variants may be added; define
    the first four now) each carrying `ts: OffsetDateTime`, `mint_id`,
    and metadata-only fields.
  - `MintId`: `briefcred_t_<12 lowercase hex>` from a CSPRNG; `Display`,
    `FromStr`, validated.
  - `PostgresDynamicMinter` (tokio-postgres): config `{ host, port,
    dbname, user (master), sslmode, role_template: { grants:
    Vec<Grant> } }` where `Grant { privileges: Vec<String>, on: String
    /* e.g. "ALL TABLES IN SCHEMA public" | "TABLE orders" */ }`. Mint:
    `CREATE ROLE <id> LOGIN PASSWORD '<random 32 bytes base64>' VALID
    UNTIL '<now+ttl>'` then one `GRANT` per template entry, all inside a
    transaction. Returns fields `PGUSER`, `PGPASSWORD`, `PGHOST`,
    `PGPORT`, `PGDATABASE`, `DATABASE_URL`. Revoke: for each grant emit
    the symmetric `REVOKE ... FROM <id>`, then best-effort `DROP OWNED BY
    <id>` (error swallowed into detail), then `DROP ROLE <id>`. Any SQL
    error → `RevokeOutcome::Failed { detail: <sqlstate + message> }`.
    Role missing → `AlreadyGone`. All identifiers quoted via
    `tokio_postgres` escaping helpers; never string-format user input
    into SQL beyond the validated `MintId`.
  - Document the 63-char `NAMEDATALEN` ceiling in a doc comment on
    `MintId`.
- `briefcred-e2e`:
  - `pg_harness` module: ephemeral cluster per Global Constraints. Creates
    a `master` superuser and a second non-owning role `master_limited`
    that does **not** own schema `public` but has `CREATEROLE` and the
    needed grant privileges (mirrors managed-Postgres defaults).
  - Tests: full mint → connect as minted role → run `SELECT 1` → revoke
    → assert role gone. Second test: run five mint/revoke cycles as
    `master_limited` where the minted role created a table (so `DROP
    OWNED BY` matters) and assert `pg_roles` has no `briefcred_t_%` rows.
    Third test: force a revoke failure (drop the master's CREATEROLE mid
    way) and assert `Failed { detail }` is non-empty.
- Docs: `ARCHITECTURE.md` (hybrid shape, crate map, data flow diagram in
  text, Model A/B/C per phase table) and `THREAT_MODEL.md` (assets,
  trust boundaries, attacker model, Model C exposure for Phase 3 and how
  Phase 10 closes it, audit guarantees). `README.md` with build/test
  instructions. `CHANGELOG.md`. `Justfile` with `check`, `test`,
  `fmt`, `e2e`. `.gitignore` for `target/`.

Done when: `just check && just test` pass locally including the three
e2e tests against the local PG14 cluster.

## Task 2 — Phase 1: daemon foundation

Implements ROADMAP Phase 1.

- `briefcred-proto`: `Request` / `Response` enums (serde JSON), framing
  helpers: 4-byte big-endian length prefix, max frame 16 MiB. Initial
  requests: `Ping`, `Status`, `Shutdown`. `Response::Status { version,
  pid, uptime_secs, started_at, audit_path, metrics_addr }`.
- `briefcred-daemon`:
  - Binary `briefcred-daemon`. Tokio runtime. Unix listener at
    `paths::socket()`, parent dir `0700`, socket `0600`, stale-socket
    cleanup on start if no live peer. Peer-UID check via `SO_PEERCRED`
    (Linux) / `LOCAL_PEERCRED` (macOS); mismatched UID → connection
    closed and an audit `AuthReject` row.
  - Dispatch table: `HashMap<&'static str, Handler>` keyed by request
    variant name, not a giant `match`.
  - Graceful shutdown on `SIGTERM`/`SIGINT` and on `Request::Shutdown`:
    stop accepting, drain in-flight (5 s), remove socket file.
  - JSONL audit writer: `paths::audit_dir()/audit-YYYY-MM-DD.jsonl`,
    one `AuditEntry` per line, `O_APPEND`, fsync every write, daily
    rotation by filename, retention sweep on startup and every hour
    deleting files older than `retention_days` (default 90, from
    `daemon.toml`).
  - Prometheus text endpoint on `127.0.0.1:<port>` (default 9317,
    configurable) via `hyper`: `briefcred_uptime_seconds`,
    `briefcred_ipc_requests_total{request}`,
    `briefcred_audit_write_errors_total`.
  - `daemon.toml` config loader with defaults.
- `briefcred-cli` (binary `briefcred`, `clap`):
  - `daemon status|start|stop|restart`: `start` uses `launchctl
    bootstrap gui/$UID <plist>` on macOS / `systemctl --user start` on
    Linux; never spawns the daemon directly. `status` opens the socket
    and prints `Response::Status`. If the socket is absent, print
    `daemon is not running; run 'briefcred daemon start'` and exit 3.
  - `install [--dry-run]` / `uninstall`: create directory layout with
    correct modes, write the LaunchAgent plist to
    `~/Library/LaunchAgents/dev.briefcred.daemon.plist` (`RunAtLoad`,
    `KeepAlive`, `ProcessType Interactive`, stdout/err to
    `paths::log_dir()`), or the systemd user unit to
    `~/.config/systemd/user/briefcred.service`, then start. Idempotent.
    `--dry-run` prints the files it would write.
- Tests: framing round-trip + oversize rejection; daemon integration test
  under `BRIEFCRED_HOME=tmp` that spawns the daemon binary, pings,
  checks status, scrapes metrics, sends Shutdown, asserts socket removed
  and an audit file exists; plist/unit generation snapshot tests.

Done when: on this Mac, `briefcred install`, `briefcred daemon status`,
`curl 127.0.0.1:9317/metrics` work (implementer runs and records output
in the report; then `briefcred uninstall`).

## Task 3 — Phase 2: CA bootstrapping

Implements ROADMAP Phase 2.

- `briefcred-core::ca`: generate a root CA (`rcgen`, ECDSA P-256, CN
  `briefcred local CA <hostname>`, 10-year validity, `pathlen 0`) at
  install time. Private key stored via `KeyStore` trait: macOS
  implementation writes to the login keychain (`security-framework`,
  generic password item, service `dev.briefcred.ca`); Linux/fallback
  writes `paths::ca_dir()/ca.key` mode `0600`. Public cert at
  `paths::ca_dir()/ca.pem`. Leaf issuance API `issue_leaf(hostnames)`
  with 24-hour validity, cached per hostname in memory.
- `briefcred install` gains `--trust-ca` step: macOS runs `security
  add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain
  ca.pem` via `sudo`; Linux copies to
  `/usr/local/share/ca-certificates/briefcred.crt` and runs
  `update-ca-certificates`. `briefcred ca show|regenerate|untrust`
  subcommands.
- Runtime trust env: `briefcred_core::ca::trust_env(profile) ->
  BTreeMap<String,String>` returning `NODE_EXTRA_CA_CERTS`,
  `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `GIT_SSL_CAINFO`,
  `AWS_CA_BUNDLE`, `CURL_CA_BUNDLE` → `ca.pem`, filtered by the
  profile's `trust_env: Vec<String>` override when present.
- `docs/ca-pinning.md`: known pinning offenders and the error users see.
- Tests: CA generation + leaf issuance verified with `rustls` +
  `webpki` chain validation; trust_env filtering; keystore round-trip
  (file backend; keychain backend behind `#[ignore]` with a note).

Done when: implementer demonstrates in the report that `curl --cacert
ca.pem https://localhost:<port>` against a test `rustls` server using an
issued leaf succeeds.

## Task 4 — Phase 3a: master sources, biometric gate, registry, profile loader

First half of ROADMAP Phase 3.

- `briefcred-core::source`: `KeychainSource` (macOS, `security-framework`
  generic password lookup, service `dev.briefcred.master`, account =
  key; returns `Zeroizing<String>`), `FileSource` (Linux/dev: `paths::
  secrets_dir()/<key>` mode `0600`), `EnvSource` (dev only, warns).
- `briefcred-daemon::unlock`: `UnlockGate` trait with
  `async fn unlock(&self, policy: UnlockPolicy, reason: &str) ->
  Result<(), UnlockError { Cancelled, Failed, NoAquaSession, Unsupported
  }>`. macOS impl via `objc2-local-authentication`: `LAContext` +
  `evaluatePolicy(LAPolicyDeviceOwnerAuthentication)`, run on a
  dedicated thread with a oneshot back to tokio. Headless detection:
  if `SecuritySessionGetInfo` reports no graphical session (or env
  `SSH_CONNECTION` set and no `Aqua` session) return `NoAquaSession`
  immediately. Linux impl returns `Unsupported` unless policy `none`.
  `policy: none` skips the gate. Unlock results cached per profile for
  `unlock.cache_secs` (default 300).
- Minter registry: `inventory::submit!`-registered
  `MinterFactory { kind: &'static str, build: fn(&Value) -> Result<Arc<dyn
  Minter>> }`. `Profile::validate(&Registry)` errors with
  `unknown minter kind "X" (registered: a, b, c)`.
- Profile loader in daemon: load `paths::profiles_dir()/*.yaml` at
  start, `notify` watcher with 250 ms debounce for hot reload; invalid
  file → keep last good, log + audit `ProfileLoadError`.
- Session model: `Session { id, profile, opened_at, last_used, master:
  Zeroizing<String>, mints: Vec<MintId> }` in daemon state; idle
  eviction task (default 30 min, `daemon.toml`) zeroises master and
  drops the session.
- `briefcred-proto`: `ListProfiles`, `ShowProfile`, `OpenSession`,
  `CloseSession` requests.
- `CONTRIBUTING.md` section "Adding a minter" describing the registry
  contract.
- Tests: registry unknown-kind error text; loader hot-reload with a
  temp dir; idle eviction with a mocked clock; unlock gate `none`
  policy path; `NoAquaSession` path forced via env.

## Task 5 — Phase 3b: helpers, exec wrapper, revoke queue, reconciler, CLI, hook

Second half of ROADMAP Phase 3.

- Helper protocol (`briefcred-proto::helper`): JSON-RPC 2.0 over stdio,
  methods `mint`, `revoke`, `reconcile`, `shutdown`. Daemon spawns
  `briefcred-helper-<kind>` from the same directory as the daemon binary
  (or `BRIEFCRED_HELPER_DIR`), one process per (profile, kind) kept
  alive for the session, killed on session close.
- `briefcred-helper-postgres` crate: wraps `PostgresDynamicMinter` with
  a persistent master connection (reconnect on error) and implements
  `reconcile`: list `pg_roles` where `rolname LIKE 'briefcred_t_%'` and
  `rolvaliduntil < now()`, revoke each, return the list.
- Subprocess wrapper (`briefcred-daemon::exec` + CLI `exec`):
  `briefcred exec --profile <name> [--cred a,b] -- <cmd> [args]`.
  Flow: open session → unlock gate → fetch master → mint every
  credential (best-effort; missing ones logged and absent) → compose env
  from templates + `ca::trust_env` → the CLI spawns the child with
  `Command::env_clear()` and the composed env plus a passthrough list
  (`PATH`, `HOME`, `TERM`, `LANG`, `TMPDIR`, profile `env_passthrough`)
  → child exit code is returned immediately → daemon enqueues revokes.
  Enforce `allow_argv0` (exact match on basename or absolute path) and
  `allow_args` (every arg must match at least one regex when the list is
  non-empty); violations exit 4 with the offending arg. Minted values
  travel CLI→daemon over the socket only; never written to disk.
- Async revoke queue: tokio mpsc, retry with exponential backoff
  (1 s, 2 s, 4 s … cap 60 s, max 8 attempts), persisted as JSONL in
  `paths::state_dir()/revoke-queue.jsonl` so a daemon restart resumes
  it. Every attempt writes an audit `Revoke` row with the outcome.
- Reconciler: every `reconcile_interval_secs` (default 300) call each
  live helper's `reconcile`; also runs once at startup. Test: kill the
  daemon (`SIGKILL`) mid-exec, restart, assert the stranded role is
  cleaned within one reconcile tick.
- Audit rows: `Mint`, `ExecStart { argv0, args_sha256, pid }`,
  `ExecEnd { exit_code, duration_ms }`, `Revoke`. `audit.raw_args:
  true` in `daemon.toml` opts into raw args.
- Metrics: `briefcred_mint_duration_seconds` and
  `briefcred_revoke_duration_seconds` histograms with `kind` label,
  `briefcred_revoke_failures_total`.
- CLI: `get --profile <p> --cred <c> --field <f>` (prints one field,
  refuses if stdout is a TTY unless `--force`), `profiles` (table),
  `health`, `audit [--since 24h] [--json]`, `profile bootstrap`
  (interactive: name, kind from registry, kind-specific prompts, writes
  YAML, prompts for master and stores via the platform `MasterSource`
  behind the unlock gate). Use `dialoguer`.
- `briefcred-hook`: reads Claude Code PreToolUse JSON from stdin
  (`tool_name`, `tool_input.command`), loads
  `paths::config_dir()/hook-rules.yaml` (`rules: [{ match: <regex on
  command>, profile, decision: allow|deny|ask, rewrite: bool }]`),
  asks the daemon `HookCheck { command, profile }` (which validates
  argv0/args against the profile without minting), and prints
  `{"hookSpecificOutput": {"hookEventName": "PreToolUse",
  "permissionDecision": ..., "permissionDecisionReason": ...,
  "updatedInput": {"command": "briefcred exec --profile <p> -- <cmd>"}}}`
  when `rewrite` is true. Document the `updatedInput` caveats in
  `docs/hook.md`.
- Memory-hygiene test (`briefcred-e2e/tests/memory_hygiene.rs`, macOS,
  `#[ignore]` unless `BRIEFCRED_MEM_HYGIENE=1`): run a full exec cycle
  with a known 32-byte master marker, then `vmmap`/`lldb`-free
  approach: read the daemon's own heap via `proc_pidinfo`-free
  method is not available without entitlements, so instead the daemon
  exposes a debug-only `Request::HeapScan { needle_sha256 }` (compiled
  only with feature `debug-heapscan`) that scans its own mapped regions
  via `mach_vm_region`/`mach_vm_read` and returns whether the needle is
  present. Assert absent after revoke. `just mem-hygiene` runs it.
- Tests: env composition (templates, `env_clear`, passthrough);
  allowlist enforcement; revoke queue persistence across restart;
  reconciler after SIGKILL (e2e, PG14); hook decision matrix; CLI `get`
  TTY refusal.

Done when: `briefcred exec --profile=db-ro -- psql -c "SELECT 1"` against
the local PG14 works end-to-end on this Mac with Touch ID (implementer
records the run; if no Touch ID hardware is available, records the
`policy: none` run and the `NoAquaSession` message from an `ssh
localhost` shell).

## Task 6 — Additional minters: AWS STS, SSH cert, MCP tools

ROADMAP "Additional minters" section.

- `briefcred-helper-sts` crate: `AwsStsMinter` (`aws-sdk-sts`). Config
  `{ role_arn, region, session_policy: Option<String>, source: static |
  ambient, duration_secs }`. Static: master is `AKIA...:secret` split on
  first `:`. `RoleSessionName = <mint_id>`. Precheck: session policy
  plaintext > 2,048 chars → refuse before calling STS. Fields
  `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`,
  `AWS_REGION`. Revoke: `iam:PutRolePolicy` named
  `briefcred-revoke-older-sessions` on the role with a single Deny where
  `aws:TokenIssueTime < <now RFC3339>`, one rolling policy per role,
  returns `EventuallyConsistent { 5s }`. Unit tests with the SDK's
  `StaticReplayClient`; live test behind `BRIEFCRED_AWS_LIVE=1`.
- `SshCertMinter` in `briefcred-core` (runs in-daemon; no helper): CA
  private key fetched from the master source as OpenSSH PEM. Mint:
  generate ed25519 keypair (`ssh-key` crate), sign a user cert with
  principals, `valid_after=now-60s`, `valid_before=now+ttl`, serial = a
  random u64, key id = mint id, using the `ssh-key` crate (no
  `ssh-keygen` subprocess). Write key + cert to a fresh `0700` dir under
  `$TMPDIR/briefcred-<mint_id>/`, fields `SSH_IDENTITY_FILE`,
  `SSH_CERT_FILE`, `GIT_SSH_COMMAND="ssh -i <key> -o
  CertificateFile=<cert>"`. Revoke: append serial to
  `paths::state_dir()/ssh-krl` (OpenSSH KRL format via `ssh-key`) and
  delete the temp dir; returns `Revoked` with a doc note that servers
  must consume the KRL. `docs/ssh-krl.md`.
- `kubectl` via SSH cert: profile example only (`examples/profiles/
  kubectl-bastion.yaml`) using the SSH minter plus `KUBECONFIG` from
  `${config.kubeconfig}`; no new minter.
- MCP server inside the daemon (`rmcp`, stdio transport exposed by
  `briefcred mcp` CLI subcommand that bridges stdio to the daemon
  socket): tools `briefcred_list_profiles`, `briefcred_db_query {
  profile, sql, max_rows }` (runs via a minted Postgres role inside the
  daemon, returns rows as JSON, credential never leaves the daemon) and
  `briefcred_exec { profile, argv }` (server-side exec through the
  wrapper, returns `{stdout, stderr, exit_code}`). One mint per MCP
  session; audit rows carry `mcp_call_id`.
- Tests: STS replay tests; SSH cert round-trip verified with `ssh-key`
  (cert validates against CA pubkey, principals/serial correct, KRL
  contains serial after revoke); MCP tool listing and `db_query` against
  PG14 through an in-process `rmcp` client.

## Task 7 — Phase 4: HTTP proxy MVP

Implements ROADMAP Phase 4 (thin).

- `briefcred-daemon::proxy`: HTTP/1.1 CONNECT listener on
  `127.0.0.1:<proxy_port>` (default 9318). On CONNECT, terminate TLS
  with a leaf from `ca::issue_leaf(host)`, parse the inner HTTP/1.1
  request with `hyper`, apply policy, forward upstream over `rustls`
  with the system roots (`rustls-native-certs`), stream the response
  back. Plain `http://` absolute-URI requests also supported.
- Synthetic token: `bc.<base64url(payload)>.<base64url(sig)>` where
  payload = `{ sid, cred, iat, exp, cnf: { jkt } }`, signed with a
  per-machine Ed25519 key in the keystore (`dev.briefcred.token-signer`).
  `jkt` = SHA-256 thumbprint of a per-session ephemeral Ed25519 key
  that the CLI generates at session open and sends the public half of.
  For the env-var-only runtime (no DPoP proof header possible) the
  proxy accepts the token bare; when a `DPoP` header is present it is
  verified against `cnf.jkt`. Document both paths.
- Credential kinds `http_bearer`, `http_header { name }`,
  `http_basic`: "mint" produces a synthetic token; the real master is
  held in the session. Placeholder swap: any header value containing
  `__<cred_name>__` gets the real value substituted; `Authorization:
  Bearer bc....` gets the whole token replaced by the real value.
- Cedar (`cedar-policy` 4.x): principal `Session::"<sid>"`, action
  `Action::"GET"` etc., resource `Http::"<host><path>"` with attributes
  `host`, `path`, `scheme`. Profile `policy:` field is Cedar source
  text; schema fixed in `briefcred-core::policy`. Default deny.
  `policy_mode: enforce | observe` per profile; observe = log a
  `ProxyRequest { decision: would_deny }` row and allow.
- Audit `ProxyRequest { ts, mint_id, method, host, path (no query),
  status, req_bytes, resp_bytes, latency_ms, decision }`.
- Metrics: `briefcred_proxy_requests_total{decision,status_class}`,
  `briefcred_proxy_latency_seconds`.
- `exec` sets `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` to the proxy
  address plus the trust env.
- Tests: in-process upstream (`hyper` server with a `rustls` cert from
  a test CA) + policy allow/deny/observe matrix + placeholder swap +
  token verification (tampered sig, expired, wrong session) + DPoP
  proof happy path. `examples/profiles/openai.yaml`.

Done when: implementer shows `OPENAI_API_KEY=<synthetic> curl
https://api.openai.com/v1/models` through `briefcred exec` returning
200 (if the user has no OpenAI key, use the in-process upstream test and
say so).

## Task 8 — Phase 10: Postgres connection-auth proxy

Implements ROADMAP Phase 10.

- `briefcred-daemon::pgproxy`: TCP listener `127.0.0.1:<pg_proxy_port>`
  (default 9319). Parse the startup message (protocol 3.0; reject 2.0
  and refuse `SSLRequest` with `N` unless `pgproxy.tls: true`, in which
  case terminate with a `ca` leaf). `user` = synthetic token or
  `password` = synthetic token from the client. Look up the session,
  open an upstream connection with the real master (SCRAM-SHA-256
  client side via `tokio-postgres`'s auth primitives or a small in-crate
  SCRAM implementation; MD5 behind `pgproxy.allow_md5: true`, off by
  default, logs a deprecation warning), complete auth with the client
  by sending `AuthenticationOk` + the upstream's parameter status
  messages + `BackendKeyData` + `ReadyForQuery`, then byte-forward both
  directions until either side closes.
- Credential kind `postgres_proxy { host, port, dbname, user }`: "mint"
  returns a synthetic DSN `postgresql://<sid>:<token>@127.0.0.1:9319/
  <dbname>` in `DATABASE_URL` plus `PG*` fields.
- Audit `PgConnection { ts, mint_id, master_user, started, ended,
  client_bytes, server_bytes }`.
- Tests against PG14: `psql` with the synthetic DSN runs `SELECT
  current_user`; wrong token rejected with a proper `ErrorResponse`;
  audit row written; SCRAM path exercised (PG14 cluster configured with
  `password_encryption = scram-sha-256`).

## Task 9 — Phase 5: quotas and policy cookbook

Implements ROADMAP Phase 5.

- Token bucket per session: profile `quota: { rate: f64, burst: u32,
  total: Option<u64> }`. Proxy returns `429` with body `{"error":
  "briefcred quota exceeded"}` when empty; `PgConnection` and `exec`
  count as one token each.
- Metric `briefcred_quota_saturation{profile}` (0..1) and
  `briefcred_quota_rejections_total`.
- `docs/policy-cookbook.md`: Cedar examples for method × path, time
  window (`context.hour`), per-session, byte budget (`context.
  resp_bytes_so_far`), and `examples/profiles/{openai,anthropic,github,
  stripe}.yaml` that load and validate in a test.
- Tests: 21st request in one second rejected with `rate: 10, burst:
  20`; refill after 1 s; cookbook examples compile against the schema.

## Task 10 — Phase 8: profile distribution

Implements ROADMAP Phase 8. Ruling: signing scheme is Ed25519 detached
signatures in minisign-compatible format (`<file>.minisig`), keys
generated by `briefcred profile keygen`.

- `daemon.toml`: `[profiles] trust_roots = ["<pubkey>", ...]`,
  `registries = [{ name, url }]` (git `https://` or `file://` for tests,
  and plain HTTPS directory index `index.json`), `dev_mode = false`.
- `briefcred profile sync`: fetch every registry into
  `paths::profiles_dir()/registry/<name>/`, verify each `.yaml` against
  its `.minisig` with any trust root; unsigned or bad signature → skip
  with error unless `dev_mode` (then load with a bold warning on every
  daemon start and in `profiles` output).
- Precedence: local `profiles/*.yaml` overrides registry profiles of
  the same name; `briefcred profile show <name>` prints source path,
  registry, signer key id, signature status, and whether it is an
  override.
- `briefcred profile sign <file> --key <path>`.
- Tests: unsigned rejected; signed accepted; tampered rejected;
  override detection; dev-mode warning presence.

## Task 11 — Phase 6: streaming protocols

Implements ROADMAP Phase 6.

- SSE: detect `text/event-stream` responses and stream body chunks
  without buffering; propagate upstream close; keep-alive comments
  passed through.
- WebSocket: on `Upgrade: websocket`, complete the handshake with
  upstream (`tokio-tungstenite` not required; raw byte forwarding after
  a validated 101), then bidirectional copy with frame counting (parse
  frame headers only).
- Audit: `ProxyStream { kind: sse|ws, started, ended, events_or_frames,
  bytes_up, bytes_down }`.
- Tests: in-process SSE server emitting 100 events with 10 ms gaps,
  assert first event arrives before the last is sent (no buffering);
  in-process WS echo server, 50 frames each way; audit counts match.

## Task 12 — Phase 7: concurrent sessions and zero-downtime upgrade

Implements ROADMAP Phase 7.

- Session isolation audit: every session owns its tokio task + state;
  add a test running 20 concurrent `exec` sessions on the same profile
  with distinct mints.
- `briefcred daemon upgrade`: new daemon started with
  `--takeover <path>`; old daemon, on `Request::Handoff`, sends its
  listening FDs (IPC socket, proxy, pgproxy, metrics) over a Unix socket
  with `SCM_RIGHTS` plus a signed session-state file (Ed25519 with the
  token-signer key; sessions include masters encrypted to the new
  daemon's ephemeral X25519 key). Old daemon stops accepting, drains
  in-flight HTTP requests and streams, then exits. Linux additionally
  supports systemd socket activation (`LISTEN_FDS`).
- Tests: takeover under an active SSE stream (from Task 11's server)
  drops zero bytes; new sessions land on the new PID.

## Task 13 — Phase 9: HTTP/2 and gRPC

Implements ROADMAP Phase 9.

- ALPN on the client-facing TLS (`h2`, `http/1.1`) and independently on
  upstream. `hyper` HTTP/2 server + client; per-stream policy and audit,
  aggregated under a connection row (`ProxyH2Connection`, `stream`
  rows reference it).
- gRPC test matrix with `tonic` test server (unary, server-stream,
  client-stream, bidi) through the proxy; latency overhead measured and
  asserted < 10% of direct over 200 calls (loopback).

## Task 14 — Cross-cutting: supply chain, release, docs

ROADMAP "Cross-cutting".

- `deny.toml` + `cargo deny check` and `cargo vet` init in `just check`.
- `.github/workflows/ci.yml` (fmt, clippy, test on macOS + ubuntu with a
  Postgres service on ubuntu) and `release.yml` (tag → build universal
  macOS binaries, sign + notarise when `APPLE_*` secrets exist, else
  unsigned tarball; SHA-256 sums; GitHub release).
- `release/Formula/briefcred.rb` Homebrew formula (installs `briefcred`,
  `briefcred-daemon`, helpers, `briefcred-hook`; `service` block for the
  LaunchAgent).
- `docs/compatibility.md` runtime matrix (Node, Python, Go, Rust, Ruby,
  AWS CLI, gcloud, gh, psql, curl) with what each needs per phase;
  `docs/cb4a-conformance.md` (Model A/B/C mapping per credential kind,
  DPoP status); `docs/profile-schema.md` generated from the serde types
  (write a `briefcred profile schema` command emitting JSON Schema via
  `schemars` and check the doc in a test).
- Refresh `ARCHITECTURE.md`, `THREAT_MODEL.md`, `README.md`,
  `CONTRIBUTING.md` to match the final crate map and features.
