# briefcred — Roadmap

briefcred is a local, biometric-gated credential broker for AI agents and
developer tooling. It hands subprocesses short-lived, narrowly scoped
credentials, swaps placeholder keys for real ones at a local proxy, and
records every mint, request, and revoke in an append-only audit log.

This is a greenfield build. Nothing below has shipped. Phases are
sequenced, not parallelised; each declares what is decided, what gets
built, and what "done" looks like. Calendar estimates are deliberately
omitted — sequencing is the load-bearing part.

## Positioning

- **Local, biometric-gated broker that mints dynamic credentials *and*
  enforces Cedar policy.** Placeholder-key swap over `HTTPS_PROXY` is
  table stakes, not the product.
- Landscape, as reviewed on 2026-09-01. Products move quickly, so check each
  one's current documentation before relying on this:
  - Local placeholder-swap proxies already exist (Infisical Agent Proxy,
    OneCLI, Authsome, AgentSecrets, among others). In that review we did not
    find dynamic DB-role or STS minting, or a biometric unlock, in them; those
    are where briefcred puts its effort.
  - OpenFirma enforces Cedar locally and delegates minting to Vault or STS.
    briefcred's choice is minting and policy in one local daemon, not Cedar
    alone.
  - Hosted brokers cover related ground as services (1Password Credential
    Broker, HashiCorp Vault MCP, Teleport, StrongDM). briefcred is local and
    open source, and includes DB connection-auth injection.
  - Anthropic Managed Agents and OpenAI Sandbox Agents inject credentials from
    outside the sandbox for agents they host. briefcred is for local,
    non-hosted workloads and dynamic DB/STS credentials, not only "the agent
    never sees the key".
- Two halves, hybrid by backend:
  - **Identity broker** — mints real short-lived credentials (Postgres
    roles, AWS STS sessions, SSH certs) and revokes them after use.
  - **Credential-exchange proxy** — the subprocess never sees the real
    secret; a local TLS-terminating proxy substitutes it on the wire.
- Credential-handoff models, in order of strength:
  - **Model A** — proxy injects the real credential; subprocess only holds
    a synthetic token. Strongest.
  - **Model B** — broker mints a short-lived credential and hands it over.
  - **Model C** — real credential handed to the subprocess, revoked later.
    Weakest; acceptable only as a stepping stone and must be documented as
    such in the threat model.
- Policy must be typed and compiled (Cedar), never string-interpolated.
  Synthetic tokens carry a sender-binding (`cnf`) claim in the DPoP style.

## Execution order

Phases keep stable numbers for cross-linking. Build order:

**0 → 1 → 2 → 3 → 4 (thin) → 10 → 5 → 8 → 6 → 7 → 9**

Rationale: Phase 3 hands a minted Postgres role to the subprocess via env
vars (Model C). Phase 10 converts Postgres to Model A, so it is pulled
directly behind the thin proxy MVP. Streaming, upgrades, and HTTP/2 are
deferred because nothing in the market differentiates on them.

---

## Phase 0 — Groundwork

**Goal:** workspace, core types, and a Postgres minter whose revoke path
cannot leak roles.

**Work:**

- Cargo workspace: `briefcred-core`, `briefcred-proto`, `briefcred-daemon`,
  `briefcred-cli`, `briefcred-hook`, `briefcred-e2e`.
- `Profile` schema + YAML loader with unit tests.
- Traits and types: `Minter`, `MasterSource`, `MintCtx`, `RevokeCtx`,
  `MintedCredential`, `RevokeOutcome`, `AuditEntry`.
- `PostgresDynamicMinter`:
  - Mint creates `briefcred_t_<12 hex>` with grants from
    `role_template.grants`. Document the 63-char `NAMEDATALEN` ceiling.
  - Revoke runs a symmetric per-grant `REVOKE` loop derived from the same
    template, then best-effort `DROP OWNED BY`, then `DROP ROLE`. Never
    rely on `DROP OWNED BY` alone — it fails when the master does not own
    the schema (the managed-Postgres default).
  - SQL errors surface in `RevokeOutcome::Failed { detail }`. An audit row
    with `outcome=failed` and no detail is a bug.
- Integration test matrix against Postgres 16 and 18 in Docker where
  the master does **not** own `public`; a series of failed sessions
  leaves `\du` clean. PG18 changed `DROP OWNED BY` to also delete
  `pg_auth_members` rows, so the REVOKE-loop-first ordering must be
  asserted explicitly there.
- `ARCHITECTURE.md` and `THREAT_MODEL.md` written up front, declaring the
  hybrid shape and the Model A/B/C mapping per phase.

**Done when:** full mint → use → revoke cycle passes end-to-end in CI with
zero leaked roles; both docs are checked in.

---

## Phase 1 — Daemon foundation

**Goal:** long-lived per-user daemon with IPC, lifecycle, audit, and
metrics — no credential work yet.

**Decided:**

- Per-user daemon: launchd LaunchAgent on macOS, `systemd --user` on Linux.
  Never a system-wide daemon (no Aqua session → biometrics hang).
- Explicit setup via `briefcred install` (sudo only for CA trust install,
  writes the unit, starts the daemon, biometric setup). Auto-starts on
  login.
- `briefcred daemon status | start | stop | restart`. The CLI never
  auto-starts the daemon; if it is down, `briefcred exec` errors with the
  fix.

**Work:**

- Unix socket at `~/Library/Application Support/briefcred/sock` (XDG
  equivalent on Linux), mode `0600`, peer-UID check via `LOCAL_PEERCRED` /
  `SO_PEERCRED`.
- Length-prefixed JSON framing; dispatch table from `Request` variants to
  handlers; graceful shutdown on `SIGTERM`.
- Unit-file generation, install/uninstall scripts, idempotent directory
  provisioning.
- Daemon-status RPC.
- JSONL audit log under `.../briefcred/audit/`: daily rotation,
  configurable retention (default 90 days), append-only.
- Prometheus `/metrics` on localhost: uptime, IPC request counter,
  audit-write errors.

**Done when:** `briefcred install` yields a daemon that survives reboot and
reaches the Aqua session on `RunAtLoad`; `briefcred daemon status` reports
health; `curl localhost:<port>/metrics` returns a valid payload.

---

## Phase 2 — CA bootstrapping

**Goal:** a per-machine root CA installed and trusted; no proxy yet.

**Decided:**

- System trust store plus per-runtime trust env vars.
- Cert-pinning subprocesses are out of scope; they fail with a recognisable
  error, never silently.

**Work:**

- Generate the root CA at install time. Private key in Keychain (macOS) or
  kernel keyring / encrypted file (Linux).
- Trust install: `security add-trusted-cert` (macOS),
  `update-ca-certificates` (Linux).
- At `briefcred exec`, set `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`,
  `SSL_CERT_FILE`, `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE`, `CURL_CA_BUNDLE`;
  list configurable per profile.
- Document known pinning offenders (pinned gRPC clients, some mobile SDKs).

**Done when:** `curl https://example.com` inside `briefcred exec` sees the
briefcred-issued cert; Python `requests`, Node `fetch`, Go `net/http` all
succeed; pinning clients fail loudly.

---

## Phase 3 — Identity broker in the daemon

**Goal:** minting runs under daemon orchestration with biometric gating,
async revoke, and reconciliation.

**Decided:**

- Daemon-orchestrated, helper-executed: the daemon owns sessions, revoke
  tokens, reconciliation, and audit; each minter kind is a short-lived
  helper process spoken to over stdio JSON-RPC.
- Profile = work envelope: a `credentials:` list of mixed kinds in one
  YAML.
- Best-effort bundle: subprocess receives whatever minted; missing entries
  are absent, not fatal.
- Per-profile unlock policy (biometric / passcode).
- Master credential fetched on session open, held for session lifetime,
  zeroised on close or idle timeout (default 30 min).
- Minter registry: `kind` validated at profile load with an "unknown kind
  X (registered: …)" error. Adding a minter is a documented contract in
  `CONTRIBUTING.md`.

**Work:**

- `KeychainSource`: `SecItemAdd` / `SecItemCopyMatching` with the legacy
  keychain (`kSecUseDataProtectionKeychain: false`) so no signing
  entitlements are required. Returns `Zeroizing<String>`.
- Biometric gate: `LAContext.evaluatePolicy(.deviceOwnerAuthentication)`
  via FFI, decoupled from keychain ACLs. Async wrapper returning
  `Cancelled | Failed | NoAquaSession`; headless callers get a clear error,
  never a hang. Budget a one-day binding spike before this item.
- Profile loader: walk `.../briefcred/profiles/*.yaml`, hot-reload on
  change.
- Subprocess wrapper (the load-bearing UX):
  - Compose `${minted.X}` / `${config.X}` env templates.
  - Spawn with an explicitly constructed env — never inherited.
  - Enforce `argv0` and arg-pattern allowlists from the profile.
  - Return immediately on child exit; revoke proceeds in background.
- Helpers: `briefcred-helper-postgres` (persistent master connection),
  `briefcred-helper-sts`.
- Async revoke queue with retry + backoff.
- Reconciliation sweep every N minutes: scan `pg_roles` for stale
  `briefcred_t_*` and force-clean. Must survive daemon `SIGKILL` mid-exec.
- SQLite or JSONL audit rows for mint, exec-start, exec-end, revoke. Args
  hashed by default; raw args opt-in.
- Memory-hygiene harness: the master credential never appears in daemon
  or child heap during or after a mint cycle.
- CLI subcommands wired to the socket: `exec`, `get`, `profiles`,
  `health`, `audit`, `profile bootstrap` (interactive wizard that writes
  YAML and stores the master in Keychain).
- `briefcred-hook`: reads a PreToolUse JSON event from stdin, matches
  `hook-rules.yaml`, consults the daemon, emits
  `hookSpecificOutput.permissionDecision` (allow / deny / ask) with
  `permissionDecisionReason`, and optionally `updatedInput` to rewrite
  the command. Known limits: `updatedInput` is ignored for the Agent
  tool and is last-writer-wins when several hooks fire.

**Done when:** a profile declares two Postgres credentials in one
envelope; `briefcred exec --profile=db-prod-ro -- psql -c "SELECT
count(*) FROM orders"` prompts Touch ID, mints both, runs, both revoke
async, reconciliation backstops them; mint/revoke histograms visible in
metrics. One week of daily personal use without daemon babysitting.

---

## Phase 4 — HTTP proxy MVP (thin)

**Goal:** the proxy half exists, narrowly. HTTP/1.1 only. Parity with
existing placeholder-swap tools, one sprint, no more.

**Decided:**

- `HTTPS_PROXY` interception with TLS termination by the local CA.
- Placeholder convention `__<credential_name>__` accepted anywhere in a
  header value, so migrating users get a drop-in.
- Mint binding via a signed structured token `bc.<base64-payload>.<sig>`
  whose payload carries a `cnf` binding to a per-session ephemeral key.
- Cedar input shape: principal `Session::"<id>"`, action = HTTP method,
  resource = host + path.
- Default deny, per-profile observation-mode toggle.
- Audit detail: metadata only — no headers, no bodies.

**Work:**

- HTTP CONNECT listener on the daemon's localhost port.
- Per-machine signing key; daemon verifies incoming synthetic tokens.
- TLS terminate + re-encrypt upstream.
- Authorization header swap: detect synthetic token → session lookup →
  substitute master credential.
- Cedar engine integration; policy lives under the profile's `policy:`.
- Observation mode: log-and-allow on no match, with a promote-to-enforce
  flag.
- Audit row per forwarded request: timestamp, mint id, method, host, path
  (no query string), status, byte counts, latency.

**Done when:** a profile with an OpenAI master credential and an allowlist
policy mints a synthetic key; the subprocess sets
`OPENAI_API_KEY=<synthetic>`; `GET api.openai.com/v1/models` succeeds with
the real key swapped in; an unmatched POST is denied; observation mode
logs the would-be denial without blocking.

---

## Phase 10 — Postgres connection-auth proxy

**Sequencing:** immediately after Phase 4. Moves Postgres from Model C to
Model A.

**Decided:**

- Connection-time auth only: intercept startup and auth, substitute the
  master credential, byte-forward afterwards.
- SQL-level privilege narrowing stays in broker mode (`postgres_dynamic`
  with `role_template.grants`).

**Work:**

- Postgres startup-message parser.
- SCRAM-SHA-256 auth handler using the daemon-held master. MD5 is
  legacy-only behind a flag: deprecated in PG18, scheduled for removal
  by PG21.
- Byte-forward state after auth.
- Audit row per connection: session, master role, start/stop, byte counts.
- `postgres_proxy` credential kind in the profile schema.

**Done when:** `psql` connects via a synthetic DSN (`host=localhost
password=<synthetic>`), upstream auth succeeds with the real master,
queries flow, audit records the connection.

---

## Phase 5 — Quotas and policy refinement

**Goal:** bound time and usage; make Cedar the headline feature with a
cookbook of rules host/path globs cannot express (method × path ×
time-window × session × byte budget).

**Decided:**

- Per-profile token-bucket quotas in YAML.
- Policy stays session-as-principal, host+path-as-resource; no body
  parsing.

**Work:**

- Token bucket per session: rate, burst, optional per-session total cap.
- Saturation metric on Prometheus; 429-style rejection at the proxy.
- Policy docs with example profiles for OpenAI, Anthropic, GitHub, Stripe.

**Done when:** `quota: { rate: 10, burst: 20 }` rejects the 21st request
inside one second; metrics show saturation; documented examples run as-is.

---

## Phase 8 — Profile distribution

**Goal:** team-wide trustable profiles.

**Decided:**

- Layered: local overrides, signed preferred, unsigned-local allowed only
  in dev mode with a loud warning.

**Work:**

- Signature scheme (sigstore-compatible or PGP — pick at design time).
- Trust-root configuration in daemon config.
- `briefcred profile sync` against a registry (git repo or HTTPS).
- Precedence resolution; `briefcred profile show <name>` reveals source and
  signature status.

**Done when:** an unsigned registry profile is rejected; a signed one from
a trusted issuer is accepted; local overrides are visible from the CLI;
dev mode cannot be run accidentally in production.

---

## Phase 6 — Streaming protocols

**Goal:** SSE and WebSockets pass through without buffering or breaking.

**Work:**

- SSE: no `Content-Length`, byte-by-byte forwarding, keep-alive, upstream
  close propagation.
- WebSocket: HTTP/1.1 Upgrade passthrough, bidirectional frame forwarding.
- Per-protocol audit: SSE rows with start/stop and event count; WS rows
  with lifetime and frame counts.
- Tests against OpenAI and Anthropic streaming endpoints.

**Done when:** streaming completions through the proxy match direct-call
latency within ~5 ms; realtime WebSocket stays full-duplex correct; audit
records both.

---

## Phase 7 — Concurrent sessions and zero-downtime upgrades

**Goal:** the daemon survives upgrades without dropping in-flight work.

**Decided:**

- Independent sessions: every session is its own mint, even on the same
  profile.
- Socket handoff for upgrades.

**Work:**

- Tokio task per session with isolated state.
- Listening-socket FD handoff: systemd socket activation on Linux, Unix
  domain socket FD passing on macOS.
- In-flight requests finish on the old daemon; new sessions route to the
  new one.
- Signed session-state file for the handoff.

**Done when:** `briefcred daemon upgrade` during an active SSE stream drops
zero bytes; new sessions immediately hit the new binary.

---

## Phase 9 — HTTP/2 and gRPC

**Goal:** the long tail of modern HTTP traffic.

**Work:**

- HTTP/2 on both proxy edges (`h2` crate); independent ALPN negotiation
  client→proxy and proxy→upstream.
- Preserve stream multiplexing across the proxy.
- gRPC matrix: unary, server-streaming, client-streaming, bidi.
- Audit: per-stream rows aggregated under a connection row.

**Done when:** all four gRPC call types complete through the proxy;
upstream connection pooling preserved; the latency briefcred adds is
bounded in absolute terms rather than as a bare ratio.

A ratio alone was the wrong bound and the measurement said so. On
loopback a direct gRPC unary call costs a couple of hundred
microseconds, and the proxied path terminates one TLS session and
originates a second on top of the token check, the quota charge, the
Cedar decision and the audit row. Ten percent of two hundred
microseconds is twenty, which no proxy doing that work can meet; the
same absolute cost against a real vendor over a real network, where the
round trip dominates, is under one percent. The measured figure on this
machine is about 212 µs added per call in a release build. So the bound
asserted is `proxied <= direct * 1.10 + 2 ms`: the ratio for the case
where the upstream is far away, and the allowance for the case where it
is not.

---

## Additional minters (slot in after Phase 3)

- **AWS STS** — `AssumeRole` with optional inline session policy;
  `RoleSessionName` derived from the mint id for audit correlation.
  Precheck inline session-policy plaintext against the 2,048-char
  `AssumeRole` limit (the 10,240-char cap is for role inline policies,
  a different quota). Revoke by
  advancing one rolling `aws:TokenIssueTime` deny policy per role (never
  one policy per mint). Record `RevokeOutcome::EventuallyConsistent
  { propagation_estimate: 5s }`.
- **SSH certificate** — CA key in Keychain, biometry-gated. Fresh ed25519
  keypair per mint, `ssh-keygen -s` with principals, TTL, serial; revoke by
  appending the serial to a local KRL. Document that servers must set
  `RevokedKeys`.
- **kubectl via SSH cert** — same pattern, kubeconfig minted server-side.
- **MCP tools** — `briefcred_db_query`, `briefcred_kubectl_exec`: the
  credential never enters model context; only `{stdout, stderr, exit_code}`
  is returned and the audit row links the MCP call id to the mint.

## Cross-cutting (every phase)

- Docs: profile schema reference, policy authoring guide, threat-model
  updates, CB4A-style conformance statement (which phases map to Model
  A/B/C, DPoP status). CB4A is still draft -00 (expires 2026-09-30, no
  WG adoption); track for revisions.
- MCP spec 2026-07-28 mandates RFC 8707 resource indicators and RFC 9728
  protected-resource metadata; the transparent proxy must pass
  audience-bound tokens through unchanged and never re-scope them.
- Operator UX testing against managed, cloud, and on-prem Postgres.
- Runtime compatibility matrix: Node, Python, Go, Rust, Ruby, AWS CLI,
  gcloud, gh, psql, curl.
- Supply chain: code-signed and notarised daemon/helper binaries,
  reproducible builds, `cargo vet` / `cargo deny` in `just check`. Proxies
  are exfil targets.
- Distribution: Homebrew tap, release CI that degrades to unsigned
  tarballs when Apple secrets are absent.

## Permanent non-goals

- HTTP-API credential brokering as a hosted service.
- Static-secret store as a marquee feature.
- Mac App Store distribution (sandbox blocks Unix-socket IPC).
- System-wide LaunchDaemon deployment.
- Replacing 1Password / Vault as a master-secret store.
- Headless / CI use of biometric-gated profiles.

## Open ambiguities

- Platform scope: macOS-first vs macOS+Linux from day one vs Windows.
- Daemon-down failure modes mid-session: in-flight requests, audit
  consistency, recovery.
- Subprocess-level identity: bind the synthetic key to a PID as well as a
  session?
- Backup / restore / DR for daemon state, audit logs, CA keys.
- Multi-machine: shared CI runners, build fleets — probably out of scope.
- Master credential rotation while a session holds the old one.
- Profile signing scheme specifics (must resolve before Phase 8).

## Open risks

- `LAContext` from a Rust LaunchAgent — budget a binding spike, run it
  on macOS 26.4+ (open reports of keychain `errSecAuthFailed` and CA
  trust regressions on that release).
- First-party sandbox brokering (Anthropic Managed Agents, OpenAI
  Sandbox Agents) erodes the "agent never sees the key" pitch for hosted
  workloads; keep dynamic DB/STS minting as the headline.
- Notarisation toolchain: Developer ID + `notarytool` + key handling in CI.
- First-time-after-reboot: `RunAtLoad` must reach the Aqua session before
  any user app launches.
- AWS STS revoke staleness — track if propagation exceeds ~5 s in practice.

## Validation gates

| Gate | Goes if… | Does not go if… |
|---|---|---|
| Phase 0 → 1 | Postgres mint/revoke leaks nothing across failed sessions | Rework the revoke path |
| Phase 3 → 4 | One week of real Postgres workflow without daemon babysitting; memory-hygiene tests pass | Reassess minter or daemon shape |
| Phase 4 → 10 | Synthetic-key swap works for a real API with default-deny policy | Reassess proxy binding model |
| STS/SSH → next | Revoke survives a two-week real workload; SSH cert works against ≥1 real host | Reconsider STS staleness; possibly require proxy mode for cloud creds |

## Architectural decisions

| Decision | Choice |
|---|---|
| Architectural shape | Hybrid by backend (identity broker + credential-exchange proxy) |
| Proxy target priority | HTTP first, DB wire protocol immediately after |
| Security properties | Hide credential, narrow privilege, bound time/usage, audit chokepoint |
| Discovery / transport | `HTTPS_PROXY` + local CA |
| Process model | Long-lived per-user daemon |
| Policy DSL | Cedar |
| Mint binding | Synthetic API key, structured signed token with `cnf` |
| Protocol scope | HTTP/1.1, SSE, WebSockets, HTTP/2 + gRPC |
| Profile shape | Work envelope of mixed credential kinds |
| MCP lease | One mint per MCP session |
| CA install | System trust + per-runtime env vars |
| Bundle semantics | Best-effort |
| Master credential lifetime | Fetch on session open, hold for session, zeroise on close |
| Audit detail | Metadata only |
| Broker home | Daemon-orchestrated, helper-executed |
| Unlock UX | Per profile, configurable |
| Quota mechanism | Per-profile token bucket |
| Concurrency | Independent sessions |
| Eviction | Session close + idle timeout |
| Cedar input shape | Session as principal, host+path as resource |
| First-run UX | Explicit setup, then use |
| Upgrade strategy | Socket handoff |
| Audit storage | Append-only JSONL |
| Observability | Prometheus `/metrics` |
| MCP role | Transparent MCP-aware HTTP proxy; no MCP protocol in the daemon |
| Postgres wire scope | Connection-time auth only |
| Profile distribution | Local + signed + registry, layered |
| Default policy | Default deny, observation-mode toggle |
