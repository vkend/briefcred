# Threat model

This document is written ahead of the code it describes, so that a phase that
weakens a guarantee has to say so out loud before it ships.

## Assets

| Asset | Where it lives | Why an attacker wants it |
| --- | --- | --- |
| Master credentials | macOS Keychain; Linux kernel keyring or an encrypted file | Long-lived, broadly scoped. The whole point of the product is that these never leave the daemon. |
| Minted credentials | Daemon memory, and for Model C the subprocess environment | Short-lived and narrowly scoped, but real. |
| Root CA private key | macOS login keychain (`dev.briefcred.ca`), or `ca/ca.key` at 0600 | Signs certificates the machine's TLS clients trust. Compromise means transparent interception of every proxied connection. |
| Audit log | `.../briefcred/audit/*.jsonl` | Tampering hides an incident; reading it reveals what ran and when. |
| Profiles | `.../briefcred/profiles/*.yaml` | Write access is privilege escalation: a profile decides what gets minted and what may run. |
| Policy (Cedar, Phase 5) | `.../briefcred` | Same as profiles. |
| Synthetic tokens | Subprocess environment | Only useful through the local proxy, and sender-bound by a `cnf` claim. |

## Trust boundaries

1. **User account boundary.** Everything briefcred owns is per-user, mode 0600,
   under the user's own directory. There is no system-wide daemon: a root
   daemon has no Aqua session, so biometric prompts would hang.
2. **Daemon / client boundary.** The Unix socket checks the peer UID via
   `LOCAL_PEERCRED` (macOS) or `SO_PEERCRED` (Linux). Any local process running
   as the same user is inside this boundary.
3. **Daemon / subprocess boundary.** The subprocess gets an explicitly
   constructed environment, never an inherited one, and is constrained by the
   profile's `argv0` and argument allowlists.
4. **Daemon / helper boundary.** Minter helpers are separate short-lived
   processes over stdio JSON-RPC. A helper sees one master credential for one
   kind, never the daemon's whole state.
5. **Machine / backend boundary.** Outbound database and API connections use
   TLS with the platform trust store. `sslmode` defaults to `require`.

## Attacker model

**In scope.**

- A malicious or compromised subprocess, including an AI agent, that tries to
  read more than it was given, outlive its credential, or reach a backend the
  profile did not authorise.
- A local process running as another user attempting to reach the socket, the
  audit log, or the profiles.
- A network attacker between the machine and the backend.
- Accidental credential leakage into logs, crash dumps, shell history, or
  error text.
- Operator error: a mistyped profile key silently disabling a control.

**Out of scope.**

- An attacker with root on the machine, or with the user's login password and
  physical access. Both can read the Keychain.
- A compromised backend.
- Malicious hardware, firmware, or a hostile OS.
- Denial of service against the local daemon.
- Certificate-pinning clients. They fail loudly and are documented, not
  worked around.

## What each phase actually guarantees

**Phase 0.** A library, no daemon, no privilege boundary. The
guarantees are hygiene guarantees:

- Master and minted secrets are held in `Zeroizing<String>` and zeroed on drop.
- `MintCtx`, `RevokeCtx`, and `MintedCredential` have hand-written `Debug`
  impls that redact secrets, and `MintedCredential` is deliberately not
  `Serialize`.
- Profile parsing rejects unknown keys at every level, so a typo cannot
  silently disable `exec.allow_argv0` or a `ttl_secs`.
- Grant clauses are restricted to keywords and dotted identifiers, and
  identifiers reach SQL only through PostgreSQL's escaping helpers.

Residual risk: `tokio_postgres::Config` copies the master password into memory
that briefcred does not control and does not zero. Closing this needs an
upstream change or a hand-rolled startup packet, and is tracked for Phase 3
when the persistent helper connection replaces per-call connects.

**Phase 2: the CA.** Generating a root CA and asking the machine to trust it
is the single largest privilege briefcred takes. What bounds it:

- `pathlen:0`. The CA can sign leaves and nothing else. Whoever holds the key
  cannot mint an intermediate and hand signing authority to someone else, so a
  stolen key is a machine-scoped problem rather than a transferable one.
- The key never leaves the machine and is never written to `ca.pem`. On macOS
  it is a login-keychain item gated by the login session; elsewhere it is a
  `0600` file inside a `0700` directory. Nothing prints it: both
  `CertificateAuthority` and `Leaf` have hand-written `Debug` impls that
  redact the key, and the key store's own `Debug` prints its location only.
- Leaves live 24 hours and are per hostname, so a leaked one is narrow and
  short.
- Trust is scoped to one certificate, added with an explicit `--trust-ca` and
  removable with `briefcred ca untrust`. `briefcred ca show` prints the
  fingerprint so the user can check what they trusted against what is
  installed.
- The trust step is the only thing briefcred runs under `sudo`. It is built as
  a plan and executed separately, so it can be printed before it is run, and
  no test can invoke it.

Residual risk, stated plainly: anyone who can read the user's login keychain,
which includes root and anyone with the login password, can take the CA key
and issue certificates every TLS client on that machine will accept. The trust
store entry also outlives an uninstall by design, because `uninstall` keeps
`ca/` so a reinstall stays trusted; a user who wants the trust gone must run
`briefcred ca untrust`.

Regenerating is destructive on purpose. `briefcred ca regenerate` untrusts the
old certificate first, because the macOS trust store matches on content and
after the replacement there would be nothing left to match, leaving a stale
trust entry for a key nobody holds.

**Phase 3: minting, `exec`, and revoke.** This is the first phase where a real
credential reaches a subprocess, and it is **Model C**: the child can read
`PGPASSWORD`. Phase 10 moves the same credential to Model A by completing the
PostgreSQL handshake at the proxy. Until then, what bounds the exposure is that
the credential is *short* and *narrow*, not that it is hidden.

What the design buys:

- **The credential is new and it expires.** A role minted for one `briefcred
  exec` is created for that run with the profile's `ttl_secs` and dropped when
  it ends. A leaked one is useful for minutes, not until somebody rotates a
  shared password.
- **The allowlist runs before the mint.** A command a profile forbids never
  causes a principal to be created, so a rejected `briefcred exec` leaves
  nothing to clean up and nothing to leak.
- **The subprocess environment is built, not inherited.** `env_clear()` means a
  credential that happened to be in the caller's shell does not travel into the
  child. That is a real reduction: the common accident is not briefcred's
  credential escaping, it is somebody else's arriving.
- **Minting is out of process.** Every minter runs as
  `briefcred-helper-<kind>`, so the code holding a database master password is
  not in the daemon's address space. A memory-disclosure bug in a backend
  client library exposes one backend's master rather than every master the
  daemon has ever held. A helper that stops answering is killed rather than
  waited on, because it is holding a master.
- **Revoke has three independent nets.** The persisted queue, the session
  close, and the reconciler. The last exists specifically for `SIGKILL`, and it
  is exercised against a real cluster by killing a real daemon mid-run.
- **The daemon's memory is checked, not asserted.** `just mem-hygiene` proves a
  master is absent from the daemon's address space after its session is closed,
  and proves it was present beforehand so the absence means something.

Residual risks, stated plainly:

- **A `get` value lives for the credential's whole TTL.** `briefcred exec`
  revokes when its child exits; `get` cannot, because it hands the value to a
  caller who is about to use it, and revoking on return would print a dead
  credential. The revoke is scheduled for the mint's own expiry instead, so
  `ttl_secs` is the exposure window for anything fetched with `get`. Set it to
  the shortest window the work needs.
- **`briefcred get` is exempt from `exec.allow_argv0`.** It spawns nothing, so
  there is no program for the allowlist to be about, and it hands the credential
  to a caller who was always free to run whatever they liked with it. Making
  `get` pick an allowed program would be theatre. The `--force` requirement for
  a terminal is a hygiene control, not a security boundary, and it does not stop
  a caller redirecting the value anywhere.
- **The allowlist is not a sandbox.** `exec.allow_args` is a set of regular
  expressions over argument strings. It stops an agent asking for `DROP TABLE`
  when the profile only permits `^SELECT `; it does not stop a permitted program
  doing something clever with a permitted argument. The real bound on damage is
  the *grant template*: what the minted role is allowed to do at the backend.
  Narrow that first.
- **The hook's rewrite is advisory.** `updatedInput` is a request an agent may
  ignore, and it is textual, so a pipeline or a `&&` chain only puts its first
  command under briefcred. `docs/hook.md` says this at length. Nothing should
  depend on a rewrite having happened.
- **A reconcile sweep needs the master.** It fetches one per profile credential
  from the master source, which on macOS may prompt for a locked keychain. A
  profile whose master has been removed is skipped, and its strays then live
  until their `VALID UNTIL` makes them useless rather than until they are
  dropped.
- **`tokio_postgres::Config` still copies the master into memory briefcred does
  not zero.** Moving minting into a helper bounds the blast radius of that to
  one backend and one short-lived process, which is the improvement Phase 3
  could make; it does not close it. Closing it needs an upstream change or a
  hand-rolled startup packet.
- **The `debug-heapscan` feature must never ship.** A same-uid caller who could
  ask a production daemon whether a digest matches anything in its memory would
  have a confirmation oracle for guessed secrets. It is behind a cargo feature
  that only `just mem-hygiene` enables, and the request does not exist in a
  daemon built without it.

**Phase 3a: master sources, the unlock gate, and sessions.** This is where
briefcred starts holding the secret that matters. The guarantee it aims at is
narrow and worth stating exactly: *malware running as the user cannot mint a
credential without a human physically answering a prompt, and cannot read a
master except during the window a human opened.*

What bounds it:

- **The gate runs before the master is fetched.** `OpenSession` prompts first
  and reads the keychain second, so a refused prompt leaves nothing behind.
  The refusal is audited as `unlock_denied` with the reason.
- **The gate fails closed, on a best-effort check.** With no graphical session
  — over SSH, or in a `launchd` background session — there is nothing to draw a
  prompt in, and briefcred returns `no_aqua_session` rather than falling back
  to something an attacker could satisfy. The refusal runs *before* the unlock
  cache, so a warm cache from a desktop login cannot carry an SSH shell
  through. Turning the gate off is possible, but only by editing the profile to
  say `unlock.policy: none`, which is a visible, auditable choice rather than
  an inference. The limits of the check are spelled out under residual risks
  below; it is not a boundary against a hostile same-uid caller.
- **The cache is per profile and time-bounded.** A cached unlock lasts
  `unlock.cache_secs`, 300 seconds by default. Unlocking a low-value profile
  never opens a high-value one, and a profile reload clears the cache, so
  tightening a policy takes effect at once.
- **Session lifetime bounds master lifetime.** Masters live in
  `Zeroizing<String>` inside the session, and closing, idle eviction, and
  shutdown all wipe them by dropping it. There is no state where a session is
  "closed" but its masters are still resident.
- **Session handles are unguessable.** 128 bits from the OS CSPRNG, because the
  handle is a bearer token: a predictable one would let any process on the
  machine use a session it never unlocked.
- **A key cannot escape its namespace.** Master keys are validated against one
  character set for every backend, so a key that is meaningless against the
  keychain cannot become `../ca/ca.key` against the file backend.

Residual risks, stated plainly:

- **The cache window is a real window.** For up to `unlock.cache_secs` after a
  successful unlock, any local process running as the user can open a session
  for that profile without a prompt, and read the masters it holds. It is a
  window on the *profile*, not on the terminal that unlocked it: briefcred
  cannot distinguish the shell the human typed into from any other same-uid
  caller. Setting `cache_secs: 0` closes it at the cost of prompting every
  time. This is the deliberate trade, and it is the single largest gap between
  "malware cannot mint without a human" as a slogan and what the code enforces.
- **The headless refusal is advisory, not enforced.** It is the union of two
  checks, and neither is a boundary. The daemon's own `SessionGetInfo` check is
  honest but blind: the daemon lives in launchd's session and cannot tell who
  is connecting. The client's `client_headless` flag closes that blind spot for
  honest clients, but it is a self-declaration — a program running as the user
  can simply send `false`. briefcred cannot verify it and does not pretend to.
  The value is real but narrow: an honest client on SSH gets an accurate
  refusal instead of a prompt drawn on the console user's screen. Against a
  hostile same-uid caller the refusal buys nothing, which is consistent with
  every other guarantee on this page.
- **An open session is an exposed master.** Anything that can read the daemon's
  memory — a debugger attached as the same user, root, a core dump — can read
  every master of every open session. `session_idle_secs` bounds how long that
  is true; it does not make it false.
- **`EnvSource` is not safe and does not pretend to be.** Every child process
  inherits the master, and it warns once per process saying so. It exists for
  development on a machine with no keychain.
- **The prompt is a system prompt.** briefcred asks `LAContext` to
  authenticate the device owner; it does not, and cannot, verify that the
  answer came from the person who typed the command rather than someone else
  at the same keyboard.
- **A trusted profile directory.** Anyone who can write `profiles/*.yaml` can
  add a profile with `unlock.policy: none` and a `source_key` naming an
  existing master. The directory is `0700`, which means that attacker is
  already the user — the same boundary as everything else here.

**Phase 3: Model C exposure.** This is the weakest point in the plan and it is
deliberate. `briefcred exec` hands the subprocess a minted role through
`PGUSER` / `PGPASSWORD` / `DATABASE_URL`. Consequences:

- The subprocess can read the credential out of its own environment and copy it
  anywhere before it expires.
- Anything that can read `/proc/<pid>/environ` on Linux, or attach a debugger
  on macOS, gets the same.
- A crash reporter that captures the environment captures the credential.

What limits the damage:

- The credential is scoped to exactly the grants in the profile's
  `role_template`, so it is not the master.
- `VALID UNTIL` caps its life at the profile's `ttl_secs`, 15 minutes by
  default, even if revoke never runs.
- Revoke runs on child exit, backed by a retry queue and a reconciliation
  sweep, so an abandoned role is removed rather than left to expire.
- Every mint, exec, and revoke is audited.

**How Phase 10 closes it.** Phase 10 moves PostgreSQL to Model A. The
subprocess is pointed at the local proxy and given a placeholder password. The
proxy completes the real authentication handshake with the backend on the
subprocess's behalf, so the minted password never enters the subprocess's
address space at all. After Phase 10, reading the environment of a briefcred
subprocess yields a token that only works through the local proxy, only for the
connections policy allows, and only while the session is open.

**Phase 4 and 10: the proxy is a new asset.** Terminating TLS locally means the
CA key becomes a high-value target and the proxy sees plaintext. Mitigations:
the CA is per machine and never leaves it, the key lives in the Keychain, the
proxy binds to loopback only, and no request body or header is ever written to
the audit log.

## Audit guarantees

- **Append-only.** Rows are appended as JSON Lines and rotated daily. Retention
  defaults to 90 days.
- **Metadata only.** Never headers, bodies, query strings, connection strings,
  or credential material. Command arguments are recorded as SHA-256 digests, so
  two runs can be correlated without the log becoming a secret store.
- **Every outcome is recorded, including failure.** A failed revoke carries a
  non-empty `detail` with the backend's SQLSTATE and message. An `outcome=failed`
  row with no detail is a bug, and there is a test for it in both directions.
- **Session and unlock events are recorded.** `session_open` and
  `session_close` carry the handle and profile, and `session_close` says which
  of `request`, `idle`, or `shutdown` ended it, so every opened session can be
  accounted for. `unlock_denied` records a refused prompt and its reason;
  `profile_load_error` records that the daemon carried on with stale profiles.
  None of these rows carries a master, a key's value, or a profile's contents.
- **Arguments can be recorded verbatim, but only on request.** `[audit]
  raw_args = true` in `daemon.toml` adds the arguments themselves alongside
  their digests. It is off by default and it makes the audit log sensitive:
  an operator who needs to see the SQL an agent actually ran turns it on
  knowingly. The digests stay either way, so a log with it on and one with it
  off remain correlatable.
- **Reconciliation is auditable.** A stray removed by a sweep gets its own
  `revoke` row plus a `reconcile` summary row, so a credential cleaned up
  because a daemon was killed is as findable as one its owner revoked. The
  summary row is written even when a sweep finds nothing, because "the
  reconciler is alive and the backend is clean" is itself the thing an operator
  needs to see.
- **Not tamper-evident.** A user who can write the log can rewrite it. Signing
  or an append-only system store is deliberately out of scope for now, and this
  line should be revisited before anyone treats the log as compliance evidence.

## Phase 4: the HTTP proxy, and Model A for HTTP

The `http-*` credential kinds are the first Model A path briefcred ships. The
subprocess never holds the API key. What it holds is a **synthetic token**, and
the whole question is what that token is worth to whoever gets it.

### What the token is bounded by

A stolen token is useful only:

- **through this machine's loopback proxy.** It is not a credential any vendor
  accepts. Sent to `api.openai.com` directly it is an invalid key.
- **for the session it was issued to.** The payload names the session; the proxy
  looks that session up, and a session that has been closed or evicted no longer
  resolves. Closing a session is therefore a real revocation, not a hint.
- **for the one credential it names.** A token for `openai` cannot be presented
  to get the `stripe` key out of the same session.
- **within the profile's Cedar policy.** The token authenticates; the policy
  authorises. A token that reaches every endpoint is a policy that permitted
  every endpoint.
- **until its `exp`, or until the grant is revoked.** `briefcred exec` finishing
  revokes it, and the proxy refuses it from that moment.

### What it is not bounded by, and this is the important part

**Possession.** The token's `cnf.jkt` names a per-session key, and a client that
sends a `DPoP` proof has it checked against that key — signature, method, URI,
and freshness. But `briefcred exec` cannot send one. The credential reaches the
subprocess as an environment variable, and the subprocess is `curl`, or a vendor
SDK, and neither has any idea briefcred exists.

So **the proxy accepts a bare token**, and on that path the token is a bearer
credential. Anything that can read the subprocess's environment — a sibling
process of the same user, a core dump, a log line that prints `env` — can use
it, for as long as it lives, from this machine.

This is a real weakening and it is stated rather than hidden. What it still buys
over Model C:

| | Model C (`PGPASSWORD`) | Model A with a bare token |
| --- | --- | --- |
| Usable off the machine | yes | no |
| Usable after the session closes | until revoked at the backend | no |
| Usable outside the policy | yes | no |
| Recorded per request | no | yes, one audit row each |
| Value if the vendor's logs leak it | the key | nothing |

The `cnf` binding is carried anyway. It costs one key generation per session, it
is what a first-party in-process client will use the moment there is one, and a
proof made with the wrong key is refused rather than shrugged at — so a client
that *does* present one cannot be downgraded by an attacker who strips it.

### What the proxy itself is trusted with

The proxy holds every master its open sessions opened, and it terminates the
subprocess's TLS. That makes it the most valuable process on the machine after
the daemon it is part of — which it is, deliberately: putting it in the daemon
means the master never crosses another process boundary to reach it.

Three things bound what it can do wrong:

- **The listener is loopback only.** `127.0.0.1`, never a routable address.
- **Upstream verification is never weakened.** There is no code path that
  accepts an unverified certificate. `upstream_roots` in `daemon.toml` adds
  roots, is documented as being for the test suite, and logs a warning naming
  itself every time it is used.
- **A synthetic token cannot leak upstream.** After the credential swap, every
  header is checked again and a request still carrying anything token-shaped is
  refused rather than forwarded.

### What the audit row does and does not hold

One `ProxyRequest` row per request, whatever happened to it: timestamp, mint id,
method, host, path, status, byte counts, latency, decision. Three omissions are
deliberate and load-bearing:

- **No headers.** One of them is the credential.
- **No body.** It is whatever the agent decided to send.
- **No query string.** It routinely carries an API key, and an audit log that
  recorded it would be the secret store this row exists to make unnecessary.

The path is enough to answer "what did the agent reach" without being enough to
reconstruct what it sent.

## Known limitations, stated plainly

- A local process running as the same user is inside every boundary. briefcred
  raises the cost of exfiltration and shortens the window; it is not a sandbox.
- Certificate-pinning clients cannot be proxied and will fail. That failure is
  documented in `docs/ca-pinning.md`, and briefcred never works around it by
  disabling a client's verification.
- Trusting the CA is machine-wide. Every process running as any user on the
  machine, not only briefcred's subprocesses, will accept a certificate this
  CA issued.
- Revoke against an eventually consistent backend, such as AWS STS, cannot be
  immediate. The outcome type says so rather than pretending otherwise.
- A subprocess can copy the credential it was given anywhere before it exits.
  Revoking afterwards ends the credential's usefulness; it does not undo what
  was done with it while it was live. This is the whole of what Model C means,
  and it is why Phase 10 exists.
- A synthetic token used without a `DPoP` proof is a bearer credential for the
  session that holds it. Every runtime `briefcred exec` wraps is on that path,
  because an environment variable is the only channel it has. See **Phase 4**
  above for what the token is still bounded by.
- The revoke queue gives up after eight attempts. A backend that is unreachable
  for longer leaves a principal behind until the reconciler's next sweep, which
  is bounded by the profile's `ttl_secs` in how long that principal is useful.


## The three additions in Phase 7, and what each one costs

### AWS STS: revoke is blunt and late

STS sessions cannot be withdrawn. AWS provides no call that ends a set of
temporary credentials early, and the technique the console's "Revoke sessions"
button uses — the one briefcred uses — is to attach an inline policy to the
**role** denying everything to any session issued before a chosen instant.

Two consequences, and neither can be engineered away:

- **It is collective.** Revoking one briefcred mint denies every session of
  that role issued before now, including sessions belonging to other people and
  other tools. The mitigation is operational, not technical: give briefcred a
  role nothing else assumes. `README.md` says so where an operator will read it
  before configuring one.
- **It is late.** IAM is eventually consistent and AWS publishes no bound. The
  outcome is `eventually_consistent` with a five-second estimate, and the audit
  row records the estimate, so "the credential may have kept working for five
  seconds" is written down rather than assumed. A session used by a service
  that cached its credentials may keep working longer than that.

If the master lacks `iam:PutRolePolicy` on the role, revoke reports `failed`
and the session simply runs to its `duration_secs`. That is why
`duration_secs` should be the shortest the work tolerates: it is the only
bound that does not depend on a second permission.

### SSH certificates: revocation depends on your servers

A signed certificate cannot be recalled. briefcred's revoke does the half it
owns — it deletes the private key from the machine, immediately — and records
the certificate's serial in an OpenSSH key revocation list at
`<home>/state/ssh-krl`. The second half only exists on servers an operator has
pointed at that file with `RevokedKeys`, and briefcred cannot do that for them:
it runs on a laptop and has no credentials for the fleet.

So:

- A certificate copied off the machine before the revoke works on every server
  that has not received the updated KRL, until its `valid_before`. **The TTL is
  the control; the KRL is the backstop.**
- `RevokedKeys` is checked at authentication. A session already established is
  unaffected by a revoke, however promptly the KRL is distributed.
- The KRL is written with a wildcard CA, so a serial revokes a certificate from
  any authority. Serials are random 64-bit values, so this over-revokes with
  negligible probability, and it errs towards refusing.
- `docs/ssh-krl.md` is the operator-facing version of all of this, including
  what an acceptable distribution lag looks like.

The `ssh-cert` minter also runs **inside the daemon** rather than in a helper,
because it opens no connection and a helper would buy only the cost of a
process. The cost is real and is stated here rather than buried: the CA private
key is resident in the daemon's address space for the length of a mint, where a
PostgreSQL master never is. A memory-disclosure bug in the daemon therefore
exposes the CA key of any profile that minted during its life, and a CA key is
strictly more valuable than any credential it signs — it mints more of them.
Mitigations are the same as for every master: the session bounds how long it is
held, `just mem-hygiene` checks that it really goes, and the daemon is a small
program that parses nothing hostile.

Minted keys live in `$TMPDIR/briefcred-<mint id>/`, mode `0700`, key file
`0600`. A daemon killed mid-`exec` leaves one behind holding a usable key; the
reconciler sweeps directories whose certificate has expired, so the window is
bounded by `ttl_secs` rather than being unbounded, but it is not zero.

### MCP: the widest grant briefcred makes

`briefcred mcp` lets a model direct briefcred. That is a genuine expansion of
what the daemon will do at somebody else's request, and it should be adopted
deliberately.

What it does **not** do is hand out credentials. `briefcred_db_query` and
`briefcred_exec` are verbs: the credential is minted in the daemon, used there,
and revoked there, and there is no value for an agent to put in a transcript, a
context window, or a model provider's logs. Against the specific risk that
motivates briefcred — a credential outliving the task and spreading — the MCP
path is *stronger* than handing an agent a connection string, which is what
these tools replace.

What it does expand:

- **`briefcred_exec` runs commands chosen by a model.** The only thing standing
  between a prompt injection and an arbitrary command is the profile's
  `exec.allow_argv0` and `exec.allow_args`. On a profile reachable over MCP,
  those are not optional. An empty `allow_argv0` means "any program", which is
  the wrong answer here even though it is a reasonable default elsewhere.
- **`briefcred_db_query` runs SQL chosen by a model**, as the minted role. The
  role's grants are the only bound: a `role_template` granting `ALL` on
  everything means an agent can drop a table. Grant `SELECT`.
- **The unlock gate runs once per connection, not per call.** An agent that has
  been let in stays in for the life of the connection. That is the same bargain
  `unlock.cache_secs` already makes, made once and held for as long as the MCP
  client stays connected.
- **Output reaches the model.** Query rows and command output are returned by
  design, so a profile whose database contains secrets is a profile that can
  read them out to a model. briefcred caps the volume (1 MiB per stream, 100
  rows by default); it does not and cannot judge the content.

What is bounded:

- One connection binds to one profile and mints once. A tool call naming a
  second profile is refused.
- Closing the connection closes the session: the mints go on the revoke queue
  and the helper processes stop, whether the client exited cleanly or was
  killed.
- The socket is unchanged — mode `0600` in a `0700` directory, peer uid checked
  before the upgrade request is read. Only a process running as the same user
  can reach the MCP server, which is the same boundary `briefcred exec` has.
- Every call writes an `mcp_call` audit row with an `mcp_call_id`, the tool, the
  profile, the mints, and the outcome. The SQL and the command line are **not**
  recorded: they are exactly the free-form text the audit rules forbid, and a
  `briefcred_exec` writes the same `argv[0]`-plus-digests `exec_start` row every
  other exec does. A *failure* message is the subtle case, because a database's
  complaint quotes the statement and a refused command names the argument that
  was refused. Those go to the caller and not to the log: the row records the
  SQLSTATE, or that the exec policy refused `argv[0]`.
- One connection mints once, and the check and the mint happen under one lock,
  so two tool calls arriving together cannot each open a session and leave one
  of them with a live credential nothing closes.
- Resource use is bounded at both ends of every tool, and bounded at the
  *server* rather than by the daemon reading less than it asked for. `max_rows`
  is a portal row limit, so the database produces the rows requested and stops;
  `mcp_query_timeout_secs` is enforced as `statement_timeout`; and a command's
  output is read through a cap that kills the child rather than buffering what
  it sends. None of this makes a hostile prompt safe — it makes an expensive
  one bounded.
- `briefcred_db_query` runs in a transaction that is rolled back, so a model
  directing it cannot write whatever the minted role's grants allow. That is a
  smaller grant than the role itself carries, and it is the tool's stated
  contract rather than an accident of the portal it needs.
