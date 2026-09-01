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

**Phase 0 (this task).** A library, no daemon, no privilege boundary. The
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
- **Not tamper-evident.** A user who can write the log can rewrite it. Signing
  or an append-only system store is deliberately out of scope for now, and this
  line should be revisited before anyone treats the log as compliance evidence.

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
