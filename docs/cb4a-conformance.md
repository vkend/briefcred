# CB4A conformance statement

*Credential Binding for Agents* (CB4A) is an Internet-Draft describing how an
agent should be given a credential it cannot exfiltrate. This page says which
of its models each briefcred credential kind implements, and where briefcred is
weaker than the draft would like.

## Standing of the draft

CB4A is at **draft -00**. It has no working-group adoption and the current
revision **expires 2026-09-30**. Nothing here should be read as conformance to
a ratified standard, because there is no standard yet. What this page is for is
narrower and more useful: it fixes a vocabulary for describing how much of a
credential a subprocess can see, so a claim like "the agent never holds the
key" can be checked rather than believed.

Track the draft for revisions. If the models are renumbered, this page and the
table in `ARCHITECTURE.md` are the two places that have to move.

## The three models

| Model | What the subprocess holds | What an attacker with full read of the subprocess gets |
| --- | --- | --- |
| **A** | A synthetic token bound to one session. The real credential never leaves the daemon. | A token that expires with the session, is refused outside the profile's policy, and buys nothing at the vendor directly. |
| **B** | A real backend credential, minted for this run and revoked after it. | A working credential, with the privileges of the minted principal, until it expires or is revoked. |
| **C** | The real long-lived credential. | Everything. |

Model C is a stepping stone and briefcred ships none of it: every credential
kind below is A or B.

## Per credential kind

| `kind` | Model | What the subprocess actually gets | Where the real credential is |
| --- | --- | --- | --- |
| `http-bearer` | **A** | `bc.<payload>.<sig>`, a signed synthetic token | In the daemon; the HTTP proxy swaps it into `Authorization` |
| `http-header` | **A** | The same synthetic token | In the daemon; swapped into the configured header |
| `http-basic` | **A** | The same synthetic token | In the daemon; swapped into `Authorization: Basic` |
| `postgres-proxy` | **A** | The same synthetic token, as a password to briefcred's Postgres proxy | In the daemon, which completes the real authentication handshake itself |
| `postgres-dynamic` | **B** | A real PostgreSQL role, created for this session with `VALID UNTIL` and the profile's grants | The master with `CREATEROLE` never leaves the helper process |
| `aws-sts` | **B** | Real STS session credentials from `AssumeRole`, with the profile's inline session policy | The master keys never leave the helper process |
| `ssh-cert` | **B** | A real OpenSSH certificate and its key, valid for the profile's principals and TTL | The CA private key never leaves the daemon |

The two Postgres kinds are alternatives rather than a migration.
`postgres-dynamic` is the stronger answer where the master has `CREATEROLE`,
because the credential the subprocess holds is revocable at the backend
independently of briefcred. `postgres-proxy` is for the databases where that is
impossible, and buys a Model A handoff at the cost of every connection
depending on a live daemon.

## Why Model B is not Model A for the minters

A Model A handoff needs a proxy that speaks the backend's wire protocol, so
that briefcred can hold the credential and attach it per request. briefcred has
two such proxies — HTTP and PostgreSQL — and the credential kinds served by
them are Model A. `aws-sts` and `ssh-cert` are Model B because there is no
equivalent chokepoint:

- **AWS.** SigV4 signs the request with the secret key, so a proxy that wanted
  to attach the credential would have to re-sign every request, which means
  parsing and canonicalising traffic for the entire AWS API surface. The
  bounded thing to do instead is bound the credential: a session with a
  short TTL, an inline session policy, and a revoke on close.
- **SSH.** The client authenticates with a challenge signed by the private key
  during the transport handshake, before there is a session anything could be
  swapped into. What briefcred bounds is the certificate: short validity,
  named principals, and a revocation list.

Both are recorded as residual exposure in `THREAT_MODEL.md` rather than
presented as equivalent to the proxy paths.

## Proof of possession: DPoP

The synthetic token carries a `cnf` claim:

```json
{ "sid": "…", "cred": "openai", "iat": 1, "exp": 901, "cnf": { "jkt": "…" } }
```

`cnf.jkt` is the SHA-256 thumbprint of a per-session Ed25519 key the CLI
generates and keeps out of the subprocess's environment.

**Implemented.** A client that holds the session key sends a `DPoP` header and
the proxy verifies it: the proof must be a compact JWS signed with EdDSA by the
key the token names, must cover this request's method and URL, and must be no
more than five minutes old.

**Optional, and that is the honest limit.** A client whose only channel is
`OPENAI_API_KEY=<token>` in its environment — which is most of them, and every
off-the-shelf SDK — cannot send a proof, so it sends the token bare and the
proxy accepts it. On that path the synthetic token is a bearer credential.

What the binding buys today is that a token stolen from one session's
environment cannot be *upgraded*: a client that does present a proof must
present the right one, so the proof path cannot be used to launder a stolen
token into a stronger one. Making DPoP mandatory would mean making briefcred
work only with clients written for it, which would trade the whole point of the
placeholder swap for a property most deployments cannot use.

`THREAT_MODEL.md` states this exposure directly rather than in a footnote.

## What briefcred adds beyond the models

The models describe the handoff. Two of briefcred's properties are about what
happens after it, and CB4A has no vocabulary for either:

- **Policy at the chokepoint.** Every Model A request is decided by the
  profile's Cedar policy before the credential is attached, so a stolen token
  is bounded by method, host, path and time window as well as by expiry.
- **The audit row.** Every mint, every proxied request, every Postgres
  connection and every revoke is one metadata-only JSONL row. A credential that
  was used is a credential somebody can account for.
