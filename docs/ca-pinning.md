# Certificate pinning and briefcred

briefcred terminates TLS locally with its own root CA, so a client that
checks the certificate against the machine's trust store sees a valid chain
and works unchanged. A client that pins — that insists on a specific
certificate, key, or public CA regardless of what the machine trusts —
sees a certificate it does not recognise and refuses the connection.

That refusal is the intended outcome. briefcred never downgrades a pinning
client to plain HTTP, never disables its verification, and never retries
without the CA. **A pinning client fails loudly, and is out of scope.**

## What the failure looks like

The error comes from the client's own TLS stack, not from briefcred, so it
varies by ecosystem. These are the ones you are most likely to meet.

| Runtime | Message |
| --- | --- |
| Go `net/http` | `x509: certificate signed by unknown authority` |
| Python `requests` | `SSLCertVerificationError: unable to get local issuer certificate` |
| Node `fetch` / `https` | `UNABLE_TO_VERIFY_LEAF_SIGNATURE` or `SELF_SIGNED_CERT_IN_CHAIN` |
| `curl` | `SSL certificate problem: unable to get local issuer certificate` |
| Java | `PKIX path building failed: unable to find valid certification path` |
| gRPC (any language) | `failed to connect to all addresses ... certificate verify failed` |

If you see one of these under `briefcred exec`, work through
[Is it really pinning?](#is-it-really-pinning) before concluding the client
pins: the same messages appear when the CA is simply not trusted yet.

## Known offenders

These do not consult the system trust store, or consult it and then apply an
additional pin on top.

- **Pinned gRPC clients.** gRPC channels frequently ship with credentials
  built from a bundled root list. `grpc.ssl_target_name_override` and a
  custom `pem_root_certs` are the usual escape hatches, and both are a
  code change in the client.
- **Go binaries built with `CGO_ENABLED=0`.** These use Go's own certificate
  pool. They do read `SSL_CERT_FILE`, so briefcred's trust environment
  covers them; a Go binary that ignores that variable has an embedded pool
  and is genuinely pinned.
- **Mobile SDKs and their desktop test harnesses.** Android's network
  security config and iOS App Transport Security both support pinning, and
  vendor SDKs that ship a pinned certificate keep it when the same code is
  run on a laptop.
- **Package managers with vendored roots.** Some npm, pip, and Go module
  proxies bundle a CA list rather than reading the system store. Most
  honour `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, or `SSL_CERT_FILE`,
  which briefcred sets; the ones that do not are pinned in practice.
- **Electron apps and browsers with HPKP-style policies.** Chrome pins its
  own update and safe-browsing endpoints regardless of trust settings.
- **Anything using a hardcoded certificate fingerprint.** Some agents and
  CLI tools compare a SHA-256 fingerprint against a constant. Nothing
  briefcred can install will satisfy that.

## Is it really pinning?

Rule out the ordinary causes first. In order:

1. **Is the CA trusted at all?** Run `briefcred ca show`. If it says
   `trusted no`, add it with `briefcred install --trust-ca` and try again.
2. **Was the CA regenerated?** `briefcred ca regenerate` invalidates every
   certificate the old CA issued, and leaves the new one untrusted unless
   `--trust-ca` was passed. The fingerprint in `briefcred ca show` is the
   one that must be in the trust store.
3. **Does the runtime need its own variable?** briefcred sets
   `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`,
   `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE`, and `CURL_CA_BUNDLE`. If the profile
   has a `trust_env:` list, only the names it mentions are set — check
   whether the failing runtime's variable was left out.
4. **Does the same request work outside `briefcred exec`?** If it fails
   there too, the problem is not briefcred's CA.

If all four check out, the client pins.

## What to do about a pinning client

There is no briefcred-side fix, by design. The options, best first:

- **Leave it alone.** Run the pinning client outside `briefcred exec`. It
  keeps its own credentials and its own trust decisions, and briefcred
  brokers nothing for it.
- **Configure the client's own trust.** Where the client exposes a root
  list — gRPC's `pem_root_certs`, a language's certifi bundle, a JVM
  truststore — point it at `ca.pem`. `briefcred ca show` prints the path.
- **Do not disable verification.** Setting `GRPC_VERIFY_SERVER_CERT=0`,
  `NODE_TLS_REJECT_UNAUTHORIZED=0`, or `verify=False` turns a loud, correct
  failure into a silent acceptance of any certificate at all, including one
  briefcred did not issue. That is strictly worse than the problem.
