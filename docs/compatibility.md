# Runtime compatibility

briefcred reaches a subprocess through environment variables and nothing else.
Two sets of them, composed by the daemon and handed to the child by
`briefcred exec`:

| Set | Variables | What they do |
| --- | --- | --- |
| Trust | `AWS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE` | Point the runtime at briefcred's root CA, so the proxy's leaf certificates verify |
| Proxy | `ALL_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY` | Point the runtime's HTTP client at briefcred's loopback proxy |

A profile narrows the trust set with `trust_env`, and an explicit empty list
opts out of it entirely. The proxy set is written whenever the profile's
`proxy` mode says so.

So "does briefcred work with X" is really two questions about X: **does it
honour a CA environment variable**, and **does it honour a proxy environment
variable**. A runtime that answers no to either needs its own configuration,
and this page says which.

## How much of this is verified

**None of it is exercised by an automated test.** The end-to-end suite drives
the proxy with `hyper` and `rustls` clients, which is the right thing to test
the proxy with and says nothing about how Node resolves a CA bundle. The rows
below come from each runtime's own documentation and from manual checks. Treat
a row as a starting point, not as a guarantee, and check the "how to verify"
line before trusting one in production.

Verifying a runtime by hand takes one command:

```sh
briefcred exec --profile <name> -- <runtime> <something that makes one HTTPS request>
```

A working setup shows the request in `briefcred audit --since 5m` with
`decision: allow`. A CA problem shows as a TLS verification error in the
subprocess. A proxy problem shows as no audit row at all, because the request
never reached briefcred.

## The matrix

| Runtime | Trust variable it honours | Proxy variables it honours | Verdict |
| --- | --- | --- | --- |
| **curl** | `CURL_CA_BUNDLE`, `SSL_CERT_FILE` | `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` | Works with no configuration |
| **Python** (`requests`) | `REQUESTS_CA_BUNDLE` | `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | Works with no configuration |
| **Python** (`httpx`, `urllib`, stdlib `ssl`) | `SSL_CERT_FILE` | `HTTPS_PROXY`, `HTTP_PROXY` | Works with no configuration |
| **AWS CLI** / boto3 | `AWS_CA_BUNDLE` | `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | Works with no configuration |
| **Go** (`net/http`) | *see below* | `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | Proxy works; CA needs the system trust store |
| **gh** (Go) | *as Go* | `HTTPS_PROXY`, `HTTP_PROXY` | As Go |
| **Rust** (`reqwest` with native roots) | system trust store, `SSL_CERT_FILE` | `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` | Works; see the pinning note |
| **Ruby** (`Net::HTTP`, OpenSSL) | `SSL_CERT_FILE` | lowercase `http_proxy` / `https_proxy` | See below |
| **Node** | `NODE_EXTRA_CA_CERTS` | *none by default* | Needs help. See below |
| **opencode** (Bun) | `NODE_EXTRA_CA_CERTS` | `HTTPS_PROXY`, `https_proxy`, `NO_PROXY` | Works; its stored key must go. See below |
| **gcloud** | *its own bundled CA* | `HTTPS_PROXY` | Needs help. See below |
| **psql** | `PGSSLROOTCERT` | not applicable | Does not use the HTTP proxy at all |

## The offenders, and what to do about each

### Node ignores the proxy variables

This is the one that surprises people. Node's built-in HTTP client and `fetch`
have historically ignored `HTTPS_PROXY` entirely: the variables are a
convention of curl and of the libraries that copied it, not of the platform.
An agent written against `fetch` will send its request straight past briefcred,
get a `403` from the vendor because it is holding a synthetic token, and
produce no audit row at all — which is the signature of this problem.

This is Node's behaviour, not every JavaScript runtime's. Bun's `fetch` reads
the proxy variables, so a Bun-based agent can go through briefcred without
help. That was checked through opencode, which is built on Bun; see below.

What works:

- Recent Node versions accept an opt-in flag for reading proxy environment
  variables. Check `node --help | grep -i proxy` on the version in use before
  assuming it is there.
- Otherwise set an explicit dispatcher or agent in the program: `undici`'s
  `ProxyAgent`, or `https-proxy-agent` for the older client.
- The CA half is fine: `NODE_EXTRA_CA_CERTS` is honoured, and it *adds* to the
  bundled roots rather than replacing them, so the subprocess keeps working
  against everything else.

### opencode prefers its own stored key

Checked by hand on 2026-10-18 with opencode 1.18.35 (built on Bun 1.3.14) on
macOS, against an OpenAI-compatible provider (`@ai-sdk/openai-compatible`)
whose key comes from an environment variable.

opencode's model requests honour `HTTPS_PROXY` (and lowercase `https_proxy`,
and `NO_PROXY`), and its TLS honours `NODE_EXTRA_CA_CERTS`, so
`briefcred exec -- opencode` goes through the proxy with no plugin and no
wrapper. The provider's address can be a hostname or an IP address; both went
through the proxy.

The configuration that works names the variable in the provider and lets the
profile fill it, here from a credential named `gateway`:

```json
"provider": {
  "my-gateway": {
    "npm": "@ai-sdk/openai-compatible",
    "env": ["MY_GATEWAY_KEY"],
    "options": { "baseURL": "https://gateway.example.com/v1" },
    "models": { "my-model": {} }
  }
}
```

```yaml
env:
  MY_GATEWAY_KEY: ${minted.gateway.TOKEN}
```

What to know:

- **A key saved with `/connect` wins over the environment.** opencode stores
  that key in `~/.local/share/opencode/auth.json` and uses it before the
  variables in the provider's `env` list. Left there, it is what opencode
  sends, and the proxy, finding no briefcred token in the request, refuses it:
  opencode shows "Proxy Authentication Required" and the audit log shows
  `proxy_token_rejected … reason=missing`. That fails closed, but the real key
  is still on disk. Remove it first with `opencode auth logout <provider-id>`.
- **The policy sees the host as the configuration writes it.** A `baseURL` of
  `https://127.0.0.1:8443/v1` arrives as host `127.0.0.1`, and a policy that
  permits `localhost` denies it. Write the policy's `resource.host` to match
  the `baseURL` exactly.
- **opencode's own background requests are refused.** At startup it fetches its
  model catalogue from `models.opencode.ai` and looks up packages on
  `registry.npmjs.org`. They carry no briefcred token, so each is refused and
  logged as `proxy_token_rejected … reason=missing`. opencode carries on
  without them, so the rows are expected and harmless.
- **`OPENCODE_*` variables do not reach it unless the profile passes them.**
  `briefcred exec` starts the child with an empty environment plus `PATH`,
  `HOME`, `TERM`, `LANG`, `TMPDIR`, the profile's `env_passthrough` and its
  `env`. A profile written by `briefcred profile bootstrap` has no
  `env_passthrough`. Put settings in `opencode.json` instead (for example
  `"autoupdate": false`, `"share": "disabled"`, `"lsp": false`), or name the
  variables in `env_passthrough`.
- **`opencode run` from a script wants `</dev/null`.** `briefcred exec` passes
  its own standard input to the child. When that is a pipe that stays open, as
  it can be in a script, a CI job or another agent's shell, `opencode run`
  waits for it to close, and under `briefcred exec` it sent nothing until it
  did.
  From a terminal, and in the interactive interface, this does not come up.

How to verify:

```sh
opencode auth logout <provider-id>
briefcred exec --profile <name> -- opencode run "Reply with OK" </dev/null
briefcred audit --since 5m
```

A working setup shows `proxy_request … POST <host>/v1/chat/completions allow
status=200`; each prompt made two such requests in these checks.

### Go does not read `SSL_CERT_FILE` on macOS

`crypto/x509` reads `SSL_CERT_FILE` and `SSL_CERT_DIR` on Unix, but on Darwin
it loads roots from the system trust store instead, and the environment
variable is not consulted. So a Go program under `briefcred exec` on macOS will
reject the proxy's certificate however the trust variables are set.

The fix is the one briefcred already recommends for other reasons:

```sh
briefcred install --trust-ca
```

which puts the root CA in the system trust store. Do that once and every Go
binary — `gh` included — works. This is why the CA install is not optional on
macOS even though six environment variables point at the same file.

### gcloud brings its own CA bundle

The Google Cloud SDK ships and uses its own root bundle and does not read the
generic trust variables. Point it at briefcred's CA explicitly:

```sh
gcloud config set core/custom_ca_certs_file \
  "$HOME/Library/Application Support/briefcred/ca/ca.pem"
```

The proxy half works: `HTTPS_PROXY` is honoured.

### Ruby wants the lowercase names

`URI::Generic#find_proxy`, which `Net::HTTP` uses, reads the lowercase
`http_proxy` and `https_proxy`, and deliberately ignores the uppercase
`HTTP_PROXY` in a CGI-like environment. briefcred sets the uppercase names,
which is the convention every other runtime here follows.

If a Ruby subprocess is not routing through the proxy, add the lowercase pair
to the profile's `env`. Every `http-*` credential publishes a `PROXY_URL`
field, so the value is already to hand:

```yaml
env:
  http_proxy: ${minted.openai.PROXY_URL}
  https_proxy: ${minted.openai.PROXY_URL}
```

### Pinned certificates defeat all of this

Any client that pins a certificate or a public key — rather than verifying
against a trust store — will refuse the proxy's leaf no matter what is
configured, because refusing exactly this is what pinning is for. A Rust client
built with `webpki-roots` compiled in rather than `rustls-native-certs` behaves
the same way: it has no trust store to add a root to.

There is no workaround, and there should not be one. Such a client wants a
Model B credential instead: give it a minted credential it can hold
(`postgres-dynamic`, `aws-sts`) rather than a synthetic token it can never use.
briefcred ships no Model C, so that is the whole of the alternative.

### psql does not go through the HTTP proxy

PostgreSQL is not HTTP, and the `postgres-proxy` kind is served by briefcred's
own PostgreSQL listener on its own port. `psql` gets a `DATABASE_URL` pointing
at that port and a synthetic token as its password; the trust and proxy
variables are irrelevant to it. What matters instead is `PGSSLROOTCERT` when
the connection to the proxy is itself TLS.

The `postgres-dynamic` kind is simpler still: `psql` gets a real role's
credentials in `PGUSER` and `PGPASSWORD` and connects to the real server.

## Adding a runtime to this page

The bar is one verified round trip, by hand, with the exact command in the
"how to verify" form above, and an honest note about anything that had to be
configured. A row asserting that something works because its documentation says
the variable exists is worth less than no row at all.
