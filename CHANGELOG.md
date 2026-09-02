# Changelog

All notable changes to briefcred are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Fixed

- **The hook no longer auto-approves a compound command.** An `allow` rule with
  `rewrite: true` answered `allow` for `psql … | tee /etc/passwd`, wrapping the
  whole line in a `briefcred exec` on the strength of a policy check that had
  only seen the words. It now answers `ask` for any line containing `|`, `;`,
  `&&`, `||`, `>`, `<`, `$(` or a backtick, and rewrites nothing.

- **Placeholder substitution is bounded by what the run minted.** The proxy
  filled in a `__name__` placeholder for every HTTP credential the profile
  declared, so a `briefcred exec --cred openai` could still have a second
  credential's key swapped into a header. It now substitutes only credentials
  this exec actually minted.

- **`proxy: always` works on a profile with no credentials.** The proxy refuses
  a request with no token, so a profile whose only value was its Cedar policy
  pointed its subprocess at a proxy that answered `407` to everything. `exec`
  now issues a policy-only token for such a profile and publishes it as
  `BRIEFCRED_PROXY_TOKEN`. It names no credential, substitutes nothing, and
  exists so the request can be attributed to a session and decided by its
  policy. Hop-by-hop `Proxy-Authorization` and `Proxy-Connection` headers are
  now stripped before the swap rather than after, so a token presented the way
  a client naturally presents one to a proxy is not mistaken for a leak.

- **A handoff proves presence and checks its socket path.** `briefcred daemon
  upgrade` exported every resident master to whatever socket the caller named,
  with no unlock prompt. It now runs the unlock gate at the strictest
  `unlock.policy` among the open sessions, with the reason "daemon upgrade",
  and refuses a socket path that is not directly inside briefcred's own state
  directory.

- **Idle eviction now counts proxied and MCP use.** A session's idle timer
  was only reset by a request on the daemon's own socket, so an agent doing all
  its work through the HTTP proxy, the Postgres proxy, or an MCP tool call had
  its masters wiped out from under a run that had never stopped. All three
  paths now mark the session as used.

### Added

- **TLS on the Postgres proxy's upstream connection.** The daemon now sends
  PostgreSQL's `SSLRequest` before the startup packet and refuses the
  connection if the server will not encrypt it, so the master password no
  longer crosses the network on a plaintext socket. A `postgres-proxy`
  credential takes an `sslmode` of `require` (the default), `verify-full`
  (chain and hostname verified against the system trust store), or `disable`.
  There is no `prefer` or `allow`: a mode that silently falls back to plaintext
  is a mode whose security nobody checks.

- **A supply-chain gate in `just check`.** `deny.toml` allows permissive
  licences only, refuses any source but crates.io, treats an open advisory as
  an error, and sets `unmaintained = "all"` so a transitive unmaintained crate
  is reported and not only a direct one. `cargo vet check --locked --frozen`
  runs offline against `supply-chain/`, which imports no third-party audit
  sets: the whole graph sits in `exemptions`, so adding a dependency produces a
  diff somebody has to look at. Install both with
  `cargo install cargo-deny cargo-vet --locked`.
- **Continuous integration.** `.github/workflows/ci.yml` runs `rustfmt`,
  `clippy` on macOS and Linux, the two supply-chain gates, and the test suite
  against PostgreSQL 16 and 18 on Linux and 16 on macOS. The PG18 half is the
  matrix Phase 0 specified and nothing had run since. The jobs install the
  PostgreSQL *server* binaries and set `BRIEFCRED_PG_BIN`, because the harness
  brings up its own throwaway cluster rather than connecting to one.
- **A release pipeline.** A `v*` tag builds every binary for both macOS
  architectures, joins each pair with `lipo`, signs and notarises them when the
  `APPLE_*` secrets exist, and publishes a tarball with its SHA-256 sum. With
  no Apple credentials it publishes an unsigned tarball and says so in the
  release notes, so a release is not something only one person can cut. The
  steps are plain scripts under `release/scripts/`.
- **The release workflow stamps the Homebrew formula.** The formula in the tree
  carries a placeholder checksum, because the checksum of a release that has
  not been built yet does not exist. `release/scripts/stamp-formula.sh` rewrites
  its `url` and `sha256` from the tarball just built and the workflow uploads
  the result as a release asset named `briefcred.rb`. Copying that into the tap
  is manual and deliberately so: the tap is a separate repository created out
  of band, and the release workflow holds no token for it. A test asserts the
  stamp changes exactly those two lines and leaves every other byte alone.
- **A Homebrew formula**, `release/Formula/briefcred.rb`. It installs all five
  binaries — a formula that shipped only `briefcred` and `briefcred-daemon`
  would produce a broker that starts and cannot mint — and carries a `service`
  block so `brew services start briefcred` runs the daemon as a LaunchAgent.
- **`briefcred profile schema`**, which prints the profile schema as a JSON
  Schema document generated by `schemars` from the same types the loader
  deserialises into. `docs/profile-schema.md` is that output with prose around
  it, and a test fails if the two disagree.
- **`docs/compatibility.md`**, a runtime matrix: which of the six CA
  environment variables and three proxy variables each of Node, Python, Go,
  Rust, Ruby, the AWS CLI, gcloud, gh, psql and curl honours, and what to do
  about the ones that honour neither. It says plainly that no row is covered by
  an automated test.
- **`docs/cb4a-conformance.md`**, mapping every credential kind to Model A, B
  or C and stating the DPoP position: the binding is implemented and optional,
  and a token sent without a proof is a bearer credential.
- **`handing_over` on `Response::Status`**, and in `briefcred daemon status`
  output. A daemon in the middle of a handoff refuses the requests that would
  create something its successor will not inherit, and can now be asked what
  state it is in rather than having it inferred from a refusal.
- **HTTP/2 and gRPC through the HTTP proxy**, and with it Phase 9 of the
  roadmap. The client-facing side of a `CONNECT` tunnel advertises ALPN `h2`
  and `http/1.1`; a client that picks `h2` is served by `hyper`'s HTTP/2 server
  over the same request pipeline, one call per stream. Plain `http://`
  absolute-URI requests and WebSocket handshakes stay HTTP/1.1.
- **The upstream negotiates separately.** An HTTP/2 client whose vendor speaks
  only HTTP/1.1 is forwarded either way, and so is the reverse. An HTTP/2
  upstream connection is kept and multiplexed, keyed on
  `(session, credential, host, port)` so two sessions holding two different
  masters can never share one; HTTP/1.1 upstreams are still a connection per
  request. Connection-specific headers an HTTP/1.1 client may send are stripped
  when a request crosses to an HTTP/2 upstream, except `te`, which gRPC needs.
- **gRPC works with nothing gRPC-specific in the proxy.** Bodies are never
  buffered and trailers are relayed as frames, so all four call shapes — unary,
  server-streaming, client-streaming, bidirectional — work, and `grpc-status`
  and `grpc-message` reach the client unread. A gRPC call is a `POST` whose
  path is the service and method, so a Cedar policy names it like anything
  else, per stream.
- **A gRPC call does not outlive its grant.** Every HTTP/2 response whose length
  the upstream did not state is watched by the same one-second liveness poll an
  event stream gets, so expiry, revocation, or the session closing ends a
  server-streaming or bidirectional call within about a second and writes a
  `proxy_stream` row of kind `h2-stream`. Nothing inside such a body is parsed,
  so its `events_or_frames` is `0`.
- **Upstream dials are bounded and isolated.** A ten-second deadline covers TCP
  and TLS together, and dialling is serialised per destination rather than
  globally, so a host that never answers delays only the requests headed for it.
  A cached upstream connection is dropped when its grant is revoked or its
  session closes, rather than lingering until a later dial notices.
- **A gRPC call to an upstream that does not speak HTTP/2** is refused with
  `upstream_error` and a reason, rather than downgraded to HTTP/1.1 and turned
  into a response the client cannot parse.
- **A `proxy_h2_connection` audit row** when a client's HTTP/2 connection
  closes, carrying the connection's shape — streams, duration, bytes each way —
  and nothing from any stream's headers, body, or trailers. Every
  `proxy_request` and `proxy_stream` row from that connection gains a
  `connection_id` naming it, so a hundred rows read back as the one connection
  they were. New metrics `briefcred_proxy_h2_connections_total` and
  `briefcred_proxy_h2_streams_total`.

- **Zero-downtime upgrade**, and with it Phase 7 of the roadmap.
  `briefcred daemon upgrade [--binary <path>]` replaces the running daemon
  without closing a socket. The CLI starts the new binary with
  `--takeover <socket>`; the old daemon passes it the four listening
  descriptors — IPC, metrics, HTTP proxy, Postgres proxy — over `SCM_RIGHTS`
  together with a signed blob of every open session, and stands down only once
  the new daemon has confirmed it is serving. The Unix socket travels as a
  descriptor rather than being unlinked and rebound, so a client connecting
  during the swap is never told "no such file", and the ports do not move.
- **Masters cross the handoff encrypted to the daemon taking over.** The new
  daemon generates an ephemeral X25519 key pair when it binds the takeover
  socket and advertises the public half; each master is sealed with
  ChaCha20-Poly1305 under a key agreed against it, with a fresh nonce per
  master. No plaintext master, token, or signing key is written anywhere during
  a handoff: the blob exists in memory, crosses a `0600` socket in a `0700`
  directory, and is dropped.
- **The blob is signed with the machine's token-signer key** — the same Ed25519
  key the proxy signs synthetic tokens with — and the signature is checked
  before the JSON is parsed. A same-uid process can connect to the takeover
  socket, but it cannot produce a blob the new daemon will adopt without first
  reading a key out of the login keychain.
- **A session survives the upgrade whole.** Its identifier, profile, age, mints,
  quota position, HTTP counters and per-session public key all move across, so a
  client's handle keeps working, the idle timer resumes where it left off, and
  neither a quota nor a `context.resp_bytes_so_far` budget is refilled by an
  upgrade. The proxy's revocation set moves too, so the new daemon does not
  start serving grants the old one had already retired.
- **In-flight work is drained rather than cut.** The outgoing daemon stops
  accepting and then waits for the requests and streams it was already serving —
  including the ones inside a `CONNECT` tunnel and a relayed WebSocket, which
  outlive the connection future that produced them — bounded by the new
  `handoff_drain_secs`, thirty seconds by default. Its sessions are wiped
  without being revoked: the daemon that took them over is holding them, and
  queueing their revokes would kill credentials it is still serving.
- **`briefcred_handoffs_total{outcome}`**, with `handed_over`, `adopted` and
  `failed` seeded at zero, and a **`daemon_handoff` audit row** written by both
  daemons, so the log shows which process was serving at any moment. A session
  that moved closes with reason `handoff` rather than `shutdown`.
- **systemd socket activation on Linux.** `briefcred install` now writes a
  `briefcred.socket` unit alongside the service unit, and the daemon honours
  `LISTEN_FDS` for its initial bind — but only when `LISTEN_PID` names its own
  process, so an inherited environment cannot make it adopt descriptors meant
  for something else. The unit's `ListenStream=` order and the daemon's
  adoption order are one fact written in two places, and both are snapshot- and
  unit-tested.
- **New work is refused for the length of a handoff.** The daemon being
  replaced goes on accepting IPC until the new one is serving, and a session
  opened in that window would reach no blob and be adopted by nobody — so a
  credential minted against it would be one neither daemon holds a revoke for.
  `open_session`, `exec` and MCP tool calls that mint are answered "the daemon
  is handing off to a new one; retry" instead, and the retry lands on the new
  daemon. On the way out the old daemon retires anything it is still holding
  that the blob did not carry, and releases without revoking only what actually
  moved. Two concurrent `Handoff` requests are settled by a compare-exchange:
  exactly one proceeds, the other is refused.
- **A handoff blob names the daemon it was built for and when.** The
  recipient's ephemeral public key is echoed inside the signature and checked
  before a master is opened, and a blob more than two minutes from the
  receiver's clock is refused. Neither keeps the masters secret — the key
  agreement does that — but together they stop a blob captured off a socket
  being presented to a later daemon as though it were current.
- **`docs/upgrade.md`**: the whole sequence, what an upgrade does and does not
  guarantee, what happens when it fails, and how the launchd and systemd units
  fit around a process the service manager did not start.

- **Streaming through the HTTP proxy**, and with it Phase 6 of the roadmap.
  Server-sent events and WebSocket now cross the proxy, and both go through the
  same checks as any other request first — the token, the quota, and the Cedar
  policy all decide a stream before a byte of it exists.
- **Server-sent events** are forwarded chunk by chunk as the upstream produces
  them, with nothing collected: an event reaches the subprocess when it is sent,
  keep-alive comments pass through untouched, and an upstream close closes the
  client's stream. Any `Content-Length` the upstream put on an event stream is
  dropped, because a body that ends when its upstream ends has no length to
  state in advance. Events are counted by a line scanner that never holds more
  than the first five bytes of the line it is reading.
- **WebSocket.** A request carrying `Upgrade: websocket` and `Connection:
  Upgrade` is decided by the policy as the `GET` it is, so a profile that does
  not permit the handshake's path does not get a WebSocket. briefcred forwards
  the client's own `Sec-WebSocket-Key` and refuses to relay unless the
  upstream's `101` carries the `Sec-WebSocket-Accept` derived from it; after
  that both halves are byte-forwarded, with frame headers parsed for the count
  and payloads never unmasked or inspected.
- **A `proxy_stream` audit row** when a stream closes, alongside the
  `proxy_request` row for the response or `101` that opened it: kind, host,
  path, start, end, `events_or_frames`, and bytes in each direction. It counts
  framing only, so no event's data and no frame's payload can reach it.
- **`briefcred_proxy_streams_total{kind}`** and
  **`briefcred_proxy_stream_duration_seconds{kind}`**, both labelled `sse` or
  `ws` and both seeded at zero. The duration histogram has bucket bounds of its
  own, from a second to two hours: a stream is not a latency, and on the request
  scale every one of them would land in `+Inf`.
- **A stream does not outlive its grant.** The same one-second liveness poll the
  Postgres proxy runs on a live connection now runs for as long as a stream is
  open, and ends both halves on expiry, revocation, or the session closing.
- **A WebSocket spends the session's byte budget while it is open.** Bytes going
  towards the client are added to the session's running total once a second or
  every 64 KiB, so a Cedar `context.resp_bytes_so_far` cannot be stepped around
  by asking for a socket instead of a response.
- **A new `bad_request` decision** on `proxy_request` rows and
  `briefcred_proxy_requests_total`, for a request briefcred could not act on —
  today, a WebSocket handshake with no `Sec-WebSocket-Key`. Kept out of `deny`
  because nothing refused it: the policy was never asked, and a client's own bug
  does not belong in the series an operator reads to find a narrow profile.
- **Signed profile distribution**, and with it Phase 8 of the roadmap. A
  profile fetched from somewhere else names the hosts a subprocess may reach
  and the credentials briefcred will mint, so briefcred now keeps two kinds of
  profile apart: `profiles/*.yaml` are yours and need no vouching, while
  `profiles/registry/<name>/*.yaml` are **dropped unless a detached signature
  beside them verifies against a trust root**. The format is minisign's,
  unmodified — `<file>.minisig`, plus a second signature over the trusted
  comment. briefcred verifies both minisign signature forms, the legacy `Ed`
  over the file's bytes and the prehashed `ED` over BLAKE2b-512 of it, which is
  what stock `minisign -S` writes by default; it only ever produces `Ed`, so a
  briefcred signature verifies under every minisign release. Password-less
  minisign secret keys are read as they are written, all-zero checksum
  included. All three directions are covered by tests that run when `minisign`
  is installed and skip with a reason when it is not.
- **`daemon.toml` gains a `[profiles]` table**: `trust_roots` (minisign public
  key lines), `registries` (`{ name, url }`), and `dev_mode`. A trust root that
  is not a well-formed key stops the daemon starting rather than being silently
  ignored, and an empty `trust_roots` means no registry profile can load — it
  never means "trust everything".
- **`briefcred profile sync`** fetches each registry into
  `profiles/registry/<name>/`, verifying as it goes. Three URL schemes and no
  others: `file://` for a directory, `https://` for an `index.json` whose
  SHA-256 is checked before the signature, and `git+https://` for a shallow
  clone through the system `git`. Each fetch lands in a staging directory and is
  moved into place at the end, so a failed sync leaves the previous contents
  rather than a mix of two, and a withdrawn profile really does disappear — but
  a fetch that produced *no* profiles will not replace a registry that
  currently has some, because that is evidence of a bad URL rather than of a
  publisher who withdrew everything. One unreachable registry never stops the
  others; the exit code is non-zero if any file was skipped.
- **`briefcred profile keygen`, `sign`, and `verify`.** `keygen --out <dir>`
  writes `briefcred.key` (mode `0600`, password-less, and the command says so)
  and `briefcred.pub`, and prints the line to paste into `trust_roots`. Signing
  puts the file's name in the trusted comment, which the second signature
  covers, so a signature moved onto another profile still names the file it was
  made for.
- **Provenance on every profile.** `briefcred profiles` gains `SOURCE` and
  `SIGNATURE` columns, and `briefcred profile show` prints where a profile came
  from, the file it was read from, what its signature was worth, which key
  vouched for it, and what it overrides. A local profile of the same name overrides a registry one, which is
  what makes a registry usable: take the set somebody publishes and change the
  one profile you need to.
- **A `profile_trust_warning` audit row** per file that failed verification,
  with `action` of `dropped` or `loaded_dev_mode` and the file's path. Under
  `dev_mode` an unverified profile loads, and pays for it with a
  `!! PROFILE NOT VERIFIED` line on every daemon start, a banner above
  `briefcred profiles`, and one of those rows per file — because the thing that
  must survive running an unverified profile is the ability to establish
  afterwards which ones ran.
- `docs/profile-distribution.md`, covering the signature format, publishing, the
  three URL schemes, precedence, and what `dev_mode` costs.
- **Per-session quotas**, and with them Phase 5 of the roadmap. A profile may
  set `quota: { rate, burst, total }` — a token bucket, in tokens per second,
  where `rate` may be fractional and `total` is an optional hard cap for the
  whole session. One token is spent per HTTP proxy request, per Postgres proxy
  connection, per `briefcred exec` or `briefcred get` that mints, and per
  `briefcred_db_query` or `briefcred_exec` MCP tool call — an MCP call uses a
  credential inside the daemon rather than handing one to a subprocess, so
  without a charge of its own it would be the one unmetered way to spend a
  metered profile. The bucket is built when the session opens and dies with it,
  so two concurrent runs of one profile get a budget each rather than competing
  for one, and nothing survives a daemon restart. `rate` must be positive and `burst` at least 1, and
  both are checked when the profile is loaded.
- **What a throttled client is told.** The HTTP proxy answers `429` with
  `{"error":"briefcred quota exceeded"}` and a `Retry-After` header, and audits
  the request as `decision: "quota"`. The Postgres proxy refuses the connection
  with SQLSTATE `53300` (`too_many_connections`) *before* it opens an upstream
  one, so the database never sees a login the client did not get.
  `briefcred exec` and the MCP tools fail with an error naming the profile and
  how long to wait. A spent `total` gets no `Retry-After`, because no wait would
  help. `policy_mode: observe` does not soften a quota refusal: observe mode is
  for trialling a rule, and a quota is a resource bound rather than a rule.
- **The quota is charged before the policy is evaluated**, so a request the
  policy denies still costs a token. The expensive thing to defend against is a
  loop, and a loop that is being denied is still a loop — one that would
  otherwise get an unmetered retry channel precisely because it is doing
  something the profile forbids.
- **Two metrics series**: `briefcred_quota_saturation{profile}`, a gauge from 0
  for an untouched bucket to 1 for an empty one, updated on every charge and
  pinned at exactly 1 by a refusal so `== 1` is an alert expression that works;
  and `briefcred_quota_rejections_total{profile,surface}` with `surface` one of
  `http`, `postgres`, `exec`, `mcp`. The gauge is deliberately unseeded: a series that
  exists is a profile somebody metered.
- **A Cedar request context.** `Http` requests now carry
  `context: { hour, weekday, resp_bytes_so_far, requests_so_far }`, all `Long`.
  `hour` and `weekday` are UTC and cannot be configured otherwise; both counters
  report what the session did *before* the request being decided, so
  `context.requests_so_far < 100` permits exactly a hundred. This is what lets a
  policy express a time window or a per-session budget, which a vocabulary of
  method, host and path cannot. A policy naming an attribute the context lacks
  is still rejected when the profile loads.
- **`docs/policy-cookbook.md`**: five worked policies — method × path, a time
  window, a per-session cap, a byte budget, and combining a policy with a quota
  — with a section on telling a policy limit from a quota. Every Cedar block in
  it appears verbatim in a profile under `examples/profiles/`, and a test fails
  if one drifts.
- **Four example profiles carrying those recipes**: `anthropic.yaml`,
  `github.yaml` and `stripe.yaml` are new, and `openai.yaml` was rewritten to
  match. Every example is loaded, validated, and its policy compiled against the
  Cedar schema by `crates/briefcred-core/tests/example_profiles.rs`.

- **The Postgres connection-auth proxy** (`briefcred-daemon::pgproxy`), and with
  it Phase 10 of the roadmap. A listener on `127.0.0.1:9319` speaks the
  PostgreSQL v3 protocol to the wrapped subprocess, authenticates it with a
  synthetic token, then opens its own connection to the real server and
  authenticates *that* with the master over SCRAM-SHA-256. Only once the
  upstream connection exists is the client told it is in; the server's own
  `ParameterStatus`, `BackendKeyData` and `ReadyForQuery` are relayed verbatim,
  and after that bytes are copied both ways through a fixed buffer and counted,
  never parsed.
- **The `postgres-proxy` credential kind**, `config: { host, port, dbname,
  user }`. This is Model A for PostgreSQL: the subprocess holds no password at
  all, and the master — the password of the `user` in the config — stays in the
  daemon. The mint publishes six fields: `DATABASE_URL`
  (`postgresql://<session>:<token>@127.0.0.1:9319/<dbname>`), `PGHOST`,
  `PGPORT`, `PGDATABASE`, `PGUSER` (the session id) and `PGPASSWORD` (the
  token). `postgres-dynamic` is unchanged and is still the better answer where
  the master has `CREATEROLE`.
- **An in-crate SCRAM-SHA-256 client** (`pgproxy::scram`), checked against the
  RFC 7677 test vector. It verifies the server's signature before believing
  anything the server says, refuses `SCRAM-SHA-256-PLUS` rather than downgrading
  to the unbound mechanism, and refuses a master password outside printable
  ASCII rather than hashing it without SASLprep. MD5 is refused unless
  `pgproxy.allow_md5` is set; cleartext upstream is never answered at all.
- **A live `postgres-proxy` connection is bound by its grant, not only checked
  at connect time.** Every open connection is re-examined once a second and
  closed when the token expires, when the `(session, credential)` pair is
  revoked, or when the session ends — so a connection outlives its grant by at
  most a second. The client is told why with an `ErrorResponse` under SQLSTATE
  `57P01` (`admin_shutdown`), sent only when the stream is between messages so a
  client that is mid-parse is never handed bytes it cannot place.
- **`PgConnection` audit rows**: timestamp, mint id, the upstream role's name,
  start and end times, and the bytes each way. No statement, and no field one
  could be recorded in.
- **Two metrics series**: `briefcred_pgproxy_connections_total{outcome}` and
  `briefcred_pgproxy_bytes_total{direction}`.
- **`daemon.toml` gains `pg_proxy_port` (default `9319`), `pg_proxy_enabled`,
  and a `[pgproxy]` table with `tls` and `allow_md5`, both off by default.**
  `pg_proxy_enabled` requires `proxy_enabled`, because both proxies verify
  tokens with the same signing key; a configuration with one and not the other
  is refused at startup rather than failing every mint later.
- **`briefcred daemon status` reports the Postgres proxy's address**, next to
  the HTTP proxy's.
- **`examples/profiles/warehouse.yaml`**: a managed database whose master
  password never reaches the agent.

- **The HTTP proxy** (`briefcred-daemon::proxy`), and with it Phase 4 of the
  roadmap. A `CONNECT` listener on `127.0.0.1:9318` terminates the wrapped
  subprocess's TLS with a leaf from briefcred's own CA, applies the profile's
  policy, swaps the real credential in, and re-encrypts upstream against the
  system trust store. Plain `http://` absolute-URI requests are handled too.
  Bodies stream in both directions and are counted as they pass; nothing is
  buffered whole.
- **Three credential kinds the proxy serves**: `http-bearer`, `http-header
  { name }`, and `http-basic`. None of them mints anything — an API key is the
  only credential the vendor will accept — so instead the daemon signs a
  **synthetic token**, `bc.<base64url(payload)>.<base64url(signature)>`, whose
  payload names the session, the credential, and its expiry. The subprocess
  gets that; the real key never leaves the daemon. Each kind publishes two
  fields, `TOKEN` and `PROXY_URL`.
- **A per-machine Ed25519 signing key**, kept in the platform key store under
  `token-signer` and read on the first token rather than at daemon start, so a
  daemon nobody proxies through never prompts for keychain access.
- **`cnf` binding and DPoP.** `OpenSession` gains `session_pubkey`: the client
  generates a per-session Ed25519 pair and offers the public half, whose
  thumbprint goes into every token the session is issued. A client that sends a
  `DPoP` proof has it verified against that key; one that cannot — anything
  whose only channel is an environment variable, which is most of them — sends
  the token bare and it is accepted. `THREAT_MODEL.md` states what each path is
  worth.
- **Cedar policy** (`briefcred_core::policy`). A profile's `policy:` field is
  Cedar source over a fixed schema: `principal` is the session, `action` is the
  HTTP method, `resource` carries `host`, `path` and `scheme`. Compiled and
  validated when the profile is loaded, so a typo is an error next to the file.
  Default deny. `policy_mode: observe` logs the denial it would have made and
  forwards the request anyway, which is how a policy is written for a real
  workload; `enforce` is the default. `docs/policy.md` is the guide.
- **Placeholder swap.** Any header value containing `__<credential name>__` gets
  the master substituted, for every credential the session holds, so a profile
  can replace an existing placeholder tool without the agent changing.
- **Proxy environment.** `briefcred exec` sets `HTTPS_PROXY`, `HTTP_PROXY` and
  `ALL_PROXY` alongside the trust environment whenever the profile declares an
  HTTP credential, or whenever it says `proxy: always`.
- **`ProxyRequest` audit rows**: timestamp, mint id, method, host, path,
  status, request and response byte counts, latency, and decision. No headers,
  no body, and **no query string** — a query string routinely carries a
  credential.
- **Two metrics series**: `briefcred_proxy_requests_total{decision,status_class}`
  and `briefcred_proxy_latency_seconds`.
- **`daemon.toml` gains `proxy_port` (default `9318`), `proxy_enabled`, and
  `upstream_roots`.** The last is for the test suite and is documented as such:
  it adds certificate authorities the proxy will believe for every upstream.
- **`briefcred daemon status` reports the proxy's address**, next to the metrics
  endpoint, so a user debugging "my agent cannot reach the internet" does not
  have to read `daemon.toml` and guess whether the port was taken.
- **`examples/profiles/openai.yaml`**: an OpenAI key that never reaches the
  agent, with a two-endpoint Cedar allowlist.

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
  at 1 MiB; `db_query` fetches through a portal bounded at `max_rows` (100 by
  default) so the server produces no more than that, runs under a
  `statement_timeout` of `mcp_query_timeout_secs` (30 by default), and rolls
  its transaction back, which makes it read-only by contract. Every call writes
  an `mcp_call` audit row carrying an `mcp_call_id`, never the SQL or the
  command line.
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

- **`serde_yaml` replaced with `serde_yaml_ng`** across every crate. The
  original was deprecated and unmaintained; the fork is a continuation of the
  same code with the same API, so no behaviour changed.

  What this does *not* change is the parser underneath. `serde_yaml_ng`
  still depends on `unsafe-libyaml`, the same transliterated-C YAML parser
  `serde_yaml` used, which is archived alongside it. No advisory fires today:
  the one RUSTSEC entry against it, RUSTSEC-2023-0075, is an unsoundness fixed
  in 0.2.10 and the graph has 0.2.11, and there is no unmaintained advisory for
  it — `cargo deny` is configured with `unmaintained = "all"`, so a transitive
  one would be reported. Recorded here because "the unmaintained dependency was
  removed" would be the wrong summary: the deprecated *wrapper* was replaced
  and the parser it wraps is unchanged.
- **`rustls-pemfile` removed**, also unmaintained, in favour of the `pem`
  module of `rustls-pki-types`, which was already a dependency.
- **The AWS SDK clients no longer pull the legacy TLS stack.** Their default
  features enable a `rustls` path that means hyper 0.14, rustls 0.21 and
  rustls-webpki 0.101, all of which carry open advisories and none of which
  briefcred used. The clients now name `default-https-client` explicitly.
- **Development builds keep line tables in a packed `dSYM`.** The default macOS
  dev profile left full DWARF unpacked as one `.o` per codegen unit, which this
  workspace had accumulated tens of gigabytes of. Nothing about what is
  compiled changed.
- **The proxy's latency budget is stated as an absolute bound.** The roadmap
  asked for "within ~10% of direct"; on loopback, where a call costs a couple
  of hundred microseconds and the proxied path terminates one TLS session and
  originates another, ten percent is twenty microseconds and no proxy can meet
  it. The measured cost is about 212 µs per call in a release build, under one
  percent of a call to a real vendor. The assertion is now
  `proxied <= direct * 1.10 + 2 ms`.

- **Last-good no longer extends to trust.** A profile that does not *parse*
  still leaves the previous set in force, because one typo must not cost you
  every profile. A registry profile whose signature stops verifying is dropped
  on the next reload instead — continuing to run a profile precisely because its
  signature has just gone bad is the opposite of what that news calls for.
- The profile watcher is recursive, so a `briefcred profile sync` into
  `profiles/registry/` is picked up without restarting the daemon.
- The end-to-end daemon harness inserted its ephemeral-port overrides at the end
  of `daemon.toml`. In TOML a top-level key written after a table header belongs
  to that table, so a test whose config ended in a table got a daemon that
  refused to start complaining about the wrong key entirely. The overrides now
  go in before the first table header.
- **The CA's leaf cache is bounded.** It was an unbounded map keyed on the
  hostname list joined with a comma, which both grew without limit and made
  `["a,b"]` and `["a", "b"]` the same key. It is now a 256-entry
  least-recently-used cache keyed on the list itself.
- **`MinterFactory` gains `Hosting::Proxy`.** The `http-*` kinds register their
  schema so a profile naming one is validated at load, and have no minter to
  build: their credential's lifecycle belongs to the proxy, which needs the
  signing key and the session, neither of which exists behind the `Minter`
  contract. The mint, revoke, and reconcile paths all ask the registry rather
  than special-casing three strings.
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

### Fixed

- **`proxy: always` works on a profile with no credentials.** The proxy refuses
  a request with no token, so a profile whose only value was its Cedar policy
  pointed its subprocess at a proxy that answered `407` to everything. `exec`
  now issues a policy-only token for such a profile and publishes it as
  `BRIEFCRED_PROXY_TOKEN`. It names no credential, substitutes nothing, and
  exists so the request can be attributed to a session and decided by its
  policy. Hop-by-hop `Proxy-Authorization` and `Proxy-Connection` headers are
  now stripped before the swap rather than after, so a token presented the way
  a client naturally presents one to a proxy is not mistaken for a leak.

- **A handoff proves presence and checks its socket path.** `briefcred daemon
  upgrade` exported every resident master to whatever socket the caller named,
  with no unlock prompt. It now runs the unlock gate at the strictest
  `unlock.policy` among the open sessions, with the reason "daemon upgrade",
  and refuses a socket path that is not directly inside briefcred's own state
  directory.

- **The end-to-end harness refuses to start when any helper binary is
  missing**, not only the PostgreSQL one. A test reads the workspace's
  manifests and fails if the harness's list and the actual helper binaries
  disagree, so a new helper cannot be forgotten.
- **A flaky handoff test.** `a_session_asked_for_during_the_handoff_window_is_refused`
  slept a fixed second to land inside the handoff window, which raced the
  takeover spawn from both sides. It now waits for the daemon to report
  `handing_over`.
- **Two stale documentation counts.** `docs/policy.md` said the proxy's
  `decision` label was one of six; it is one of seven. The `record_proxy_request`
  doc comment listed five values and omitted `quota` and `bad_request`.
