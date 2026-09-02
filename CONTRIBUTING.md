# Contributing to briefcred

## Before you start

```sh
just check   # cargo fmt --check, then clippy with -D warnings
just test    # the whole workspace
```

Both must pass before a commit lands. Clippy warnings are errors here; there is
no "fix it later" tier.

Two rules override everything else in this document:

1. **A secret lives in `Zeroizing<String>` and never leaves it.** Never log it,
   never `Debug`-print it, never `Serialize` it. Any type that holds one gets a
   hand-written `Debug` that redacts it, and a test asserting the redaction.
2. **Audit rows carry metadata only.** Never headers, bodies, query strings,
   connection strings, or credential material. Arguments are SHA-256 digests.

## Adding a minter

A minter creates and destroys short-lived principals at some backend. It is
selected by the `kind` string in a profile's credential spec, and it registers
itself — there is no central table to edit.

### 1. Implement `Minter`

In a new module under `briefcred-core/src/minters/`:

```rust
/// The `kind` string profiles use to select this minter.
pub const KIND: &str = "my-backend";

pub struct MyMinter;

#[async_trait]
impl Minter for MyMinter {
    fn kind(&self) -> &'static str { KIND }

    async fn mint(&self, ctx: MintCtx) -> Result<MintedCredential> { ... }

    async fn revoke(&self, ctx: RevokeCtx) -> RevokeOutcome { ... }
}
```

`kind` is the name users type in a profile, so pick it as carefully as a public
API name. It is `lowercase-with-hyphens` and names the *thing being minted*,
not the vendor: `postgres-dynamic`, not `pg` and not `acme-corp-db`.

### 2. Define the config type

The credential spec's `config` block is yours to interpret. Give it a struct
with `#[serde(deny_unknown_fields)]` — a typo in a profile must fail loudly
rather than silently switch a control off — and a `from_value` that returns
`Error::MinterConfig { kind: KIND, .. }`.

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MyConfig { pub endpoint: String, /* ... */ }
```

### 3. Register it

Next to the implementation, in the same file:

```rust
inventory::submit! {
    crate::registry::MinterFactory {
        kind: KIND,
        hosting: crate::registry::Hosting::Helper,
        validate: |config| {
            MyConfig::from_value(config)?;
            Ok(())
        },
        construct: Some(|| std::sync::Arc::new(MyMinter::new())),
    }
}
```

`Registry::discover()` collects every submission the binary was linked with, so
that is the whole registration.

### The contract `validate` must honour

- **Validate eagerly.** `validate` receives the credential's `config` and is
  called from `Profile::validate`, which the daemon runs when it loads the
  directory. Parse the config and return `Error::MinterConfig` on anything
  wrong. A minter that defers validation to the first mint turns a typo into a
  failure half an hour later, in a different context, with a worse message.
- **Check everything a backend would reject up front.** `aws-sts` refuses a
  session policy over 2,048 characters here, because AWS refuses it after the
  request has been signed with a message that names a percentage rather than
  the limit.
- **Never panic.** An invalid config is an `Err`, not an `unwrap`. A panic here
  takes down a profile reload.
- **Do no I/O.** `validate` runs on the profile-load path and must not connect
  to anything. Reachability is a mint-time concern.
- **Be cheap and repeatable.** It is called once per credential on every
  reload.

### The contract `construct` must honour

- **Hold no secrets.** The master arrives in `MintCtx`, per mint. A minter that
  captured one at construction would keep it resident for the daemon's whole
  life, which is exactly what the session model exists to prevent.
- **Do no I/O**, for the same reason `validate` does none: it runs wherever a
  minter is first needed, including on a profile-load path.

### Choosing `hosting`

`Hosting::Helper` unless you can argue otherwise, and the argument is narrow.
A helper means the daemon spawns `briefcred-helper-<kind>` and the master
credential crosses a pipe into an address space the daemon does not share, so a
bug in your backend client library costs one backend rather than every master
the daemon holds.

`Hosting::Daemon` is correct only when the minter **talks to no backend at
all**, because the master is then resident in the daemon for the length of a
mint. `ssh-cert` qualifies: it signs a certificate and writes two files. If
your minter opens a socket, it is a helper.

Both shapes answer the same `MintChannel` trait, so nothing above the registry
branches on which you chose, and changing your mind later is a one-line edit to
this registration.

### When the implementation lives outside `briefcred-core`

A minter that drags in a large vendor SDK does not belong in `briefcred-core`,
because the CLI and the hook would pay for it to use none of it. Split it:

- The **schema** — the `KIND` constant, the config struct, its validation, and
  the `inventory::submit!` — goes in `briefcred-core/src/minters/`, with
  `construct: None`. Every binary that reads profiles can then reject a bad one.
- The **minter** goes in `crates/briefcred-helper-<crate>/`, and its binary
  constructs it directly. Wrap it in `briefcred_core::MinterAdapter` and hand
  that to `briefcred_proto::helper::serve_stdio`; do not write the protocol
  conversion again.

`aws-sts` is the worked example. `Registry::build` on a kind with no
constructor reports which binary mints it, so the split cannot produce a
confusing failure.

### What `mint` and `revoke` owe the caller

- `mint` is **transactional where the backend allows it**. A failed grant must
  not leave a usable principal behind. Where the backend has no transactions,
  clean up on the failure path yourself.
- `mint` returns a `revoke_token` carrying whatever state makes `revoke`
  exactly symmetric. Do not make `revoke` re-derive it from the config: the
  config may have changed since.
- `revoke` returns `RevokeOutcome`, not `Result`. "The revoke failed" is a
  normal auditable state that the daemon retries, not an exception.
  `RevokeOutcome::Failed` always carries a non-empty `detail` with the
  backend's error; use `RevokeOutcome::failed(..)`, which substitutes a
  placeholder rather than emitting an empty one. A backend that cannot revoke
  synchronously returns `EventuallyConsistent` with an honest propagation
  estimate rather than claiming `Revoked`.
- Removing something already absent is `AlreadyGone`, not an error.
- **Free-form profile text never reaches a query.** Identifiers go through the
  backend's escaping helpers, and anything template-shaped is restricted to a
  keyword or dotted-identifier grammar and validated before use.

### 4. Test it

- A unit test that an unknown key in your config is rejected and names itself.
- A unit test that the registry resolves your `kind` and that a malformed
  config fails at `build` rather than at mint.
- An end-to-end test in `briefcred-e2e` against a real backend if one can be
  run locally without Docker. Follow `pg_harness`: bring the backend up on a
  free loopback port under a temp dir, tear it down after, and **skip with a
  printed reason** when the binary is not installed rather than failing.

### 5. Document it

- A `## The <backend> minter` section in `README.md` with a worked profile, and
  a row in the minter matrix above it.
- A `CHANGELOG.md` entry under `## Unreleased`.
- The residual risks in `THREAT_MODEL.md` if your backend adds any.

## Adding a request to the protocol

1. Add the variant to `Request` in `briefcred-proto`, its arm in
   `Request::name`, and its name to `Request::NAMES`.
2. Add the handler and its `dispatch_table` entry in `briefcred-daemon`.

The table is asserted in a test to cover `Request::NAMES` exactly, in both
directions, so forgetting either half fails the build rather than producing a
request nothing answers.

A request that takes the **connection** over rather than being answered once
goes in `Request::UPGRADE_NAMES` instead of the dispatch table, and is handled
in `serve_connection` before dispatch. `Request::Mcp` is the only one, and it
exists because MCP is not request/response. The table's test excludes upgrade
names in both directions, so an upgrade cannot quietly acquire a handler that
could never run.

Responses that carry data from the daemon's own types get a wire type of their
own, the way `ProfileSummary` does. Serialising an internal type across the
socket means the next field somebody adds to it is exposed by default.

## Tests

- Tests never touch real user directories. Set `BRIEFCRED_HOME` to a temp dir;
  it overrides the entire layout, socket included.
- Networking in tests is localhost only.
- Never call the biometric prompt from a test that is not `#[ignore]`. It puts
  a sheet on the developer's screen and blocks until somebody answers it. Force
  the headless path with `briefcred_core::session_env::testing::ForceNoAqua`,
  which sets `BRIEFCRED_FORCE_NO_AQUA=1` under a shared mutex and always
  restores the environment on drop.
- Test doubles that stand in for a secret-bearing type obey the same rules as
  the real one: `Zeroizing`, a redacting `Debug`, and `cfg(any(test, feature =
  "test-util"))` so they cannot reach a production binary. `MemorySource` is
  the worked example.
- Time-based behaviour is tested against `clock::TestClock`, not a `sleep`.

## Commits

One-line subject, present tense, describing what the change does. No body, no
trailers.
