default: check test

# Formatting, lints, and the supply chain. All four enforced in CI.
#
# `cargo deny` and `cargo vet` are here rather than in a separate recipe because
# a dependency is added on the same afternoon somebody runs `just check`, and a
# supply-chain gate nobody runs until release is one that fails at release.
# Install them with:
#
#     cargo install cargo-deny cargo-vet --locked
#
# The vet check is offline: `--frozen` forbids the network and requires
# `--locked` alongside it, which is why both are passed. `supply-chain/config.toml`
# imports no third-party audit sets, so the whole graph sits in `exemptions` and
# the check asserts that the exemption list still covers the lockfile. That
# turns a new dependency into a diff somebody has to look at, which is the part
# of `cargo vet` that is worth having before there is an audit team to run it.
check:
    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings
    cargo deny check
    cargo vet check --locked --frozen

# The whole workspace: unit tests and end-to-end tests.
#
# The build is a separate step on purpose. The end-to-end tests spawn real
# binaries — the daemon, and the `briefcred-helper-*` a mint goes through — and
# `cargo test` does not build a package's binaries unless something being
# tested asks for them, so on a clean checkout the helpers are simply absent
# and a test that mints fails for a reason that looks nothing like the cause.
# `cargo build --workspace` first costs nothing on a warm tree and makes a cold
# one behave the same as a warm one.
test:
    cargo build --workspace
    cargo test --workspace

# Rewrite formatting in place.
fmt:
    cargo fmt --all

# Only the end-to-end tests, with their output shown.
e2e:
    cargo test -p briefcred-e2e -- --nocapture

# The memory-hygiene check: build the daemon with the self-scan feature and
# assert a master is gone from its address space once its session is closed.
# Ignored by default because the scan takes seconds and the feature must never
# reach a shipping daemon.
mem-hygiene:
    cargo build -p briefcred-daemon --features debug-heapscan
    BRIEFCRED_MEM_HYGIENE=1 cargo test -p briefcred-e2e --features debug-heapscan \
        --test memory_hygiene -- --ignored --nocapture
