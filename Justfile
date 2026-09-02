default: check test

# Formatting and lints, both enforced in CI.
check:
    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings

# The whole workspace: unit tests and end-to-end tests.
test:
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
