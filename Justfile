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
