//! The loopback ports briefcred listens on when nothing says otherwise.
//!
//! Here rather than in the daemon's `config` module because two crates have to
//! agree about them. The daemon binds them; `briefcred install` writes them
//! into the systemd socket unit that binds them *for* the daemon. A unit that
//! listened on one port while the daemon expected another would produce a
//! socket-activated start where every listener is the wrong one — and nothing
//! would report it, because both sides would be individually correct.

/// The Prometheus port used when `daemon.toml` says nothing.
pub const DEFAULT_METRICS_PORT: u16 = 9317;

/// The HTTP proxy port used when `daemon.toml` says nothing.
///
/// One past the metrics port, so the two briefcred listens on are adjacent and
/// an operator who has allowed one through a local firewall knows where the
/// other is.
pub const DEFAULT_PROXY_PORT: u16 = 9318;

/// The Postgres proxy port used when `daemon.toml` says nothing.
///
/// One past the HTTP proxy's, so briefcred's three loopback listeners are
/// adjacent and an operator who has found one knows where the others are.
pub const DEFAULT_PG_PROXY_PORT: u16 = 9319;
