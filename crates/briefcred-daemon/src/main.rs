//! The `briefcred-daemon` binary.
//!
//! Started by launchd or systemd, never by the CLI directly. It reads its
//! whole configuration from the filesystem layout, so the only thing that
//! changes its behaviour is `BRIEFCRED_HOME` and `daemon.toml`.

fn main() -> std::process::ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("briefcred-daemon: cannot start the async runtime: {err}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(briefcred_daemon::run()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("briefcred-daemon: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}
