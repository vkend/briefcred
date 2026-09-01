//! The `briefcred` binary.

use clap::Parser;

fn main() -> std::process::ExitCode {
    let cli = briefcred_cli::Cli::parse();

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("briefcred: cannot start the async runtime: {err}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(briefcred_cli::cli::run(cli)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("briefcred: {err}");
            std::process::ExitCode::from(err.exit_code())
        }
    }
}
