//! The `briefcred-helper-postgres-dynamic` binary.
//!
//! Reads newline-delimited JSON-RPC on stdin and writes it on stdout. Nothing
//! else: the daemon owns both ends of those pipes.
//!
//! The binary is named for the *minter kind* it serves rather than for its
//! crate, because that is how the daemon finds it: a profile naming
//! `kind: postgres-dynamic` makes the daemon look for
//! `briefcred-helper-postgres-dynamic`. One crate can grow a second kind and a
//! second binary without a lookup table in the middle.

use briefcred_helper_postgres::PostgresHelper;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    let helper = PostgresHelper::new();
    let stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();

    match briefcred_proto::helper::serve_stdio(&helper, stdin, &mut stdout).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            // stderr, never stdout: stdout is protocol.
            eprintln!("briefcred-helper-postgres-dynamic: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}
