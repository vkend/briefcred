//! The `briefcred-helper-aws-sts` binary.
//!
//! Reads newline-delimited JSON-RPC on stdin and writes it on stdout. Nothing
//! else: the daemon owns both ends of those pipes.
//!
//! The binary is named for the *minter kind* it serves rather than for its
//! crate, because that is how the daemon finds it: a profile naming
//! `kind: aws-sts` makes the daemon look for `briefcred-helper-aws-sts`.

use briefcred_helper_sts::StsHelper;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    let helper = StsHelper::new();
    let stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();

    match briefcred_proto::helper::serve_stdio(&helper, stdin, &mut stdout).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            // stderr, never stdout: stdout is protocol.
            eprintln!("briefcred-helper-aws-sts: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}
