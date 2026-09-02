//! The daemon-to-helper protocol: JSON-RPC 2.0, one object per line, on stdio.
//!
//! A minter runs in a helper process rather than in the daemon so that a
//! backend client library crashing, leaking, or blocking cannot take the daemon
//! with it, and so that the master credential for one backend never shares an
//! address space with the master for another.
//!
//! The transport is deliberately boring: newline-delimited JSON on the child's
//! stdin and stdout, with `id` correlating a response to its request. It is
//! JSON-RPC 2.0 so that a helper can be written in any language without
//! reimplementing a bespoke framing scheme.
//!
//! Four methods, and no more:
//!
//! | method | what it does |
//! | --- | --- |
//! | `mint` | create one principal and return its fields |
//! | `revoke` | remove one principal previously minted |
//! | `reconcile` | find and remove principals nothing is using any more |
//! | `shutdown` | exit cleanly |
//!
//! `mint`, `revoke`, and `reconcile` all carry the master credential, which is
//! why every one of them uses [`SecretString`] rather than a bare `String`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::secret::SecretString;

/// The only `jsonrpc` value this protocol accepts.
pub const JSONRPC_VERSION: &str = "2.0";

/// `mint`: create one principal.
pub const METHOD_MINT: &str = "mint";
/// `revoke`: remove one principal.
pub const METHOD_REVOKE: &str = "revoke";
/// `reconcile`: sweep principals nothing is using any more.
pub const METHOD_RECONCILE: &str = "reconcile";
/// `shutdown`: exit cleanly.
pub const METHOD_SHUTDOWN: &str = "shutdown";

/// Every method a helper must answer.
pub const METHODS: &[&str] = &[
    METHOD_MINT,
    METHOD_REVOKE,
    METHOD_RECONCILE,
    METHOD_SHUTDOWN,
];

/// JSON-RPC "invalid params": the method exists but the params do not fit.
pub const CODE_INVALID_PARAMS: i64 = -32602;
/// JSON-RPC "method not found".
pub const CODE_METHOD_NOT_FOUND: i64 = -32601;
/// Application error: the backend refused, or could not be reached.
pub const CODE_BACKEND: i64 = 1;

/// One JSON-RPC request on the helper wire.
///
/// `Debug` is derived rather than hand-written because every secret inside
/// `params` is a [`SecretString`], which redacts itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperRequest {
    /// Always [`JSONRPC_VERSION`].
    pub jsonrpc: String,
    /// Correlates this request with its response.
    pub id: u64,
    /// One of [`METHODS`].
    pub method: String,
    /// The method's parameters.
    pub params: HelperParams,
}

impl HelperRequest {
    /// Build a well-formed request for `params`' own method.
    pub fn new(id: u64, params: HelperParams) -> HelperRequest {
        HelperRequest {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            method: params.method().to_string(),
            params,
        }
    }
}

/// The parameter block of each method, tagged by the method it belongs to.
///
/// Untagged on the wire — the `method` field already says which it is — but an
/// enum here rather than a `serde_json::Value` so a helper cannot accidentally
/// accept a `revoke` payload for a `mint`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HelperParams {
    /// Parameters for [`METHOD_MINT`].
    Mint(MintParams),
    /// Parameters for [`METHOD_REVOKE`].
    Revoke(RevokeParams),
    /// Parameters for [`METHOD_RECONCILE`].
    Reconcile(ReconcileParams),
    /// Parameters for [`METHOD_SHUTDOWN`], which takes none.
    Shutdown(ShutdownParams),
}

impl HelperParams {
    /// The method these parameters belong to.
    pub fn method(&self) -> &'static str {
        match self {
            HelperParams::Mint(_) => METHOD_MINT,
            HelperParams::Revoke(_) => METHOD_REVOKE,
            HelperParams::Reconcile(_) => METHOD_RECONCILE,
            HelperParams::Shutdown(_) => METHOD_SHUTDOWN,
        }
    }
}

/// Everything a helper needs to mint one credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintParams {
    /// The identifier the principal must be created under.
    pub mint_id: String,
    /// The profile that asked for the mint, for the helper's own diagnostics.
    pub profile: String,
    /// The credential's name within that profile.
    pub credential: String,
    /// The credential spec's `config` block, converted from YAML to JSON.
    pub config: serde_json::Value,
    /// The master credential the helper authenticates with.
    pub master: SecretString,
    /// The requested lifetime.
    pub ttl_secs: u64,
}

/// Everything a helper needs to remove one credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeParams {
    /// The principal to remove.
    pub mint_id: String,
    /// The same `config` block the mint ran against.
    pub config: serde_json::Value,
    /// The master credential.
    pub master: SecretString,
    /// The opaque state the mint recorded, so revoke is exactly symmetric.
    pub revoke_token: String,
}

/// Everything a helper needs to sweep principals nothing is using.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileParams {
    /// A `config` block naming the backend to sweep.
    pub config: serde_json::Value,
    /// The master credential.
    pub master: SecretString,
}

/// [`METHOD_SHUTDOWN`] takes no parameters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownParams {}

/// One JSON-RPC response on the helper wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperResponse {
    /// Always [`JSONRPC_VERSION`].
    pub jsonrpc: String,
    /// The `id` of the request being answered.
    pub id: u64,
    /// The result, when the call succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<HelperResult>,
    /// The failure, when it did not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<HelperError>,
}

impl HelperResponse {
    /// A successful response to `id`.
    pub fn ok(id: u64, result: HelperResult) -> HelperResponse {
        HelperResponse {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// A failed response to `id`.
    pub fn err(id: u64, code: i64, message: impl Into<String>) -> HelperResponse {
        HelperResponse {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(HelperError {
                code,
                message: message.into(),
            }),
        }
    }
}

/// What a method returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HelperResult {
    /// [`METHOD_MINT`] succeeded.
    Mint(MintResult),
    /// [`METHOD_REVOKE`] finished, successfully or not — a revoke that the
    /// backend refused is a normal outcome, not a JSON-RPC error.
    Revoke(RevokeResult),
    /// [`METHOD_RECONCILE`] finished.
    Reconcile(ReconcileResult),
    /// [`METHOD_SHUTDOWN`] was accepted.
    Shutdown(ShutdownResult),
}

/// A freshly minted credential, as it crosses the helper pipe.
///
/// The `fields` values are the credential material itself, which is why they
/// are [`SecretString`] and why this type has no path to disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintResult {
    /// The principal that was created.
    pub mint_id: String,
    /// Minter-defined fields, for example `PGUSER` and `PGPASSWORD`.
    pub fields: BTreeMap<String, SecretString>,
    /// When the backend stops honouring the credential, RFC 3339.
    pub expires_at: String,
    /// Opaque state to hand back on revoke. Metadata, not a secret.
    pub revoke_token: String,
}

/// The outcome of a revoke attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeResult {
    /// One of `revoked`, `eventually_consistent`, `failed`, `already_gone`.
    pub outcome: String,
    /// Backend error text. Always present when `outcome` is `failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Propagation estimate, when the outcome was eventually consistent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub propagation_estimate_ms: Option<u64>,
}

/// What a reconcile sweep found and removed.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileResult {
    /// The principals the sweep removed, in the order it removed them.
    #[serde(default)]
    pub revoked: Vec<String>,
    /// Principals the sweep found but could not remove, with the reason.
    #[serde(default)]
    pub failed: Vec<ReconcileFailure>,
}

/// One principal a reconcile sweep found but could not remove.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileFailure {
    /// The principal that is still there.
    pub mint_id: String,
    /// Why it is still there.
    pub detail: String,
}

/// [`METHOD_SHUTDOWN`] returns nothing but an acknowledgement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownResult {
    /// Always `true`; a field exists so the object is not empty on the wire.
    pub stopping: bool,
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperError {
    /// A JSON-RPC or application error code.
    pub code: i64,
    /// Operator-readable text. Never credential material.
    pub message: String,
}

impl std::fmt::Display for HelperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "helper error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for HelperError {}

/// Encode one message as a line: compact JSON plus `\n`.
///
/// The message must not contain a raw newline, which `serde_json`'s compact
/// form guarantees, so a reader can split on `\n` without a parser.
pub fn encode_line<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let mut line = serde_json::to_string(value)?;
    line.push('\n');
    Ok(line)
}

/// What a helper process does with one call.
///
/// The trait lives here rather than in `briefcred-core` so that
/// [`serve_stdio`] can be shared by every helper without `briefcred-core`
/// having to know about the wire format, and without the wire crate having to
/// know about minters. A helper crate implements this over whatever it wraps.
#[allow(async_fn_in_trait)]
pub trait StdioHandler {
    /// Answer one call. Returning `Err` produces a JSON-RPC error response;
    /// the loop keeps running either way.
    async fn handle(&self, params: HelperParams) -> Result<HelperResult, HelperError>;
}

/// Run the newline-delimited JSON-RPC loop on the process's own stdio.
///
/// Returns when stdin reaches end of file or a [`METHOD_SHUTDOWN`] call is
/// answered — both of which are the daemon saying it is finished with this
/// helper. A malformed line is answered with an error and the loop continues,
/// because one bad frame should not cost the daemon a live connection to the
/// backend.
///
/// Only `stdout` carries protocol. Anything a helper wants to say to a human
/// goes on `stderr`, which the daemon inherits, so a helper that prints a
/// diagnostic cannot corrupt the stream.
pub async fn serve_stdio<H, R, W>(handler: &H, reader: R, writer: &mut W) -> std::io::Result<()>
where
    H: StdioHandler,
    R: tokio::io::AsyncBufRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let request: HelperRequest = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(err) => {
                // No `id` to answer with, so use 0 and say what was wrong.
                let response = HelperResponse::err(
                    0,
                    CODE_INVALID_PARAMS,
                    format!("unparsable request: {err}"),
                );
                writer.write_all(encode_line(&response)?.as_bytes()).await?;
                writer.flush().await?;
                continue;
            }
        };

        let stopping = request.method == METHOD_SHUTDOWN;
        let response = match handler.handle(request.params).await {
            Ok(result) => HelperResponse::ok(request.id, result),
            Err(error) => HelperResponse {
                jsonrpc: JSONRPC_VERSION.to_string(),
                id: request.id,
                result: None,
                error: Some(error),
            },
        };
        writer.write_all(encode_line(&response)?.as_bytes()).await?;
        writer.flush().await?;
        if stopping {
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mint_params() -> MintParams {
        MintParams {
            mint_id: "briefcred_t_0123456789ab".into(),
            profile: "db-ro".into(),
            credential: "db".into(),
            config: serde_json::json!({ "host": "127.0.0.1" }),
            master: SecretString::new("master-secret"),
            ttl_secs: 900,
        }
    }

    #[test]
    fn a_mint_request_round_trips_through_one_line() {
        let request = HelperRequest::new(7, HelperParams::Mint(mint_params()));
        assert_eq!(request.method, "mint");
        let line = encode_line(&request).unwrap();
        assert_eq!(line.matches('\n').count(), 1);
        assert!(line.ends_with('\n'));

        let back: HelperRequest = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(back, request);
    }

    #[test]
    fn a_request_never_debug_prints_the_master_it_carries() {
        let request = HelperRequest::new(1, HelperParams::Mint(mint_params()));
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("master-secret"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn a_mint_result_never_debug_prints_the_fields_it_carries() {
        let result = MintResult {
            mint_id: "briefcred_t_0123456789ab".into(),
            fields: BTreeMap::from([
                ("PGUSER".to_string(), SecretString::new("briefcred_t_x")),
                ("PGPASSWORD".to_string(), SecretString::new("t0p-s3cret")),
            ]),
            expires_at: "2026-01-01T00:00:00Z".into(),
            revoke_token: "{}".into(),
        };
        let rendered = format!("{result:?}");
        assert!(!rendered.contains("t0p-s3cret"), "{rendered}");
        assert!(rendered.contains("PGPASSWORD"), "{rendered}");
    }

    #[test]
    fn an_error_response_carries_no_result() {
        let response =
            HelperResponse::err(3, CODE_BACKEND, "28P01: password authentication failed");
        assert!(response.result.is_none());
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("result").is_none(), "{json}");
        assert_eq!(json["error"]["code"], CODE_BACKEND);
    }

    #[test]
    fn every_method_name_is_listed_exactly_once() {
        let mut sorted = METHODS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), METHODS.len());
        for params in [
            HelperParams::Mint(mint_params()),
            HelperParams::Revoke(RevokeParams {
                mint_id: "briefcred_t_0123456789ab".into(),
                config: serde_json::Value::Null,
                master: SecretString::new("m"),
                revoke_token: String::new(),
            }),
            HelperParams::Reconcile(ReconcileParams {
                config: serde_json::Value::Null,
                master: SecretString::new("m"),
            }),
            HelperParams::Shutdown(ShutdownParams {}),
        ] {
            assert!(METHODS.contains(&params.method()), "{:?}", params.method());
        }
    }

    /// Answers `shutdown`, and fails everything else, so the loop's control
    /// flow can be tested without a backend.
    struct StopsOnShutdown;

    impl StdioHandler for StopsOnShutdown {
        async fn handle(&self, params: HelperParams) -> Result<HelperResult, HelperError> {
            match params {
                HelperParams::Shutdown(_) => {
                    Ok(HelperResult::Shutdown(ShutdownResult { stopping: true }))
                }
                other => Err(HelperError {
                    code: CODE_METHOD_NOT_FOUND,
                    message: format!("`{}` is not implemented here", other.method()),
                }),
            }
        }
    }

    async fn run(input: &str) -> String {
        let mut output: Vec<u8> = Vec::new();
        serve_stdio(
            &StopsOnShutdown,
            tokio::io::BufReader::new(input.as_bytes()),
            &mut output,
        )
        .await
        .unwrap();
        String::from_utf8(output).unwrap()
    }

    #[tokio::test]
    async fn the_loop_answers_shutdown_and_then_returns() {
        let shutdown = encode_line(&HelperRequest::new(
            1,
            HelperParams::Shutdown(ShutdownParams {}),
        ))
        .unwrap();
        let never_read =
            encode_line(&HelperRequest::new(2, HelperParams::Mint(mint_params()))).unwrap();

        let output = run(&format!("{shutdown}{never_read}")).await;
        let replies: Vec<&str> = output.lines().collect();
        assert_eq!(replies.len(), 1, "nothing after shutdown may be served");
        let reply: HelperResponse = serde_json::from_str(replies[0]).unwrap();
        assert_eq!(reply.id, 1);
        assert!(reply.error.is_none(), "{reply:?}");
    }

    #[tokio::test]
    async fn a_malformed_line_is_answered_rather_than_ending_the_loop() {
        let shutdown = encode_line(&HelperRequest::new(
            9,
            HelperParams::Shutdown(ShutdownParams {}),
        ))
        .unwrap();
        let output = run(&format!("not json\n\n{shutdown}")).await;

        let replies: Vec<&str> = output.lines().collect();
        assert_eq!(replies.len(), 2, "{output}");
        let bad: HelperResponse = serde_json::from_str(replies[0]).unwrap();
        assert_eq!(bad.error.unwrap().code, CODE_INVALID_PARAMS);
        let good: HelperResponse = serde_json::from_str(replies[1]).unwrap();
        assert_eq!(good.id, 9);
    }

    #[tokio::test]
    async fn a_handler_failure_becomes_an_error_response_on_the_same_id() {
        let mint = encode_line(&HelperRequest::new(4, HelperParams::Mint(mint_params()))).unwrap();
        let output = run(&mint).await;
        let reply: HelperResponse = serde_json::from_str(output.trim_end()).unwrap();
        assert_eq!(reply.id, 4);
        assert_eq!(reply.error.unwrap().code, CODE_METHOD_NOT_FOUND);
        // And the master it carried is not echoed back in the complaint.
        assert!(!output.contains("master-secret"), "{output}");
    }

    #[test]
    fn a_revoke_result_round_trips_with_and_without_a_detail() {
        for result in [
            RevokeResult {
                outcome: "revoked".into(),
                detail: None,
                propagation_estimate_ms: None,
            },
            RevokeResult {
                outcome: "failed".into(),
                detail: Some("42501: permission denied".into()),
                propagation_estimate_ms: None,
            },
        ] {
            let line = encode_line(&result).unwrap();
            let back: RevokeResult = serde_json::from_str(line.trim_end()).unwrap();
            assert_eq!(back, result);
        }
    }
}
