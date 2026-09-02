//! What the Postgres proxy records, and what it deliberately cannot.
//!
//! One row per connection, written when the connection closes, because that is
//! when the byte counts and the end time exist. There is no row per query,
//! because after authentication the proxy copies bytes without parsing them —
//! see [`crate::pgproxy::forward::relay`] — so a statement is not something it
//! declines to record, it is something it does not have.
//!
//! # What is counted but not written
//!
//! Every connection is *counted*, on
//! `briefcred_pgproxy_connections_total{outcome}`. Only a connection that was
//! established is *written*, because an [`AuditEntry::PgConnection`] names a
//! `mint_id` and a `master_user`, and a client refused at authentication has
//! named neither. So a bad token is a metric and a line on the daemon's log,
//! and a real session is a row.

use briefcred_core::audit::AuditEntry;
use briefcred_core::types::MintId;
use time::OffsetDateTime;

use crate::pgproxy::forward::Transferred;

/// The connection was authenticated and relayed.
pub const OUTCOME_ALLOW: &str = "allow";

/// The client's token did not authorise the connection it asked for.
pub const OUTCOME_DENY: &str = "deny";

/// The token authorised the connection; the real server would not have it.
///
/// Distinct from [`OUTCOME_DENY`] because it is not a briefcred decision at
/// all: a rising `deny` means a profile or a stale token, and a rising
/// `upstream_error` means somebody should go and look at the database.
pub const OUTCOME_UPSTREAM_ERROR: &str = "upstream_error";

/// What arrived was not a PostgreSQL connection briefcred serves.
pub const OUTCOME_PROTOCOL_ERROR: &str = "protocol_error";

/// The token authorised the connection; the session's quota is spent.
///
/// Distinct from [`OUTCOME_DENY`] because nothing is wrong with the credential:
/// a rising `deny` means a profile or a stale token, and a rising `quota` means
/// a client opening connections faster than the profile budgeted for.
pub const OUTCOME_QUOTA: &str = "quota";

/// One `PgConnection` audit row. Metadata only, by construction.
pub fn connection_row(
    mint_id: &MintId,
    master_user: &str,
    started: OffsetDateTime,
    transferred: Transferred,
) -> AuditEntry {
    AuditEntry::PgConnection {
        ts: OffsetDateTime::now_utc(),
        mint_id: mint_id.clone(),
        master_user: master_user.to_string(),
        started,
        ended: OffsetDateTime::now_utc(),
        client_bytes: transferred.client_bytes,
        server_bytes: transferred.server_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_row_records_who_and_how_much_and_nothing_else() {
        let mint_id = MintId::generate();
        let row = connection_row(
            &mint_id,
            "reporting",
            OffsetDateTime::UNIX_EPOCH,
            Transferred {
                client_bytes: 42,
                server_bytes: 900,
            },
        );
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(json["event"], "pg_connection");
        assert_eq!(json["master_user"], "reporting");
        assert_eq!(json["client_bytes"], 42);
        assert_eq!(json["server_bytes"], 900);
        assert_eq!(json["started"], "1970-01-01T00:00:00Z");
        assert_eq!(json["mint_id"], mint_id.as_str());
        assert!(json["ended"].is_string(), "{json}");
    }

    #[test]
    fn a_connection_row_is_about_the_principal_it_names() {
        let row = connection_row(
            &MintId::generate(),
            "reporting",
            OffsetDateTime::UNIX_EPOCH,
            Transferred::default(),
        );
        assert_eq!(row.mint_ids().len(), 1);
    }

    #[test]
    fn a_connection_row_round_trips_as_one_line_of_jsonl() {
        let row = connection_row(
            &MintId::generate(),
            "reporting",
            OffsetDateTime::UNIX_EPOCH,
            Transferred {
                client_bytes: 1,
                server_bytes: 2,
            },
        );
        let line = serde_json::to_string(&row).unwrap();
        assert!(!line.contains('\n'));
        let back: AuditEntry = serde_json::from_str(&line).unwrap();
        assert_eq!(back, row);
    }

    #[test]
    fn the_row_has_no_field_a_query_could_hide_in() {
        // The proxy does not parse statements, so there is nowhere for one to
        // be recorded even by accident. Asserted so a future field addition
        // has to justify itself against this test.
        let row = connection_row(
            &MintId::generate(),
            "reporting",
            OffsetDateTime::UNIX_EPOCH,
            Transferred::default(),
        );
        let json = serde_json::to_value(&row).unwrap();
        let fields: Vec<&String> = json.as_object().unwrap().keys().collect();
        assert_eq!(
            fields,
            [
                "event",
                "ts",
                "mint_id",
                "master_user",
                "started",
                "ended",
                "client_bytes",
                "server_bytes"
            ]
        );
    }

    #[test]
    fn the_five_outcomes_are_the_ones_the_metric_documents() {
        let outcomes = [
            OUTCOME_ALLOW,
            OUTCOME_DENY,
            OUTCOME_UPSTREAM_ERROR,
            OUTCOME_PROTOCOL_ERROR,
            OUTCOME_QUOTA,
        ];
        assert_eq!(
            outcomes,
            ["allow", "deny", "upstream_error", "protocol_error", "quota"]
        );
    }
}
