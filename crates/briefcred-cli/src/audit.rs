//! `briefcred audit`: reading the log back.
//!
//! The CLI reads the JSONL files directly rather than asking the daemon for
//! them. That is deliberate. The log is the record of what the daemon did, and
//! a daemon that is asked to summarise its own history is a daemon that could
//! be made to lie about it. It also means `briefcred audit` works when the
//! daemon is not running, which is exactly when somebody is most likely to be
//! reading it.

use std::path::Path;

use time::{Duration, OffsetDateTime};

use crate::error::{Error, Result};

/// Parse a duration written the way a human writes one: `30m`, `24h`, `7d`.
///
/// Seconds, minutes, hours and days only. Nothing longer, because "1M" is
/// ambiguous between a minute and a month in every tool that accepts it, and
/// an audit window that silently means the wrong one is worse than no shorthand.
pub fn parse_since(raw: &str) -> Result<Duration> {
    let raw = raw.trim();
    let (digits, unit) = raw.split_at(raw.find(|c: char| !c.is_ascii_digit()).unwrap_or(raw.len()));
    let count: i64 = digits.parse().map_err(|_| {
        Error::Refused(format!(
            "`{raw}` is not a duration; write it like `30m`, `24h`, or `7d`"
        ))
    })?;
    let unit = match unit {
        "s" => Duration::seconds(1),
        "m" => Duration::minutes(1),
        "h" => Duration::hours(1),
        "d" => Duration::days(1),
        other => {
            return Err(Error::Refused(format!(
                "`{other}` is not a duration unit; use `s`, `m`, `h`, or `d`"
            )))
        }
    };
    Ok(unit * count as i32)
}

/// Every row in `dir` newer than `since`, oldest first.
///
/// Returned as raw JSON values rather than typed `AuditEntry`s so a log
/// written by a newer briefcred, with a row kind this binary does not know
/// about, is still readable. An audit tool that refuses to show a row it
/// cannot classify is not much of an audit tool.
pub fn read_since(dir: &Path, since: Option<Duration>) -> Result<Vec<serde_json::Value>> {
    let cutoff = since.map(|window| OffsetDateTime::now_utc() - window);

    let mut files: Vec<std::path::PathBuf> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "jsonl"))
            .collect(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(Error::io("read", dir, err)),
    };
    // Filenames carry the UTC date, so sorting them sorts the rows.
    files.sort();

    let mut rows = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).map_err(|e| Error::io("read", &path, e))?;
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(row) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if let Some(cutoff) = cutoff {
                if !newer_than(&row, cutoff) {
                    continue;
                }
            }
            rows.push(row);
        }
    }
    Ok(rows)
}

/// Whether a row's `ts` is at or after `cutoff`.
///
/// A row with no readable timestamp is kept: dropping it would hide exactly the
/// row somebody had tampered with.
fn newer_than(row: &serde_json::Value, cutoff: OffsetDateTime) -> bool {
    let Some(ts) = row.get("ts").and_then(serde_json::Value::as_str) else {
        return true;
    };
    match OffsetDateTime::parse(ts, &time::format_description::well_known::Rfc3339) {
        Ok(ts) => ts >= cutoff,
        Err(_) => true,
    }
}

/// One row, rendered as a line for a terminal.
///
/// Fixed-width event name, wide enough for the longest, then the fields that
/// matter for that kind. Rows the binary does not recognise fall back to their
/// whole JSON, so nothing is ever silently dropped from the output.
pub fn render(row: &serde_json::Value) -> String {
    let ts = row
        .get("ts")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("-");
    let event = row
        .get("event")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");

    let detail = match event {
        "mint" => format!(
            "{} {}/{} ttl={}s",
            text(row, "mint_id"),
            text(row, "profile"),
            text(row, "credential"),
            text(row, "ttl_secs")
        ),
        "exec_start" => format!(
            "{} argv0={} args={} pid={}",
            text(row, "profile"),
            text(row, "argv0"),
            count(row, "args_sha256"),
            text(row, "pid")
        ),
        "exec_end" => format!(
            "{} exit={} {}ms",
            text(row, "profile"),
            text(row, "exit_code"),
            text(row, "duration_ms")
        ),
        "revoke" => format!(
            "{} {}{}",
            text(row, "mint_id"),
            text(row, "outcome"),
            row.get("detail")
                .and_then(serde_json::Value::as_str)
                .map(|d| format!(" ({d})"))
                .unwrap_or_default()
        ),
        "reconcile" => format!(
            "{} revoked={} failed={}",
            text(row, "profile"),
            text(row, "revoked"),
            text(row, "failed")
        ),
        "session_open" | "session_close" => format!(
            "{} {} {}",
            text(row, "session_id"),
            text(row, "profile"),
            text(row, "reason")
        ),
        "unlock_denied" => format!(
            "{} policy={} {}",
            text(row, "profile"),
            text(row, "policy"),
            text(row, "reason")
        ),
        "proxy_request" => format!(
            "{} {} {}{} {}{}",
            text(row, "mint_id"),
            text(row, "method"),
            text(row, "host"),
            text(row, "path"),
            text(row, "decision"),
            row.get("status")
                .and_then(serde_json::Value::as_u64)
                .map(|s| format!(" status={s}"))
                .unwrap_or_default()
        ),
        "proxy_token_rejected" => format!(
            "{} {}{} reason={}",
            text(row, "method"),
            text(row, "host"),
            text(row, "path"),
            text(row, "reason")
        ),
        "proxy_h2_connection" => format!(
            "{} {} {} streams={}",
            text(row, "connection_id"),
            text(row, "mint_id"),
            text(row, "host"),
            text(row, "streams")
        ),
        "daemon_start" | "daemon_stop" => {
            format!("pid={} {}", text(row, "pid"), text(row, "reason"))
        }
        _ => row.to_string(),
    };
    // RFC 3339 drops trailing zeros from the fraction, so a timestamp can be a
    // character or two short; padding keeps the columns after it aligned.
    format!("{ts:<27}  {event:<21}{}", detail.trim_end())
}

fn text(row: &serde_json::Value, key: &str) -> String {
    match row.get(key) {
        None | Some(serde_json::Value::Null) => "-".to_string(),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

fn count(row: &serde_json::Value, key: &str) -> usize {
    row.get(key)
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_log(dir: &Path, name: &str, lines: &[&str]) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), format!("{}\n", lines.join("\n"))).unwrap();
    }

    #[test]
    fn durations_parse_in_the_units_a_person_would_type() {
        assert_eq!(parse_since("30s").unwrap(), Duration::seconds(30));
        assert_eq!(parse_since("30m").unwrap(), Duration::minutes(30));
        assert_eq!(parse_since("24h").unwrap(), Duration::hours(24));
        assert_eq!(parse_since("7d").unwrap(), Duration::days(7));
        assert_eq!(parse_since(" 1h ").unwrap(), Duration::hours(1));
    }

    #[test]
    fn an_ambiguous_or_malformed_duration_is_refused() {
        for bad in ["1M", "1w", "h", "", "1", "-1h", "1.5h"] {
            assert!(parse_since(bad).is_err(), "`{bad}` should be refused");
        }
    }

    #[test]
    fn rows_come_back_oldest_first_across_files() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit");
        write_log(
            &log,
            "audit-2026-01-02.jsonl",
            &[r#"{"event":"ping","ts":"2026-01-02T00:00:00Z","n":2}"#],
        );
        write_log(
            &log,
            "audit-2026-01-01.jsonl",
            &[r#"{"event":"ping","ts":"2026-01-01T00:00:00Z","n":1}"#],
        );

        let rows = read_since(&log, None).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["n"], 1);
        assert_eq!(rows[1]["n"], 2);
    }

    #[test]
    fn a_window_drops_only_the_rows_older_than_it() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit");
        let recent = OffsetDateTime::now_utc() - Duration::minutes(5);
        let ancient = OffsetDateTime::now_utc() - Duration::days(30);
        let rfc = &time::format_description::well_known::Rfc3339;
        write_log(
            &log,
            "audit-2026-01-01.jsonl",
            &[
                &format!(
                    r#"{{"event":"mint","ts":"{}","tag":"old"}}"#,
                    ancient.format(rfc).unwrap()
                ),
                &format!(
                    r#"{{"event":"mint","ts":"{}","tag":"new"}}"#,
                    recent.format(rfc).unwrap()
                ),
            ],
        );

        let rows = read_since(&log, Some(Duration::hours(1))).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["tag"], "new");
    }

    #[test]
    fn a_row_with_no_readable_timestamp_is_kept_rather_than_hidden() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit");
        write_log(
            &log,
            "audit-2026-01-01.jsonl",
            &[
                r#"{"event":"mint","ts":"not a timestamp"}"#,
                r#"{"event":"mint"}"#,
            ],
        );
        assert_eq!(read_since(&log, Some(Duration::hours(1))).unwrap().len(), 2);
    }

    #[test]
    fn a_missing_audit_directory_reads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_since(&dir.path().join("nope"), None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_row_kind_this_binary_does_not_know_is_still_shown() {
        let row: serde_json::Value =
            serde_json::from_str(r#"{"event":"from_the_future","ts":"2030-01-01T00:00:00Z"}"#)
                .unwrap();
        let line = render(&row);
        assert!(line.contains("from_the_future"), "{line}");
        assert!(line.contains("2030-01-01"), "{line}");
    }

    #[test]
    fn an_exec_row_renders_the_argument_count_rather_than_the_arguments() {
        let row: serde_json::Value = serde_json::from_str(
            r#"{"event":"exec_start","ts":"2026-01-01T00:00:00Z","profile":"db-ro",
                 "argv0":"psql","args_sha256":["deadbeef","cafef00d"],"pid":42}"#,
        )
        .unwrap();
        let line = render(&row);
        assert!(line.contains("argv0=psql"), "{line}");
        assert!(line.contains("args=2"), "{line}");
        assert!(
            !line.contains("deadbeef"),
            "digests do not belong in the summary: {line}"
        );
    }

    #[test]
    fn a_proxy_request_row_renders_as_a_line_not_as_json() {
        let row: serde_json::Value = serde_json::from_str(
            r#"{"event":"proxy_request","ts":"2026-01-01T00:00:00Z","mint_id":"briefcred_t_1",
                 "method":"GET","host":"api.openai.com","path":"/v1/models","status":200,
                 "req_bytes":0,"resp_bytes":48,"latency_ms":3,"decision":"allow"}"#,
        )
        .unwrap();
        let line = render(&row);
        assert!(
            line.ends_with("briefcred_t_1 GET api.openai.com/v1/models allow status=200"),
            "{line}"
        );
    }

    #[test]
    fn a_rejected_token_row_says_why_and_nothing_about_the_token() {
        let row: serde_json::Value = serde_json::from_str(
            r#"{"event":"proxy_token_rejected","ts":"2026-01-01T00:00:00Z","method":"GET",
                 "host":"api.openai.com","path":"/v1/models","reason":"revoked"}"#,
        )
        .unwrap();
        let line = render(&row);
        assert!(
            line.ends_with("GET api.openai.com/v1/models reason=revoked"),
            "{line}"
        );
    }

    #[test]
    fn a_short_timestamp_does_not_shift_the_columns() {
        let row = |ts: &str| serde_json::json!({"event":"revoke","ts":ts,"mint_id":"briefcred_t_1","outcome":"revoked"});
        let long = render(&row("2026-01-01T00:00:00.123456Z"));
        let short = render(&row("2026-01-01T00:00:00.1234Z"));
        assert_eq!(long.find("revoke"), short.find("revoke"), "{long}\n{short}");
    }
}
