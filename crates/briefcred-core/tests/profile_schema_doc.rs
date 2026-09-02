//! `docs/profile-schema.md` is generated, and this is what keeps it that way.
//!
//! The profile schema is the one part of briefcred every user writes by hand,
//! so it is the one part where a documentation drift is a user typing a key
//! that does not exist. The reference block in the doc is the exact output of
//! `briefcred profile schema`; this test regenerates it and compares. When it
//! fails, the fix is never to edit the block — it is to run
//!
//! ```sh
//! cargo run -p briefcred-cli --bin briefcred -- profile schema
//! ```
//!
//! and paste the result back in.

use std::path::PathBuf;

/// The committed reference document.
fn doc_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/briefcred-core")
        .join("docs")
        .join("profile-schema.md")
}

/// The contents of the document's single fenced ```json block.
fn fenced_json(markdown: &str) -> String {
    let mut fences = markdown.split("```json");
    fences.next().expect("text before the first fence");
    let body = fences
        .next()
        .expect("docs/profile-schema.md has a ```json block");
    assert!(
        fences.next().is_none(),
        "docs/profile-schema.md must have exactly one ```json block, so there \
         is no question which one is generated"
    );
    body.split("```")
        .next()
        .expect("the block is closed")
        .trim()
        .to_string()
}

#[test]
fn the_committed_schema_document_matches_the_generated_schema() {
    let path = doc_path();
    let markdown = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    assert_eq!(
        fenced_json(&markdown),
        briefcred_core::profile::json_schema().trim(),
        "{} is stale; regenerate it with `briefcred profile schema`",
        path.display()
    );
}

/// The schema is only useful if it names the keys a profile actually has.
///
/// A `JsonSchema` derive that silently stopped covering a field would still
/// produce a document this test's other half is happy with, because the
/// document is generated from the same derive. Naming the top-level keys here
/// is the independent statement of what the schema is for.
#[test]
fn the_schema_names_every_top_level_profile_key() {
    let schema: serde_json::Value =
        serde_json::from_str(&briefcred_core::profile::json_schema()).expect("valid JSON");
    let properties = schema
        .get("properties")
        .and_then(|p| p.as_object())
        .expect("the schema describes an object");
    for key in [
        "name",
        "description",
        "unlock",
        "credentials",
        "exec",
        "env",
        "env_passthrough",
        "trust_env",
        "policy",
        "policy_mode",
        "quota",
        "proxy",
    ] {
        assert!(
            properties.contains_key(key),
            "the schema is missing `{key}`"
        );
    }
    assert_eq!(
        schema.get("additionalProperties"),
        Some(&serde_json::Value::Bool(false)),
        "the profile schema must reject unknown keys, as the loader does"
    );
}
