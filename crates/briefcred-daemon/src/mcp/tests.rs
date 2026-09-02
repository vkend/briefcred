use super::*;

/// The tool surface is a public contract: a renamed tool silently breaks every
/// agent configuration that named it, and a new one is a new capability an
/// operator has not agreed to. Both should be a failing test, not a surprise.
#[test]
fn the_server_offers_exactly_the_three_documented_tools() {
    let names: Vec<String> = McpServer::tool_router()
        .list_all()
        .iter()
        .map(|tool| tool.name.to_string())
        .collect();
    assert_eq!(
        names,
        vec![
            "briefcred_db_query",
            "briefcred_exec",
            "briefcred_list_profiles",
        ]
    );
}

#[test]
fn every_tool_describes_itself_and_its_arguments() {
    for tool in McpServer::tool_router().list_all() {
        let description = tool.description.as_deref().unwrap_or_default();
        assert!(
            description.len() > 40,
            "`{}` needs a description a model can choose it from: {description:?}",
            tool.name
        );
        assert!(
            tool.input_schema.contains_key("type"),
            "`{}` must publish an input schema",
            tool.name
        );
    }
}

/// The two tools that mint say so, because "this returns no credential" is the
/// claim the whole design rests on and it belongs where a model reads it.
#[test]
fn the_minting_tools_say_that_no_credential_comes_back() {
    for tool in McpServer::tool_router().list_all() {
        if tool.name == "briefcred_list_profiles" {
            continue;
        }
        let description = tool.description.as_deref().unwrap_or_default();
        assert!(
            description.contains("never returned"),
            "`{}` must say the credential does not come back: {description}",
            tool.name
        );
    }
}

#[test]
fn output_under_the_cap_is_returned_whole_and_unmarked() {
    let (text, truncated) = capped(b"hello");
    assert_eq!(text, "hello");
    assert!(!truncated);

    let exact = vec![b'x'; MAX_OUTPUT_BYTES];
    let (text, truncated) = capped(&exact);
    assert_eq!(text.len(), MAX_OUTPUT_BYTES);
    assert!(!truncated, "exactly at the cap is not over it");
}

#[test]
fn output_over_the_cap_is_cut_and_says_so() {
    let flood = vec![b'x'; MAX_OUTPUT_BYTES * 2];
    let (text, truncated) = capped(&flood);
    assert!(truncated);
    assert!(text.len() <= MAX_OUTPUT_BYTES, "{}", text.len());
}

#[test]
fn a_cut_never_lands_inside_a_character() {
    // Three-byte characters, so the cap falls in the middle of one.
    let mut bytes = "€".repeat(MAX_OUTPUT_BYTES).into_bytes();
    bytes.truncate(MAX_OUTPUT_BYTES + 2);
    let (text, truncated) = capped(&bytes);
    assert!(truncated);
    assert!(
        !text.contains('\u{FFFD}'),
        "a cut inside a character would leave a replacement character"
    );
    assert!(text.chars().all(|c| c == '€'), "{}", &text[..12]);
}

#[test]
fn an_empty_output_is_an_empty_string_rather_than_a_truncation() {
    assert_eq!(capped(b""), (String::new(), false));
}
