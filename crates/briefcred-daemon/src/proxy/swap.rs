//! Putting the real credential into an outgoing request.
//!
//! This is the moment the whole proxy exists for. The subprocess sent a
//! synthetic token, or a `__name__` placeholder, and the request about to go
//! upstream has to carry the real key instead.
//!
//! Three rules, and the third is the one that has teeth:
//!
//! 1. **Placeholders.** Any header value containing `__<credential>__` gets the
//!    master substituted, for every credential the session holds. This is the
//!    convention the tools people are already using speak, so a profile can
//!    replace one of them without the agent changing.
//! 2. **The token.** The header carrying the synthetic token is *replaced
//!    entirely* by the header the credential's kind belongs in, with the real
//!    value rendered for that kind.
//! 3. **Nothing synthetic leaves.** After the swap, every header value is
//!    checked again, and a request still carrying anything that looks like a
//!    briefcred token is refused rather than forwarded. A token that reached an
//!    upstream would be a briefcred-shaped string in somebody else's logs, and
//!    a swap that silently missed a header would be invisible without this.
//!
//! No function here ever logs, formats, or returns a header value. The errors
//! name headers and credentials; the values are the secrets.

use std::fmt;

use briefcred_core::minters::http::HttpKind;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use zeroize::Zeroizing;

use crate::proxy::token::looks_synthetic;

/// One credential a session holds, ready to be swapped in.
///
/// `Debug` is written by hand: `master` is the secret this whole crate exists
/// to keep out of the subprocess, and a derived one would print it.
#[derive(Clone)]
pub struct Credential {
    /// The credential's name within its profile, and the `__name__` it answers.
    pub name: String,
    /// Which header its master belongs in, and how it is rendered.
    pub kind: HttpKind,
    /// The real credential.
    pub master: Zeroizing<String>,
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("name", &self.name)
            .field("kind", &self.kind.kind())
            .field("master", &"<redacted>")
            .finish()
    }
}

/// Why a request could not be prepared for forwarding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SwapError {
    /// A header value could not be rebuilt — it would not be a valid header.
    ///
    /// Names the header, never the value: the value is the credential.
    #[error("credential `{credential}` cannot be sent as a `{header}` header value")]
    NotAHeaderValue {
        /// The header the swap was writing.
        header: String,
        /// The credential whose master would not fit in it.
        credential: String,
    },

    /// A synthetic token survived the swap.
    ///
    /// The refusal of last resort: it means a token was somewhere the swap did
    /// not look, and forwarding it would leak a briefcred identifier upstream.
    #[error("a synthetic token is still present in the `{header}` header after the swap")]
    TokenWouldLeak {
        /// The header it was found in.
        header: String,
    },
}

/// The `__name__` placeholder for `credential`.
pub fn placeholder(credential: &str) -> String {
    format!("__{credential}__")
}

/// Substitute the real credentials into `headers`.
///
/// `authorized` is the credential the request's token named, already verified;
/// `session` is every credential the session holds, for the placeholder pass.
/// A request with no token at all passes `None` and gets the placeholder pass
/// only.
pub fn apply(
    headers: &mut HeaderMap,
    session: &[Credential],
    authorized: Option<&Credential>,
) -> Result<(), SwapError> {
    substitute_placeholders(headers, session)?;
    if let Some(credential) = authorized {
        replace_token_header(headers, credential)?;
    }
    reject_surviving_tokens(headers)
}

/// Replace every `__name__` occurrence with the credential it names.
fn substitute_placeholders(
    headers: &mut HeaderMap,
    session: &[Credential],
) -> Result<(), SwapError> {
    let needles: Vec<(String, &Credential)> = session
        .iter()
        .map(|credential| (placeholder(&credential.name), credential))
        .collect();

    // Collected first because the map cannot be written while it is iterated,
    // and because a value is only rewritten when it actually changed — an
    // untouched header keeps its original bytes exactly.
    let mut rewritten: Vec<(HeaderName, Zeroizing<String>)> = Vec::new();
    for (name, value) in headers.iter() {
        let Ok(text) = value.to_str() else { continue };
        if !needles
            .iter()
            .any(|(needle, _)| text.contains(needle.as_str()))
        {
            continue;
        }
        let mut swapped = Zeroizing::new(text.to_string());
        for (needle, credential) in &needles {
            if swapped.contains(needle.as_str()) {
                *swapped = swapped.replace(needle.as_str(), &credential.master);
            }
        }
        rewritten.push((name.clone(), swapped));
    }

    for (name, value) in rewritten {
        let header = HeaderValue::from_str(&value).map_err(|_| SwapError::NotAHeaderValue {
            header: name.to_string(),
            credential: "a placeholder".to_string(),
        })?;
        headers.insert(name, sensitive(header));
    }
    Ok(())
}

/// Take the header carrying the token out and put the real one in.
///
/// The whole header goes, not just the token inside it: an `http-header`
/// credential's real value belongs under its own name, and leaving an
/// `Authorization` header behind with the token trimmed out of it would send an
/// empty credential upstream.
fn replace_token_header(headers: &mut HeaderMap, credential: &Credential) -> Result<(), SwapError> {
    let carrying: Vec<HeaderName> = headers
        .iter()
        .filter(|(_, value)| value.to_str().is_ok_and(contains_token))
        .map(|(name, _)| name.clone())
        .collect();
    for name in carrying {
        headers.remove(&name);
    }

    let name = HeaderName::from_bytes(credential.kind.header_name().as_bytes()).map_err(|_| {
        SwapError::NotAHeaderValue {
            header: credential.kind.header_name().to_string(),
            credential: credential.name.clone(),
        }
    })?;
    let value = credential.kind.header_value(&credential.master);
    let value = HeaderValue::from_str(&value).map_err(|_| SwapError::NotAHeaderValue {
        header: name.to_string(),
        credential: credential.name.clone(),
    })?;
    headers.insert(name, sensitive(value));
    Ok(())
}

/// Refuse a request that still carries anything token-shaped.
fn reject_surviving_tokens(headers: &HeaderMap) -> Result<(), SwapError> {
    for (name, value) in headers.iter() {
        if value.to_str().is_ok_and(contains_token) {
            return Err(SwapError::TokenWouldLeak {
                header: name.to_string(),
            });
        }
    }
    Ok(())
}

/// Whether `value` has a briefcred token anywhere in it.
///
/// Anywhere, not just at the start: `Authorization: Bearer bc.…` is the common
/// case, and a token pasted into the middle of some vendor-specific header is
/// exactly the one the final sweep exists to catch.
fn contains_token(value: &str) -> bool {
    value
        .split(|c: char| c.is_ascii_whitespace())
        .any(looks_synthetic)
}

/// Mark a header value so `http`'s own formatting redacts it.
///
/// Belt and braces next to the hand-written `Debug` implementations: nothing
/// here formats a header map, but a future caller that does gets `Sensitive`
/// rather than a credential.
fn sensitive(mut value: HeaderValue) -> HeaderValue {
    value.set_sensitive(true);
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(name: &str, kind: HttpKind, master: &str) -> Credential {
        Credential {
            name: name.to_string(),
            kind,
            master: Zeroizing::new(master.to_string()),
        }
    }

    fn bearer() -> Credential {
        credential("openai", HttpKind::Bearer, "sk-real-key")
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn value_of(map: &HeaderMap, name: &str) -> Option<String> {
        map.get(name).map(|v| v.to_str().unwrap().to_string())
    }

    #[test]
    fn a_bearer_token_is_replaced_by_the_real_key() {
        let mut map = headers(&[("authorization", "Bearer bc.abc.def")]);
        let openai = bearer();
        apply(&mut map, std::slice::from_ref(&openai), Some(&openai)).unwrap();
        assert_eq!(
            value_of(&map, "authorization").as_deref(),
            Some("Bearer sk-real-key")
        );
    }

    #[test]
    fn a_basic_credential_is_sent_as_base64_of_its_user_and_password() {
        let creds = credential("vendor", HttpKind::Basic, "aladdin:opensesame");
        let mut map = headers(&[("authorization", "Bearer bc.abc.def")]);
        apply(&mut map, std::slice::from_ref(&creds), Some(&creds)).unwrap();
        assert_eq!(
            value_of(&map, "authorization").as_deref(),
            Some("Basic YWxhZGRpbjpvcGVuc2VzYW1l")
        );
    }

    #[test]
    fn a_header_credential_replaces_the_whole_authorization_header() {
        let creds = credential(
            "vendor",
            HttpKind::Header {
                name: "X-Api-Key".into(),
            },
            "sk-real-key",
        );
        let mut map = headers(&[("authorization", "Bearer bc.abc.def"), ("accept", "*/*")]);
        apply(&mut map, std::slice::from_ref(&creds), Some(&creds)).unwrap();

        assert_eq!(value_of(&map, "x-api-key").as_deref(), Some("sk-real-key"));
        assert!(
            map.get("authorization").is_none(),
            "the token's header must go, not just its value"
        );
        assert_eq!(value_of(&map, "accept").as_deref(), Some("*/*"));
    }

    #[test]
    fn a_token_in_a_vendor_header_is_swapped_too() {
        let creds = credential(
            "vendor",
            HttpKind::Header {
                name: "X-Api-Key".into(),
            },
            "sk-real-key",
        );
        let mut map = headers(&[("x-api-key", "bc.abc.def")]);
        apply(&mut map, std::slice::from_ref(&creds), Some(&creds)).unwrap();
        assert_eq!(value_of(&map, "x-api-key").as_deref(), Some("sk-real-key"));
    }

    #[test]
    fn a_placeholder_anywhere_in_a_value_is_substituted() {
        let openai = bearer();
        let mut map = headers(&[
            ("x-custom", "prefix __openai__ suffix"),
            ("authorization", "Bearer __openai__"),
        ]);
        apply(&mut map, std::slice::from_ref(&openai), None).unwrap();
        assert_eq!(
            value_of(&map, "x-custom").as_deref(),
            Some("prefix sk-real-key suffix")
        );
        assert_eq!(
            value_of(&map, "authorization").as_deref(),
            Some("Bearer sk-real-key")
        );
    }

    #[test]
    fn every_credential_in_the_session_gets_a_placeholder() {
        let session = vec![
            bearer(),
            credential(
                "stripe",
                HttpKind::Header {
                    name: "X-Stripe".into(),
                },
                "sk-stripe",
            ),
        ];
        let mut map = headers(&[("x-both", "__openai__/__stripe__")]);
        apply(&mut map, &session, None).unwrap();
        assert_eq!(
            value_of(&map, "x-both").as_deref(),
            Some("sk-real-key/sk-stripe")
        );
    }

    #[test]
    fn a_placeholder_naming_something_the_session_lacks_is_left_alone() {
        // Left alone rather than blanked: it is not briefcred's placeholder, so
        // whatever it means is the upstream's business.
        let openai = bearer();
        let mut map = headers(&[("x-custom", "__not_ours__")]);
        apply(&mut map, std::slice::from_ref(&openai), None).unwrap();
        assert_eq!(value_of(&map, "x-custom").as_deref(), Some("__not_ours__"));
    }

    #[test]
    fn headers_that_mention_nothing_are_untouched() {
        let openai = bearer();
        let mut map = headers(&[("accept", "application/json"), ("user-agent", "curl/8")]);
        apply(&mut map, std::slice::from_ref(&openai), None).unwrap();
        assert_eq!(
            value_of(&map, "accept").as_deref(),
            Some("application/json")
        );
        assert_eq!(value_of(&map, "user-agent").as_deref(), Some("curl/8"));
    }

    #[test]
    fn a_token_the_swap_did_not_reach_stops_the_request() {
        // Two headers carrying a token and a `http-header` credential: the
        // swap replaces both, so to reach the sweep the token has to arrive
        // somewhere the swap is not looking — which is what happens when no
        // credential was authorised at all.
        let openai = bearer();
        let mut map = headers(&[("x-leftover", "bc.abc.def")]);
        let err = apply(&mut map, std::slice::from_ref(&openai), None).unwrap_err();
        assert_eq!(
            err,
            SwapError::TokenWouldLeak {
                header: "x-leftover".to_string()
            }
        );
    }

    #[test]
    fn a_master_that_is_not_a_legal_header_value_is_refused_by_name_only() {
        let broken = credential("openai", HttpKind::Bearer, "line one\nline two");
        let mut map = headers(&[("authorization", "Bearer bc.abc.def")]);
        let err = apply(&mut map, std::slice::from_ref(&broken), Some(&broken)).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("openai"), "{text}");
        assert!(
            !text.contains("line one"),
            "the master must not leak: {text}"
        );
    }

    #[test]
    fn no_error_or_debug_output_ever_carries_a_master() {
        let openai = bearer();
        let rendered = format!("{openai:?}");
        assert!(!rendered.contains("sk-real-key"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn a_swapped_header_is_marked_sensitive() {
        let openai = bearer();
        let mut map = headers(&[("authorization", "Bearer bc.abc.def")]);
        apply(&mut map, std::slice::from_ref(&openai), Some(&openai)).unwrap();
        assert!(map.get("authorization").unwrap().is_sensitive());
    }

    #[test]
    fn the_placeholder_is_the_documented_double_underscore_form() {
        assert_eq!(placeholder("openai"), "__openai__");
    }
}
