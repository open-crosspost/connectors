//! The owner's rules for what the agent may do with their account.
//!
//! This is the whole reason the connector exists rather than handing an
//! agent a token that posts as them. The owner says how much may be posted
//! and whether they confirm each post themselves; the connector enforces it
//! inside the enclave, before anything reaches X.
//!
//! Fail-closed: no policy means nothing is posted. A policy this build
//! cannot read refuses posting too — an unknown field is a parse error, not
//! something to ignore, because the field somebody added is probably the
//! restriction they cared about.

pub use connector_core::Counted;
pub use connector_core::policy::{required, Loaded};

/// The env var the owner's policy arrives in.
pub const POLICY_ENV: &str = crate::oauth::POLICY_ENV;

/// Where the owner connects an account and stores its policy.
pub const CONNECT_PAGE: &str = crate::oauth::CONNECT_PAGE;

/// The count namespace of this connector's budget records: never another
/// connector's, never the family's.
pub const COUNT_PREFIX: &str = "x";

/// Serialised, it is what `status` reports: every member, under the name
/// the policy spells it with.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Posts a day for one agent, counted per calling wallet in UTC days.
    /// Optional: absent means no cap of the owner's — the manifest's
    /// per-wallet technical ceiling still applies, from the coordinator.
    pub max_per_day: Option<u32>,
    /// The operations that need the owner: one listed here prepares its
    /// post and leaves it as a task, and the run the platform starts on the
    /// owner's approval carries it out. Absent or empty: none.
    pub confirm: Option<Vec<Confirmable>>,
}

/// An operation the owner may ask to confirm. A name that is not one does
/// not parse, and a policy that does not parse refuses posting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confirmable {
    Post,
}

impl Policy {
    /// Does `operation` need the owner?
    pub fn confirms(&self, operation: Confirmable) -> bool {
        self.confirm.as_ref().is_some_and(|listed| listed.contains(&operation))
    }
}

/// The policy a post needs, or the refusal to answer with.
pub fn require() -> Result<Policy, String> {
    connector_core::policy::required(load(), POLICY_ENV, CONNECT_PAGE)
}

pub fn load() -> Loaded<Policy> {
    connector_core::policy::load(POLICY_ENV)
}

/// The policy as it is stored, byte for byte: what a task is made under,
/// and what an answer to it is judged against. Empty when there is none.
pub fn stored() -> Vec<u8> {
    std::env::var(POLICY_ENV).unwrap_or_default().into_bytes()
}

/// The day's counter for `counted`.
pub fn count_key(day: &str, counted: connector_core::Counted) -> String {
    connector_core::policy::count_key(COUNT_PREFIX, day, counted)
}

/// The text of one post, as X will carry it: one to 280 characters, and
/// not nothing. X's weighted count (URLs, wide characters) is its own to
/// enforce — this is the pre-check every caller can satisfy before the
/// request is built, and what it refuses, X would refuse too.
pub fn check_text(text: &str) -> Result<(), String> {
    if text.trim().is_empty() {
        return Err("`text` is required: the post would be empty".into());
    }
    let chars = text.chars().count();
    if chars > 280 {
        return Err(format!("`text` holds {chars} characters; X carries at most 280"));
    }
    Ok(())
}

/// The policy as `status` reports it: every member, under the name the
/// policy spells it with, `present` beside it.
pub fn view(loaded: Loaded<Policy>) -> serde_json::Value {
    match loaded {
        Loaded::Some(p) => {
            let mut full = serde_json::to_value(&p).unwrap_or(serde_json::json!({}));
            full["present"] = serde_json::json!(true);
            full
        }
        Loaded::None => serde_json::json!({
            "present": false,
            "effect": "nothing can be posted until the owner stores a policy",
        }),
        Loaded::Unreadable(e) => serde_json::json!({"present": true, "readable": false, "error": e}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json: &str) -> Policy {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn a_policy_asks_for_the_owner_by_naming_the_operation() {
        let asks: Policy = policy(r#"{"confirm":["post"]}"#);
        assert!(asks.confirms(Confirmable::Post));
        for quiet in [r#"{}"#, r#"{"confirm":[]}"#, r#"{"confirm":null}"#] {
            let quiet: Policy = policy(quiet);
            assert!(!quiet.confirms(Confirmable::Post));
        }
        // An operation that cannot be confirmed is a policy that cannot be read.
        for unread in [r#"{"confirm":["send"]}"#, r#"{"confirm":["Post"]}"#, r#"{"confirm":"post"}"#] {
            assert!(serde_json::from_str::<Policy>(unread).is_err(), "{unread}");
        }
    }

    #[test]
    fn the_cap_is_the_only_field_and_it_is_optional() {
        assert_eq!(policy(r#"{"max_per_day":7}"#).max_per_day, Some(7));
        assert_eq!(policy(r#"{}"#).max_per_day, None, "no cap of the owner's; the manifest's ceiling still applies");
        assert!(serde_json::from_str::<Policy>(r#"{"max_per_day":5,"allow_delete":true}"#).is_err(),
            "an unknown field is a parse error, not a quieter policy");
    }

    #[test]
    fn the_text_is_one_to_280_characters_and_not_nothing() {
        assert!(check_text("gm").is_ok());
        assert!(check_text("  gm\n").is_ok(), "posted as written; trimmed only for the emptiness check");
        assert!(check_text("").is_err());
        assert!(check_text("   ").is_err());
        assert!(check_text(&"ж".repeat(280)).is_ok());
        let said = check_text(&"ж".repeat(281)).unwrap_err();
        assert!(said.contains("281") && said.contains("280"), "{said}");
    }

    #[test]
    fn the_view_reports_every_member_the_policy_holds() {
        let full = view(Loaded::Some(policy(r#"{"max_per_day":3,"confirm":["post"]}"#)));
        assert_eq!(full["present"], serde_json::json!(true));
        assert_eq!(full["max_per_day"], serde_json::json!(3));
        assert_eq!(full["confirm"], serde_json::json!(["post"]));

        let none = view(Loaded::None);
        assert_eq!(none["present"], serde_json::json!(false));
        assert!(none["effect"].as_str().unwrap().contains("nothing can be posted"));

        let unreadable = view(Loaded::Unreadable("X_POLICY could not be read (x)".into()));
        assert_eq!(unreadable["present"], serde_json::json!(true));
        assert_eq!(unreadable["readable"], serde_json::json!(false));
        assert!(unreadable["error"].as_str().unwrap().contains("could not be read"));
    }

    #[test]
    fn a_refusal_for_want_of_a_policy_tells_the_owner_what_to_store() {
        let said = require_with(Loaded::None);
        assert!(said.starts_with("policy_denied: the secrets row this call names holds no X_POLICY"), "{said}");
        assert!(said.contains(CONNECT_PAGE) && said.contains("access condition"), "{said}");
    }

    fn require_with(loaded: Loaded<Policy>) -> String {
        connector_core::policy::required(loaded, POLICY_ENV, CONNECT_PAGE).unwrap_err()
    }
}
