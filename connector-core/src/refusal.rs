//! The refusal vocabulary, and the helpers that spell it.
//!
//! An agent branches on the *prefix* of `error` — the sentence gets reworded,
//! the prefix does not — so the prefixes here are the connector family's
//! contract, and every helper a connector refuses with passes through one of
//! them:
//!
//! | prefix | terminal? | what it means |
//! |---|---|---|
//! | `no credential reached this run` | until the owner connects or grants | nothing reached the run: not connected, not granted, wrong `secrets_ref` |
//! | `credential_expired:` | yes | the refresh token is dead; the owner reconnects; retrying does nothing |
//! | `credential_rejected:` | yes | the live token was refused mid-flight; the owner reconnects |
//! | `scope_missing:` | yes | the credential was not granted the scope the operation needs |
//! | `rate_limited:` | no | the outside service is throttling; nothing was changed; wait, then retry |
//! | `policy_denied:` | not by retrying | the owner's rules refused; change the request or ask the owner |
//! | `operation_limit_reached` | no, `retry_after_seconds` | a connector's cap on one operation; a refused attempt still counts |
//! | `X refused …: HTTP 4…` | judge by the service | the request was refused outright: nothing happened |
//! | `… outcome is unknown` | never resend blind | the request went out, or may have; surface for owner review |
//!
//! A refusal names no credential value and, where the answer lands on chain
//! and the sentence would carry it, no private subject either: the helpers
//! take what to say about a thing, not the thing.


/// A posting the connector may have made and did not get an answer for, or
/// one the service refused outright. Kept apart because the two must never
/// be answered the same way: an unknown outcome is *not* sent again blind.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// The service answered no: nothing happened, and the refusal says why.
    Refused(String),
    /// The request went out, or may have, and its outcome is unknown.
    Unknown(String),
}

impl Outcome {
    pub fn refusal(self) -> String {
        match self {
            Outcome::Refused(s) | Outcome::Unknown(s) => s,
        }
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, Outcome::Unknown(_))
    }
}

/// The owner's OAuth client or ours is misconfigured: the refresh token has
/// no client that may use it. Terminal until someone stores a working client.
pub fn no_client(refresh_env: &str, client_envs: (&str, &str), connect_url: &str) -> String {
    format!(
        "a refresh token reached this run with no OAuth client to use it with. A token only works \
         with the client that issued it: store {0} and {1} beside {2}, or connect the account \
         through {connect_url}, whose client this connector carries itself.",
        client_envs.0, client_envs.1, refresh_env
    )
}

/// No credential arrived at all: not connected, not granted, or the call
/// names the wrong `secrets_ref`. Terminal until the owner connects or grants.
pub fn no_credential(refresh_env: &str, client_envs: (&str, &str), connect_url: &str) -> String {
    format!(
        "no credential reached this run. Connect an account at {connect_url} — that stores \
         {refresh_env} — or store your own {0}, {1} and {refresh_env} and name that row in the \
         call's `secrets_ref`. Nothing a caller sends in the body can stand in for them.",
        client_envs.0, client_envs.1
    )
}

/// The refresh token is dead: revoked, expired, or issued by a client in
/// testing mode. Terminal — the owner reconnects; retrying will not help.
pub fn credential_expired(service: &str, detail: &str, connect_url: &str) -> String {
    format!(
        "credential_expired: {service} refused the refresh token ({detail}). It is gone for good — \
         revoked, expired, or issued by an OAuth client still in testing mode. The owner connects \
         the account again at {connect_url}, or, with an OAuth app of their own, stores a new \
         refresh token in the same secrets row; retrying will not help."
    )
}

/// The live access token was refused: probably revoked mid-flight. Terminal —
/// the owner reconnects.
pub fn credential_rejected(service: &str, detail: &str, connect_url: &str) -> String {
    format!(
        "credential_rejected: {service} refused the access token ({detail}). It was probably \
         revoked mid-flight; the owner reconnects the account at {connect_url}."
    )
}

/// The credential works but does not carry the scope this operation needs.
/// Terminal — the owner consents again, for the missing scope.
pub fn scope_missing(scope: &str, service: &str) -> String {
    format!("scope_missing: the credential was not granted `{scope}`, which this operation needs; {service} was not asked")
}

/// The service is throttling. Not terminal — wait, then retry; nothing was
/// changed.
pub fn rate_limited(service: &str, what: &str) -> String {
    format!("rate_limited: {service} is refusing more requests for now ({what}). Wait and retry; nothing was changed.")
}

/// The owner's rules refused. Never fixed by retrying: change the request or
/// ask the owner.
pub fn policy_denied(detail: String) -> String {
    format!("policy_denied: {detail}")
}

/// The service refused an operation outright, in its own words. Nothing
/// happened; judge by what it said.
pub fn upstream_refused(service: &str, path: &str, status: u16, detail: &str) -> String {
    format!("{service} refused {path}: HTTP {status} {detail}")
}

/// The request could not be completed, or the service answered a server
/// error, and the operation may still have happened. The caller looks before
/// doing it again; a connector confirms it *never* reports this as refused.
pub fn outcome_unknown(service: &str, path: &str, detail: &str) -> String {
    format!(
        "{service} could not complete {path}: {detail}. The request went out, or may have, and its \
         outcome is unknown: do not resend blind — check the account before trying again, and say \
         so to the owner"
    )
}

/// The connector's own technical ceiling, as the coordinator reads it out of
/// the manifest's `limits`: answered with the seconds left in the window.
pub fn operation_limit_reached(operation: &str, cap: u32, retry_after_seconds: u64) -> String {
    format!("operation_limit_reached: {cap} {operation}s a day are used; the cap resets in {retry_after_seconds}s")
}

/// Seconds until the next UTC midnight — when every day-windowed count
/// resets. `now_ms` is the run's wall clock in milliseconds. Rounded up: a
/// second from midnight is one second to wait, never zero.
pub fn retry_after_seconds(now_ms: u64) -> u64 {
    let into_day = now_ms % 86_400_000;
    (86_400_000 - into_day + 999) / 1000
}

/// A refusal the owner must act on, marked as terminal for the caller.
pub fn is_terminal(refusal: &str) -> bool {
    for prefix in ["credential_expired:", "credential_rejected:", "scope_missing:"] {
        if refusal.starts_with(prefix) {
            return true;
        }
    }
    // A missing policy is also terminal until the owner stores one; the word
    // rides inside `policy_denied:`.
    refusal.starts_with("policy_denied: ") && refusal.contains("no policy")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_helper_spells_its_prefix_and_says_what_to_do() {
        let c = credential_expired("X", "invalid_grant", "https://example.test/connect/x");
        assert!(c.starts_with("credential_expired: ") && c.contains("invalid_grant"), "{c}");
        assert!(c.contains("retrying will not help"), "{c}");

        let r = credential_rejected("X", "HTTP 401", "https://example.test/connect/x");
        assert!(r.starts_with("credential_rejected: ") && r.contains("401"), "{r}");

        let s = scope_missing("tweet.write", "X");
        assert!(s.starts_with("scope_missing: ") && s.contains("tweet.write"), "{s}");
        assert!(s.contains("was not asked"), "a scope refusal costs no API call: {s}");

        let t = rate_limited("X", "quota");
        assert!(t.starts_with("rate_limited: ") && t.contains("nothing was changed"), "{t}");

        let p = policy_denied("3 of the owner's 3 posts a day are used".into());
        assert!(p.starts_with("policy_denied: "), "{p}");

        let u = upstream_refused("X", "/2/tweets", 400, "could not authenticate");
        assert!(u.starts_with("X refused /2/tweets: HTTP 400 "), "{u}");

        let o = outcome_unknown("X", "/2/tweets", "connection reset");
        assert!(o.contains("outcome is unknown") && o.contains("do not resend blind"), "{o}");
    }

    #[test]
    fn the_dual_credential_refusals_name_the_rows_that_fix_them() {
        let n = no_credential("X_REFRESH_TOKEN", ("X_CLIENT_ID", "X_CLIENT_SECRET"), "https://c.test/x");
        assert!(n.contains("X_REFRESH_TOKEN") && n.contains("X_CLIENT_ID"), "{n}");
        assert!(n.contains("secrets_ref"), "{n}");
        let m = no_client("X_REFRESH_TOKEN", ("X_CLIENT_ID", "X_CLIENT_SECRET"), "https://c.test/x");
        assert!(m.contains("client that issued it"), "{m}");
        assert!(!m.contains("no credential reached"), "{m}");
    }

    #[test]
    fn the_limit_refusal_names_the_cap_and_the_reset() {
        let l = operation_limit_reached("post", 500, 43200);
        assert!(l.starts_with("operation_limit_reached: 500 posts"), "{l}");
        assert!(l.contains("43200s"), "{l}");
    }

    /// Every day-window count resets at UTC midnight: the seconds to wait are
    /// what is left of the day.
    #[test]
    fn retry_after_runs_to_utc_midnight() {
        assert_eq!(retry_after_seconds(0), 86_400);
        assert_eq!(retry_after_seconds(86_400_000 - 1_000), 1);
        assert_eq!(retry_after_seconds(86_400_000 + 500), 86_400);
        // Halfway through a day: half a day to wait.
        assert_eq!(retry_after_seconds(86_400_000 / 2), 43_200);
    }

    #[test]
    fn terminality_is_read_off_the_prefix() {
        for terminal in [
            credential_expired("X", "x", "u"),
            credential_rejected("X", "x", "u"),
            scope_missing("tweet.write", "X"),
            policy_denied("no policy reached this run: the owner stores one at u".into()),
        ] {
            assert!(is_terminal(&terminal), "{terminal}");
        }
        for retryable in [
            rate_limited("X", "quota"),
            upstream_refused("X", "/2/tweets", 500, "backend"),
            outcome_unknown("X", "/2/tweets", "reset"),
        ] {
            assert!(!is_terminal(&retryable), "{retryable}");
        }
        assert!(!is_terminal(&policy_denied("3 of the owner's 3 posts a day are used".into())));
    }

    #[test]
    fn an_unknown_outcome_is_known_as_such() {
        let lost = Outcome::Unknown(outcome_unknown("X", "/2/tweets", "reset"));
        assert!(lost.is_unknown());
        assert!(lost.refusal().contains("unknown"));
        let refused = Outcome::Refused(rate_limited("X", "quota"));
        assert!(!refused.is_unknown());
    }

}
