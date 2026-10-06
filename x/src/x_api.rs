//! X's REST API, as this connector reaches it: the two endpoints a posting
//! connector needs, and the mapping of every answer to the family's
//! refusals.
//!
//! The mapping is where the semantics live, so it is exact:
//!
//! * **201 on a post** — the post went out; its id is the evidence.
//! * **429** — X is throttling: `rate_limited:`, nothing was posted,
//!   retryable after the wait.
//! * **401** — the access token was refused mid-flight:
//!   `credential_rejected:`, the owner reconnects.
//! * **403** — either the credential does not carry the scope the call
//!   needs (`scope_missing:`) or X refuses the account itself; the detail
//!   decides.
//! * **other 4xx** — X refused the request outright, in its own words:
//!   nothing happened, judge it by what X said.
//! * **5xx, or the request never answered** — the request went out, or may
//!   have, and its outcome is UNKNOWN. For a POST this is the one answer
//!   that must never be retried blind: the post MAY have gone out. Kept
//!   apart from every refusal, and never reported as one.
//!
//! A GET has no such stakes: its unknowns are ordinary errors, safe to
//! retry.

use crate::oauth::{self, Granted};
use crate::runtime::{Method, Response, Transport};
use connector_core::refusal::{self, Outcome};
use serde_json::Value;

const API_BASE: &str = "https://api.x.com/2";
const TIMEOUT_NOTE: &str = "X could not be reached";

/// The connected account: what `me` answers, and what a post's url is built
/// from. All of it public — a post's own url names the handle anyway.
#[derive(Debug, Clone, PartialEq)]
pub struct Account {
    pub id: String,
    pub username: String,
    pub name: String,
}

/// The scope `post` needs.
pub const TWEET_WRITE: &str = "tweet.write";
/// The scope `me` needs (X's `/2/users/me` answers `users.read` + `tweet.read`).
pub const USERS_READ: &str = "users.read";

/// The connected account, as X answers it. A GET whose outcome is unknown
/// is an ordinary error — nothing was changed by asking.
pub fn me(transport: &dyn Transport, granted: &Granted) -> Result<Account, String> {
    if !granted.grants(USERS_READ) {
        return Err(refusal::scope_missing(USERS_READ, "X"));
    }
    let response = ask(transport, Method::Get, &format!("{API_BASE}/users/me"), granted.access_token.as_str(), None)?;
    match response.status {
        200 => {
            let value = response.json();
            let data = value.get("data").unwrap_or(&Value::Null);
            let field = |name: &str| -> Result<String, String> {
                data.get(name)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| format!("X's answer to /2/users/me carries no {name}"))
            };
            return Ok(Account { id: field("id")?, username: field("username")?, name: field("name")? });
        }
        401 => Err(refusal::credential_rejected("X", &x_word(&response), oauth::CONNECT_PAGE)),
        403 => Err(refusal::scope_missing(USERS_READ, "X")),
        429 => Err(refusal::rate_limited("X", "quota")),
        _ => Err(upstream(response, "/2/users/me")),
    }
}

/// One post, answered as its tweet id, or as [`Outcome`]: refused outright
/// (nothing happened), or unknown (it MAY have gone out).
pub fn tweet(transport: &dyn Transport, granted: &Granted, text: &str) -> Result<String, Outcome> {
    let body = serde_json::to_vec(&serde_json::json!({ "text": text })).unwrap_or_default();
    let response = match ask(
        transport,
        Method::Post,
        &format!("{API_BASE}/tweets"),
        granted.access_token.as_str(),
        Some(&body),
    ) {
        Ok(response) => response,
        Err(network) => return Err(Outcome::Unknown(refusal::outcome_unknown("X", "/2/tweets", &network))),
    };
    match response.status {
        201 => match response.json().get("data").and_then(|d| d.get("id")).and_then(Value::as_str) {
            Some(id) => Ok(id.to_string()),
            None => Err(Outcome::Unknown(refusal::outcome_unknown(
                "X",
                "/2/tweets",
                "X answered 201 with no post id",
            ))),
        },
        429 => Err(Outcome::Refused(refusal::rate_limited("X", "quota"))),
        401 => Err(Outcome::Refused(refusal::credential_rejected("X", &x_word(&response), oauth::CONNECT_PAGE))),
        403 => {
            // A 403 on /2/tweets is X refusing THIS post: the credential may
            // lack the scope, the account may be restricted, the text may
            // be refused. What X said decides; the detail is X's own words.
            if !granted.grants(TWEET_WRITE) {
                Err(Outcome::Refused(refusal::scope_missing(TWEET_WRITE, "X")))
            } else {
                Err(Outcome::Refused(upstream(response, "/2/tweets")))
            }
        }
        status if (400..500).contains(&status) => Err(Outcome::Refused(upstream(response, "/2/tweets"))),
        _ => Err(Outcome::Unknown(refusal::outcome_unknown("X", "/2/tweets", &format!("HTTP {}", response.status)))),
    }
}

/// The one HTTPS exchange, with the bearer on it.
fn ask(transport: &dyn Transport, method: Method, path: &str, bearer: &str, body: Option<&[u8]>) -> Result<Response, String> {
    transport
        .send(
            method,
            path,
            &[
                ("Authorization", format!("Bearer {bearer}")),
                ("Content-Type", "application/json".to_string()),
            ],
            body,
        )
        .map_err(|e| format!("{TIMEOUT_NOTE}: {e}"))
}

/// X's own words for a refusal: the detail of its problem object, never a
/// page of JSON. X answers errors as `{"title", "detail", "status"}` or
/// `{"errors": [{"message"}]}`; either way the agent gets the sentence, and
/// the post that was refused gets it in full.
fn x_word(response: &Response) -> String {
    let value = response.json();
    for member in ["detail", "title"] {
        if let Some(word) = value.get(member).and_then(Value::as_str).filter(|w| !w.trim().is_empty()) {
            return word.to_string();
        }
    }
    if let Some(word) = value.get("errors").and_then(Value::as_array).and_then(|e| e.first()).and_then(|e| e.get("message")).and_then(Value::as_str) {
        return word.to_string();
    }
    format!("HTTP {}", response.status)
}

fn upstream(response: Response, path: &str) -> String {
    refusal::upstream_refused("X", path, response.status, &x_word(&response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::testing::MockTransport;

    fn granted(scope: &str) -> Granted {
        Granted { access_token: "AT".into(), scope: scope.into(), rotated_to: None, expires_in: 7200 }
    }

    fn ok_tweet() -> Result<Response, String> {
        MockTransport::ok(201, serde_json::json!({"data": {"id": "1901", "text": "gm"}}))
    }

    fn refused(status: u16, detail: &str) -> Result<Response, String> {
        MockTransport::ok(status, serde_json::json!({"detail": detail, "status": status, "title": "refused"}))
    }

    #[test]
    fn me_reads_the_handle_the_ui_displays() {
        let transport = MockTransport::with(vec![MockTransport::ok(
            200,
            serde_json::json!({"data": {"id": "16282460", "username": "elliotBraem", "name": "Elliot"}}),
        )]);
        let account = me(&transport, &granted("users.read tweet.write")).unwrap();
        assert_eq!(account.username, "elliotBraem");
        assert_eq!(account.id, "16282460");
        assert_eq!(account.name, "Elliot");
        let (method, url, body) = &transport.seen.borrow()[0];
        assert_eq!((method, url.as_str(), body.is_empty()), (&Method::Get, "https://api.x.com/2/users/me", true));
    }

    #[test]
    fn me_refuses_before_x_when_the_scope_is_not_granted() {
        let transport = MockTransport::with(vec![]);
        let said = me(&transport, &granted("tweet.write")).unwrap_err();
        assert!(said.starts_with("scope_missing: ") && said.contains(USERS_READ), "{said}");
        assert!(transport.seen.borrow().is_empty(), "X was not asked");
    }

    /// Every mapping of /2/tweets: the post that left, the ones that
    /// refused outright, and the two unknowns that must never be retried.
    #[test]
    fn a_posts_outcome_is_posted_refused_or_unknown() {
        let g = granted("tweet.write users.read");

        let posted = tweet(&MockTransport::with(vec![ok_tweet()]), &g, "gm").unwrap();
        assert_eq!(posted, "1901");

        // X's throttle: nothing was posted; wait, then retry.
        let throttled = tweet(&MockTransport::with(vec![refused(429, "Rate limit exceeded")]), &g, "gm").unwrap_err();
        assert!(matches!(&throttled, Outcome::Refused(s) if s.starts_with("rate_limited: ")), "{throttled:?}");

        // A dead access token mid-flight: the owner reconnects.
        let dead = tweet(&MockTransport::with(vec![refused(401, "Unauthorized")]), &g, "gm").unwrap_err();
        assert!(matches!(&dead, Outcome::Refused(s) if s.starts_with("credential_rejected: ")), "{dead:?}");

        // The scope missing: refused before the call, never a 403 from X.
        let no_scope = granted("users.read");
        let refused_scope = tweet(&MockTransport::with(vec![refused(403, "not allowed")]), &no_scope, "gm").unwrap_err();
        assert!(matches!(&refused_scope, Outcome::Refused(s) if s.starts_with("scope_missing: ")), "{refused_scope:?}");

        // A 403 with the scope granted is X's own word on this post.
        let account_refused = tweet(&MockTransport::with(vec![refused(403, "client-not-enrolled")]), &g, "gm").unwrap_err();
        assert!(matches!(&account_refused, Outcome::Refused(s) if s.starts_with("X refused /2/tweets: HTTP 403 ")), "{account_refused:?}");

        // Other 4xx: refused outright, in X's own words.
        let bad = tweet(&MockTransport::with(vec![refused(400, "could not authenticate you")]), &g, "gm").unwrap_err();
        assert!(matches!(&bad, Outcome::Refused(s) if s.contains("could not authenticate you")), "{bad:?}");

        // A 5xx: the request went out, or may have — UNKNOWN.
        let backend = tweet(&MockTransport::with(vec![refused(503, "backend")]), &g, "gm").unwrap_err();
        assert!(backend.is_unknown(), "{backend:?}");
        let said = backend.refusal();
        assert!(said.contains("do not resend blind"), "{said}");

        // No answer at all: UNKNOWN, the same discipline.
        let lost = tweet(&MockTransport::with(vec![MockTransport::network("connection reset")]), &g, "gm").unwrap_err();
        assert!(lost.is_unknown(), "{lost:?}");
    }

    /// An X answer this build cannot read as a post is not a refusal: it is
    /// an unknown outcome, and no id is drawn from it.
    #[test]
    fn a_post_answer_that_names_no_id_is_an_unknown_outcome() {
        let g = granted("tweet.write");
        let odd = tweet(
            &MockTransport::with(vec![MockTransport::ok(201, serde_json::json!({"data": {"text": "gm"}}))]),
            &g,
            "gm",
        ).unwrap_err();
        assert!(odd.is_unknown(), "{odd:?}");
    }

    /// The network refusal of the transport is worded so a caller can only
    /// say "unknown": the port cannot know whether the request left.
    #[test]
    fn an_unknown_outcome_says_what_it_is_and_never_resends() {
        let said = refusal::outcome_unknown("X", "/2/tweets", "connection reset");
        assert!(said.contains("do not resend blind"), "{said}");
        assert!(said.contains("MAY have") || said.contains("may have"), "{said}");
    }
}
