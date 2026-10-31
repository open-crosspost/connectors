//! X's REST API, as this connector reaches it: the four endpoints a
//! managing connector needs (posting, reposting, unstamping, a post
//! withdrawn), and the mapping of every answer to the family's refusals.
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
/// (nothing happened), or unknown (it MAY have gone out). `reply_to` is
/// the resolved snowflake id the post answers — [`resolve_tweet_ref`]
/// got it there; absent, the post is standalone.
pub fn tweet(
    transport: &dyn Transport,
    granted: &Granted,
    text: &str,
    reply_to: Option<&str>,
    poll: Option<&Poll>,
) -> Result<String, Outcome> {
    let mut body_value = serde_json::json!({ "text": text });
    if let Some(id) = reply_to {
        // Bare `in_reply_to_tweet_id` is v1.1-only: /2/tweets wants the reply object.
        body_value["reply"] = serde_json::json!({ "in_reply_to_tweet_id": id.trim() });
    }
    if let Some(poll) = poll {
        body_value["poll"] = serde_json::json!({ "options": poll.options, "duration_minutes": poll.duration_minutes });
    }
    let body = serde_json::to_vec(&body_value).unwrap_or_default();
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

/// A repost, as X now spells retweet: `POST /2/users/:id/retweets`, the id
/// naming the REPOSTER (the account whose stamp it is), the body the tweet
/// being reposted. The answer's `data.retweeted` is the truth of it: true
/// when the repost is new, false when the account had already made one —
/// nothing to retry in either case, and X's own words when it refuses.
pub fn retweet(transport: &dyn Transport, granted: &Granted, me_id: &str, tweet_id: &str) -> Result<bool, Outcome> {
    let path = format!("{API_BASE}/users/{me_id}/retweets");
    let body = serde_json::to_vec(&serde_json::json!({ "tweet_id": tweet_id })).unwrap_or_default();
    match repost_call(transport, granted, Method::Post, &path, Some(&body))? {
        Some(retweeted) => Ok(retweeted),
        // A 200 with no word on whether the repost is there: the stamp may
        // be on either way, and no id is drawn from an answer that names none.
        None => Err(Outcome::Unknown(refusal::outcome_unknown(
            "X",
            "/2/users/…/retweets",
            "X answered 200 with no `retweeted`",
        ))),
    }
}

/// A repost withdrawn: `DELETE /2/users/:id/retweets/:tweet_id`. Only the
/// account's own repost is affected — X refuses anyone else's — so an
/// unknown outcome repeats nothing X would double: the caller decides.
pub fn unretweet(transport: &dyn Transport, granted: &Granted, me_id: &str, tweet_id: &str) -> Result<(), Outcome> {
    let path = format!("{API_BASE}/users/{me_id}/retweets/{tweet_id}");
    repost_call(transport, granted, Method::Delete, &path, None).map(|_| ())
}

/// The repost exchange itself, answered as X's word on the stamp — `Some`
/// when the answer names it, `None` when it does not. A `retweet` lives on
/// the word (the stamp is its evidence); an `unretweet` lives on the 200 —
/// the stamp's absence is what the endpoint's answer is about, and the
/// boolean rides with it wherever X carries one.
fn repost_call(
    transport: &dyn Transport,
    granted: &Granted,
    method: Method,
    path: &str,
    body: Option<&[u8]>,
) -> Result<Option<bool>, Outcome> {
    let response = match ask(transport, method, path, granted.access_token.as_str(), body) {
        Ok(response) => response,
        Err(network) => return Err(Outcome::Unknown(refusal::outcome_unknown("X", "/2/users/…/retweets", &network))),
    };
    match response.status {
        200 => Ok(response.json().get("data").and_then(|d| d.get("retweeted")).and_then(Value::as_bool)),
        429 => Err(Outcome::Refused(refusal::rate_limited("X", "quota"))),
        401 => Err(Outcome::Refused(refusal::credential_rejected("X", &x_word(&response), oauth::CONNECT_PAGE))),
        403 => {
            // A 403 here is X refusing THIS repost: the credential may lack
            // the scope, the account may be restricted, the tweet may be one
            // X does not allow this account to stamp. X's words tell them apart.
            if !granted.grants(TWEET_WRITE) {
                Err(Outcome::Refused(refusal::scope_missing(TWEET_WRITE, "X")))
            } else {
                Err(Outcome::Refused(upstream(response, "/2/users/…/retweets")))
            }
        }
        status if (400..500).contains(&status) => Err(Outcome::Refused(upstream(response, "/2/users/…/retweets"))),
        _ => Err(Outcome::Unknown(refusal::outcome_unknown(
            "X",
            "/2/users/…/retweets",
            &format!("HTTP {}", response.status),
        ))),
    }
}

/// One post withdrawn from X entirely: `DELETE /2/tweets/:id`, X refusing
/// anything the account did not author. A repeat of a delete that already
/// left is a 404 in X's own words — the outcome that answers "is it gone?".
pub fn delete_tweet(transport: &dyn Transport, granted: &Granted, tweet_id: &str) -> Result<(), Outcome> {
    let path = format!("{API_BASE}/tweets/{tweet_id}");
    let response = match ask(transport, Method::Delete, &path, granted.access_token.as_str(), None) {
        Ok(response) => response,
        Err(network) => return Err(Outcome::Unknown(refusal::outcome_unknown("X", "/2/tweets/:id", &network))),
    };
    match response.status {
        200 => Ok(()),
        429 => Err(Outcome::Refused(refusal::rate_limited("X", "quota"))),
        401 => Err(Outcome::Refused(refusal::credential_rejected("X", &x_word(&response), oauth::CONNECT_PAGE))),
        403 => {
            if !granted.grants(TWEET_WRITE) {
                Err(Outcome::Refused(refusal::scope_missing(TWEET_WRITE, "X")))
            } else {
                Err(Outcome::Refused(upstream(response, "/2/tweets/:id")))
            }
        }
        status if (400..500).contains(&status) => Err(Outcome::Refused(upstream(response, "/2/tweets/:id"))),
        _ => Err(Outcome::Unknown(refusal::outcome_unknown("X", "/2/tweets/:id", &format!("HTTP {}", response.status)))),
    }
}

/// The resolution of any input member that names a tweet — a bare id, or
/// the id inside a status url: `https://x.com/<user>/status/<id>`,
/// `twitter.com` and `www.` included, query and fragment carried along or
/// not. The refusal spells the member it was handed under: a caller's own
/// error says its own name. Everything else is refused, in that sentence,
/// before anything leaves and at no cost: agents hand URLs around, so they
/// are welcome here too.
pub fn resolve_tweet_ref(param: &str, raw: &str) -> Result<String, String> {
    let refusal = |why: String| format!("`{param}` must be a tweet id or a status url: {why}");
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(refusal(format!("`{param}` is empty")));
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Ok(trimmed.to_string());
    }
    let (scheme, rest) = match trimmed.split_once("://") {
        Some(parts) => parts,
        None => return Err(refusal(format!("`{trimmed}` is neither an id nor a url"))),
    };
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return Err(refusal(format!("the scheme is `{scheme}`, not http(s)")));
    }
    let (host, path) = match rest.split_once('/') {
        Some(parts) => parts,
        None => return Err(refusal(format!("`{rest}` carries no path"))),
    };
    let host = host.strip_prefix("www.").unwrap_or(host).to_ascii_lowercase();
    if !matches!(host.as_str(), "x.com" | "twitter.com") {
        return Err(refusal(format!("`{host}` is not an X host")));
    }
    // The status path: every segment up to and after `status`, cut clean of
    // its query and fragment.
    let mut segments = path.split('/').map(|segment| segment.split(['?', '#']).next().unwrap_or(""));
    let status_named = segments.by_ref().any(|segment| segment == "status");
    if !status_named {
        return Err(refusal(format!("`{host}{path}` carries no `status` path")));
    }
    match segments.next() {
        Some(id) if !id.is_empty() && id.chars().all(|c| c.is_ascii_digit()) => Ok(id.to_string()),
        Some(other) => Err(refusal(format!("`{other}` where `status` is followed by a tweet id"))),
        None => Err(refusal(format!("`{host}{path}` carries no tweet id after `status`"))),
    }
}

/// A poll a post carries, as X's /2/tweets `poll` body member wants it: 2 to
/// 4 options of at most 25 characters each, open from 5 minutes (X's floor)
/// to a week — 1440 minutes are a day, 10080 are 7.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Poll {
    pub options: Vec<String>,
    pub duration_minutes: u32,
}

/// The poll out of the run's input value, or the sentence its own refusals
/// read: a `poll` that is not a poll object, options that are few or too
/// long or nothing, a duration X would not open. Everything here refuses
/// pre-run, at no cost, exactly like a bad `reply_to`.
pub fn poll_of(value: &Value) -> Result<Poll, String> {
    let poll: Poll = serde_json::from_value(value.clone()).map_err(|e| format!("`poll` is not a poll: {e}"))?;
    if !(2..=4).contains(&(poll.options.len())) {
        return Err(format!("`poll` carries {} options; X opens a poll with 2 to 4", poll.options.len()));
    }
    for option in &poll.options {
        if option.trim().is_empty() || option.chars().count() > 25 {
            return Err("`poll` options are 1 to 25 characters; X refuses the rest".to_string());
        }
    }
    if !(5..=10080).contains(&poll.duration_minutes) {
        return Err(format!(
            "`poll` runs {} minutes; X opens a poll for 5 minutes to 7 days",
            poll.duration_minutes
        ));
    }
    Ok(poll)
}

/// One HTTPS exchange, with the bearer on it.
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

        let posted = tweet(&MockTransport::with(vec![ok_tweet()]), &g, "gm", None, None).unwrap();
        assert_eq!(posted, "1901");

        // X's throttle: nothing was posted; wait, then retry.
        let throttled = tweet(&MockTransport::with(vec![refused(429, "Rate limit exceeded")]), &g, "gm", None, None).unwrap_err();
        assert!(matches!(&throttled, Outcome::Refused(s) if s.starts_with("rate_limited: ")), "{throttled:?}");

        // A dead access token mid-flight: the owner reconnects.
        let dead = tweet(&MockTransport::with(vec![refused(401, "Unauthorized")]), &g, "gm", None, None).unwrap_err();
        assert!(matches!(&dead, Outcome::Refused(s) if s.starts_with("credential_rejected: ")), "{dead:?}");

        // The scope missing: refused before the call, never a 403 from X.
        let no_scope = granted("users.read");
        let refused_scope = tweet(&MockTransport::with(vec![refused(403, "not allowed")]), &no_scope, "gm", None, None).unwrap_err();
        assert!(matches!(&refused_scope, Outcome::Refused(s) if s.starts_with("scope_missing: ")), "{refused_scope:?}");

        // A 403 with the scope granted is X's own word on this post.
        let account_refused = tweet(&MockTransport::with(vec![refused(403, "client-not-enrolled")]), &g, "gm", None, None).unwrap_err();
        assert!(matches!(&account_refused, Outcome::Refused(s) if s.starts_with("X refused /2/tweets: HTTP 403 ")), "{account_refused:?}");

        // Other 4xx: refused outright, in X's own words.
        let bad = tweet(&MockTransport::with(vec![refused(400, "could not authenticate you")]), &g, "gm", None, None).unwrap_err();
        assert!(matches!(&bad, Outcome::Refused(s) if s.contains("could not authenticate you")), "{bad:?}");

        // A 5xx: the request went out, or may have — UNKNOWN.
        let backend = tweet(&MockTransport::with(vec![refused(503, "backend")]), &g, "gm", None, None).unwrap_err();
        assert!(backend.is_unknown(), "{backend:?}");
        let said = backend.refusal();
        assert!(said.contains("do not resend blind"), "{said}");

        // No answer at all: UNKNOWN, the same discipline.
        let lost = tweet(&MockTransport::with(vec![MockTransport::network("connection reset")]), &g, "gm", None, None).unwrap_err();
        assert!(lost.is_unknown(), "{lost:?}");
    }

    /// The reply, on the wire: the /2/tweets body carries the reply object
    /// the id names, and the text beside it.
    #[test]
    fn a_reply_posts_the_reply_object_on_the_wire() {
        let g = granted("tweet.write");
        let transport = MockTransport::with(vec![ok_tweet()]);
        let posted = tweet(&transport, &g, "gm", Some("1901"), None).unwrap();
        assert_eq!(posted, "1901");
        let body = serde_json::from_slice::<serde_json::Value>(&transport.seen.borrow()[0].2).unwrap();
        assert_eq!(body["reply"]["in_reply_to_tweet_id"], serde_json::json!("1901"));
        assert_eq!(body["text"], serde_json::json!("gm"));
    }

    /// A standalone post names no reply member at all: absent means absent,
    /// not null and not an empty reply.
    #[test]
    fn a_standalone_post_names_no_reply_member() {
        let g = granted("tweet.write");
        let transport = MockTransport::with(vec![ok_tweet()]);
        tweet(&transport, &g, "gm", None, None).unwrap();
        let body = serde_json::from_slice::<serde_json::Value>(&transport.seen.borrow()[0].2).unwrap();
        assert!(body.get("reply").is_none(), "no reply member on a standalone post");
    }

    /// What `reply_to` resolves: a bare id, or the id in a status url of
    /// either host — and what it refuses, all of it before anything runs.
    #[test]
    fn the_reply_target_resolves_to_a_snowflake_id() {
        for (given, want) in [
            ("1901", "1901"),
            (" 1901 ", "1901"),
            ("https://x.com/elliot/status/1901", "1901"),
            ("https://x.com/elliot/status/1901?cmt=yes#m", "1901"),
            ("https://www.x.com/elliot/status/1901", "1901"),
            ("https://twitter.com/elliot/status/1901", "1901"),
            ("http://x.com/elliot/status/1901", "1901"),
            ("https://x.com/i/web/status/1901", "1901"),
            ("HTTPS://x.com/elliot/status/1901", "1901"),
        ] {
            assert_eq!(resolve_tweet_ref("reply_to", given).unwrap(), want, "`{given}` did not resolve");
        }
        for bad in [
            "",
            "   ",
            "not a tweet",
            "justtext.com/status/1901",
            "ftp://x.com/elliot/status/1901",
            "https://example.com/elliot/status/1901",
            "https://x.com/elliot/posts/1901",
            "https://x.com/elliot/status/",
            "https://x.com/elliot/status/not-a-tweet",
        ] {
            let said = resolve_tweet_ref("reply_to", bad).unwrap_err();
            assert!(said.starts_with("`reply_to` must be a tweet id or a status url: "), "{said}");
        }
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
            None,
            None,
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

    /// The same resolution under any input member's name: the refusal says
    /// the name it was handed under, so a caller's error is its own.
    #[test]
    fn the_tweet_ref_refusal_names_the_member_it_was_handed_under() {
        let said = resolve_tweet_ref("tweet_id", "not a tweet").unwrap_err();
        assert!(said.starts_with("`tweet_id` must be a tweet id or a status url: "), "{said}");
        let said = resolve_tweet_ref("tweet_id", "https://example.com/elliot/status/1").unwrap_err();
        assert!(said.contains("tweet_id"), "{said}");
        assert_eq!(resolve_tweet_ref("tweet_id", "https://x.com/elliot/status/77").unwrap(), "77");
    }

    /// The poll out of the input value: the shapes X opens and the ones it
    /// would refuse, all judged before anything runs.
    #[test]
    fn a_poll_carries_two_to_four_short_options_open_five_minutes_to_a_week() {
        let ok = poll_of(&serde_json::json!({"options": ["gm", "night"], "duration_minutes": 1440})).unwrap();
        assert_eq!(ok, Poll { options: vec!["gm".into(), "night".into()], duration_minutes: 1440 });
        // A week is the top of the range; five minutes, the floor.
        assert!(poll_of(&serde_json::json!({"options": ["a", "b"], "duration_minutes": 10080})).is_ok());
        assert!(poll_of(&serde_json::json!({"options": ["a", "b"], "duration_minutes": 5})).is_ok());

        // The refusals, each in its own sentence:
        for (bad, why) in [
            (serde_json::json!({"options": ["gm"], "duration_minutes": 60}), "2 to 4"),
            (serde_json::json!({"options": ["a","b","c","d","e"], "duration_minutes": 60}), "2 to 4"),
            (serde_json::json!({"options": ["gm", "        "], "duration_minutes": 60}), "1 to 25 characters"),
            (serde_json::json!({"options": ["gm", &"ж".repeat(26)], "duration_minutes": 60}), "1 to 25 characters"),
            (serde_json::json!({"options": ["gm", "night"], "duration_minutes": 4}), "5 minutes to 7 days"),
            (serde_json::json!({"options": ["gm", "night"], "duration_minutes": 10081}), "5 minutes to 7 days"),
            (serde_json::json!({"options": ["gm", "night"], "when": "now"}), "not a poll"),
            (serde_json::json!({"duration_minutes": 60}), "not a poll"),
        ] {
            let said = poll_of(&bad).unwrap_err();
            assert!(said.contains(why), "{said}");
        }
    }

    /// A poll rides on the wire as /2/tweets' `poll` member; a post without
    /// one names no poll member at all.
    #[test]
    fn a_poll_posts_the_poll_object_on_the_wire() {
        let g = granted("tweet.write");
        let poll = poll_of(&serde_json::json!({"options": ["gm", "night"], "duration_minutes": 60})).unwrap();
        let transport = MockTransport::with(vec![ok_tweet()]);
        tweet(&transport, &g, "gm", None, Some(&poll)).unwrap();
        let body = serde_json::from_slice::<serde_json::Value>(&transport.seen.borrow()[0].2).unwrap();
        assert_eq!(body["poll"]["options"], serde_json::json!(["gm", "night"]));
        assert_eq!(body["poll"]["duration_minutes"], serde_json::json!(60));
        assert!(body.get("reply").is_none());

        let transport = MockTransport::with(vec![ok_tweet()]);
        tweet(&transport, &g, "gm", None, None).unwrap();
        let body = serde_json::from_slice::<serde_json::Value>(&transport.seen.borrow()[0].2).unwrap();
        assert!(body.get("poll").is_none(), "no poll member without one");
    }

    /// The repost, on the wire and through its mapping: the url names the
    /// reposting account, the body the tweet reposted; 200 answers the
    /// boolean X meant, every refusal keeps its class, and a lost answer is
    /// unknown — the stamp may be on.
    #[test]
    fn a_repost_is_answered_refused_or_unknown() {
        let g = granted("tweet.write users.read");

        // Posted (or already was): 200 answers the word X gave.
        let transport = MockTransport::with(vec![MockTransport::ok(200, serde_json::json!({"data": {"retweeted": true}}))]);
        assert_eq!(retweet(&transport, &g, "1", "1901").unwrap(), true);
        let (method, url, body) = &transport.seen.borrow()[0];
        assert_eq!((method, url.as_str()), (&Method::Post, "https://api.x.com/2/users/1/retweets"));
        assert_eq!(serde_json::from_slice::<Value>(body).unwrap()["tweet_id"], serde_json::json!("1901"));

        // Already reposted: false is a fine answer, nothing to retry.
        let transport = MockTransport::with(vec![MockTransport::ok(200, serde_json::json!({"data": {"retweeted": false}}))]);
        assert_eq!(retweet(&transport, &g, "1", "1901").unwrap(), false);

        // A 200 that names no word: unknown — the stamp may be on.
        let odd = retweet(&MockTransport::with(vec![MockTransport::ok(200, serde_json::json!({"data": {}}))]), &g, "1", "1901").unwrap_err();
        assert!(odd.is_unknown(), "{odd:?}");

        // The mapping family, as every post-endpoint carries it:
        let throttled = retweet(&MockTransport::with(vec![refused(429, "Rate limit exceeded")]), &g, "1", "1901").unwrap_err();
        assert!(matches!(&throttled, Outcome::Refused(s) if s.starts_with("rate_limited: ")), "{throttled:?}");
        let dead = retweet(&MockTransport::with(vec![refused(401, "Unauthorized")]), &g, "1", "1901").unwrap_err();
        assert!(matches!(&dead, Outcome::Refused(s) if s.starts_with("credential_rejected: ")), "{dead:?}");
        let no_scope = granted("users.read");
        let scope = retweet(&MockTransport::with(vec![refused(403, "not allowed")]), &no_scope, "1", "1901").unwrap_err();
        assert!(matches!(&scope, Outcome::Refused(s) if s.starts_with("scope_missing: ")), "{scope:?}");
        let account = retweet(&MockTransport::with(vec![refused(403, "client-not-enrolled")]), &g, "1", "1901").unwrap_err();
        assert!(matches!(&account, Outcome::Refused(s) if s.starts_with("X refused /2/users/…/retweets: HTTP 403 ")), "{account:?}");
        let bad = retweet(&MockTransport::with(vec![refused(400, "could not authenticate you")]), &g, "1", "1901").unwrap_err();
        assert!(matches!(&bad, Outcome::Refused(s) if s.contains("could not authenticate you")), "{bad:?}");
        let backend = retweet(&MockTransport::with(vec![refused(503, "backend")]), &g, "1", "1901").unwrap_err();
        assert!(backend.is_unknown(), "{backend:?}");
        let lost = retweet(&MockTransport::with(vec![MockTransport::network("connection reset")]), &g, "1", "1901").unwrap_err();
        assert!(lost.is_unknown(), "{lost:?}");
    }

    /// The repost withdrawn: DELETE down the same family of urls, its own
    /// mapping, and the unknown outcome that keeps a caller honest.
    #[test]
    fn an_unretweet_is_a_delete_down_the_repost_url() {
        let g = granted("tweet.write users.read");

        let transport = MockTransport::with(vec![MockTransport::ok(200, serde_json::json!({"data": {"retweeted": false}}))]);
        unretweet(&transport, &g, "1", "1901").unwrap();
        let (method, url, body) = &transport.seen.borrow()[0];
        assert_eq!((method, url.as_str(), body.is_empty()), (&Method::Delete, "https://api.x.com/2/users/1/retweets/1901", true));

        let bad = unretweet(&MockTransport::with(vec![refused(400, "could not authenticate you")]), &g, "1", "1901").unwrap_err();
        assert!(matches!(&bad, Outcome::Refused(s) if s.contains("could not authenticate you")), "{bad:?}");
        let lost = unretweet(&MockTransport::with(vec![MockTransport::network("connection reset")]), &g, "1", "1901").unwrap_err();
        assert!(lost.is_unknown(), "{lost:?}");
    }

    /// A post withdrawn entirely: DELETE /2/tweets/:id, X's own words on a
    /// repeat (404: already gone), and the unknown that says "may have left".
    #[test]
    fn a_delete_is_a_delete_down_the_tweet_url() {
        let g = granted("tweet.write users.read");

        let transport = MockTransport::with(vec![MockTransport::ok(200, serde_json::json!({"data": {"deleted": true}}))]);
        delete_tweet(&transport, &g, "1901").unwrap();
        let (method, url, body) = &transport.seen.borrow()[0];
        assert_eq!((method, url.as_str(), body.is_empty()), (&Method::Delete, "https://api.x.com/2/tweets/1901", true));

        // Deleted twice: X's own word says it is already gone — a refusal
        // the caller reads as the answer to "is it gone?".
        let gone = delete_tweet(&MockTransport::with(vec![refused(404, "no post found")]), &g, "1901").unwrap_err();
        assert!(matches!(&gone, Outcome::Refused(s) if s.contains("no post found")), "{gone:?}");

        let no_scope = granted("users.read");
        let scope = delete_tweet(&MockTransport::with(vec![refused(403, "not allowed")]), &no_scope, "1901").unwrap_err();
        assert!(matches!(&scope, Outcome::Refused(s) if s.starts_with("scope_missing: ")), "{scope:?}");
        let throttled = delete_tweet(&MockTransport::with(vec![refused(429, "Rate limit exceeded")]), &g, "1901").unwrap_err();
        assert!(matches!(&throttled, Outcome::Refused(s) if s.starts_with("rate_limited: ")), "{throttled:?}");
        let backend = delete_tweet(&MockTransport::with(vec![refused(503, "backend")]), &g, "1901").unwrap_err();
        assert!(backend.is_unknown(), "{backend:?}");
        let lost = delete_tweet(&MockTransport::with(vec![MockTransport::network("connection reset")]), &g, "1901").unwrap_err();
        assert!(lost.is_unknown(), "{lost:?}");
    }
}
