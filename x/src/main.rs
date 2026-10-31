//! The x connector: an agent posts to X as the owner's connected account,
//! under the owner's policy, without ever holding the credential.
//!
//! | `operation` | class | what it does |
//! |---|---|---|
//! | `status` | read | whether the credential works — proved by refreshing it — which OAuth client the run used, the policy's caps, the caller's own posts today |
//! | `me` | read | the connected account's handle, for the UI |
//! | `post` | write | one post, policy-checked first; named `reply_to`, an answer to that tweet; named `poll`, the opener of one; a task for the owner when their policy says `confirm` |
//! | `retweet` | write | one repost, the account's stamp on another post, under the owner's cap; a task for the owner when their policy says `repost` |
//! | `unretweet` | write | one repost taken back — only the account's own |
//! | `delete` | write | one post withdrawn entirely, only one the account authored; the owner's confirmation, unless their policy's `confirm` says otherwise in full |
//! | `confirm` | write | run by the platform as the agent on the owner's approval: posts the text the task holds |
//! | `task_status`, `task_cancel`, `task_delete`, `tasks`, `tasks_unlock` | | the tasks this caller made, and the owner's devices |
//!
//! Nothing in any answer ever echoes a secret: every value the run read
//! from the environment or minted is swept out of the envelope before it
//! leaves (see [`runtime::Secrets`]).

mod confirm;
mod oauth;
mod policy;
mod runtime;
mod x_api;

use connector_core::{envelope, undecodable, Counted, Outcome, Refused};
use runtime::{RecordStore, Secrets, Transport, WasiStore, WasiTransport};
use serde_json::{json, Value};

// The manifest, embedded in a wasm custom section so it is covered by the
// wasm hash the contract records for this version: the connector id, the
// two hosts this module may reach, the daily caps it declares about itself.
connector_core::embed_manifest!("../manifest.json");

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct Input {
    operation: String,
    /// `post`: the text, 1 to 280 characters, posted as written.
    pub text: Option<String>,
    /// `confirm` and the `task_*` operations: the task's id.
    pub task_id: Option<String>,
    /// `confirm`: SHA-256 of the task as the owner's page showed it.
    pub task_hash: Option<String>,
    /// `confirm`: the owner's approval — `at`, `public_key`, `signature`,
    /// `nonce` — as the platform puts it in the run's input.
    pub approval: Option<Value>,
    /// `confirm`: what the owner wrote beside the approval, sealed to the
    /// task's reply key, in base64. Handed to the agent with the result.
    pub note: Option<String>,
    /// `post`: the tweet this post answers — its id, or a status url the
    /// connector resolves to one. Absent: the post is standalone.
    pub reply_to: Option<String>,
    /// `post`: X's poll as the input carries it —
    /// `{"options": [...], "duration_minutes": N}`, validated before
    /// anything runs. Absent: a post with no poll.
    pub poll: Option<Value>,
    /// `retweet`, `unretweet`, `delete`: the tweet named — its id, or a
    /// status url the connector resolves to one.
    pub tweet_id: Option<String>,
}

/// Everything this connector sells. A name not here is refused with the list.
const OPERATIONS: &[&str] = &[
    "status",
    "me",
    "post",
    "retweet",
    "unretweet",
    "delete",
    "confirm",
    "task_status",
    "task_cancel",
    "task_delete",
    "tasks",
    "tasks_unlock",
];

/// The sentence a run answers when the operation is not one of ours.
fn sells() -> String {
    format!("This connector sells: {}", OPERATIONS.join(", "))
}

fn main() {
    let raw = outlayer::env::input();
    let transport = WasiTransport;
    let store = WasiStore;
    let mut secrets = Secrets::default();
    // Every value the environment may hold is a secret this run must never
    // echo: noted before anything reads them, whatever the operation.
    for (kind, name) in [
        ("client secret", oauth::CLIENT_SECRET_ENV),
        ("client id", oauth::CLIENT_ID_ENV),
        ("refresh token", oauth::REFRESH_TOKEN_ENV),
        ("client secret", oauth::OUR_CLIENT_SECRET_ENV),
        ("client id", oauth::OUR_CLIENT_ID_ENV),
    ] {
        if let Ok(value) = std::env::var(name) {
            secrets.note(kind, &value);
        }
    }

    let envelope = match serde_json::from_slice::<Input>(&raw) {
        Err(e) => undecodable(format!("input is not the expected JSON: {e}")),
        Ok(input) => {
            let op = input.operation.trim().to_string();
            envelope(op.clone(), answer(&op, &input, &transport, &store, &mut secrets))
        }
    };

    // The guard between the connector and its answer: no secret value is
    // ever reachable from any output.
    let answered = match connector_core::sweep(&envelope, secrets.list()) {
        Ok(()) => envelope,
        Err(why) => {
            let mut bare = undecodable(why);
            bare.operation = envelope.operation.clone();
            bare
        }
    };
    let _ = outlayer::env::output_json(&answered);
}

/// The run's answer: `confirm` names the notice its refusal opened, beside
/// the refusal; every other operation's refusal is its sentence.
fn answer(
    op: &str,
    input: &Input,
    transport: &dyn Transport,
    store: &dyn RecordStore,
    secrets: &mut Secrets,
) -> Result<Value, Refused> {
    match op {
        "confirm" => confirm::confirm(input, transport, store, secrets)
            .map_err(|r| Refused { refusal: r.refusal, notice: r.notice }),
        _ => run(op, input, transport, store, secrets).map_err(Refused::from),
    }
}

fn run(
    op: &str,
    input: &Input,
    transport: &dyn Transport,
    store: &dyn RecordStore,
    secrets: &mut Secrets,
) -> Result<Value, String> {
    match op {
        "status" => status(transport, store, secrets),
        "me" => me(transport, store, secrets),
        "post" => post(input, transport, store, secrets),
        "retweet" => retweet(input, transport, store, secrets),
        "unretweet" => unretweet(input, transport, store, secrets),
        "delete" => delete_post(input, transport, store, secrets),
        "task_status" => confirm::task(op, input),
        "task_cancel" => confirm::task(op, input),
        "task_delete" => confirm::task(op, input),
        "tasks" => confirm::task(op, input),
        "tasks_unlock" => confirm::task(op, input),
        "" => Err(format!("no `operation` in the input. {}", sells())),
        other => Err(format!("unknown operation `{other}`. {}", sells())),
    }
}

/// Is the credential alive, and what may the agent do with it? Getting an
/// access token is the proof: it is the one thing a posting credential can
/// show. The policy's view is reported whole: a policy for posts names
/// nobody — `max_per_day` and `confirm` carry nothing private, so the
/// sealed-policy support other connectors need on chain is not needed here.
fn status(transport: &dyn Transport, store: &dyn RecordStore, secrets: &mut Secrets) -> Result<Value, String> {
    let credential = oauth::credential()?;
    let granted = oauth::access_token(transport, store, &credential, connector_core::now_secs(), secrets)?;
    let day = connector_core::day_key(connector_core::now_ms());
    let sent = connector_core::sent_today(
        |key, delta| runtime::store_bump(store, key, delta),
        &policy::count_key(&day, Counted::Own),
    )
    .unwrap_or(0);
    Ok(json!({
        "credential": "ok",
        "oauth_client": if connector_core::oauth::Credential::has_own_client(&oauth::NAMES) {
            "the owner's own"
        } else {
            "this connector's"
        },
        "scope": "tweet.write: this connector posts as the connected account and reads only the account's own handle",
        "granted_scope": granted.scope,
        "policy": policy::view(policy::load()),
        "sent_today": sent,
        "next": "`post` with `text` (and `reply_to`, a tweet id or status url; `poll` to open one), `retweet`/`unretweet`/`delete` with `tweet_id`",
    }))
}

/// The connected account's handle, for the UI.
fn me(transport: &dyn Transport, store: &dyn RecordStore, secrets: &mut Secrets) -> Result<Value, String> {
    let credential = oauth::credential()?;
    let granted = oauth::access_token(transport, store, &credential, connector_core::now_secs(), secrets)?;
    let account = x_api::me(transport, &granted)?;
    Ok(json!({"id": account.id, "username": account.username, "name": account.name}))
}

/// One post, policy-checked first; named `reply_to`, a reply to that post;
/// named `poll`, the opener of one.
fn post(
    input: &Input,
    transport: &dyn Transport,
    store: &dyn RecordStore,
    secrets: &mut Secrets,
) -> Result<Value, String> {
    let text = input
        .text
        .as_deref()
        .ok_or_else(|| "`text` is required: the post carries it".to_string())?;
    policy::check_text(text)?;
    // The reply target and the poll, both validated before anything runs —
    // a malformed one refuses here, at no cost and with no cap taken, the
    // same pre-run refusal a bad text gets.
    let reply_to = resolve_named(input.reply_to.as_deref(), "reply_to")?;
    let poll = match input.poll.as_ref() {
        Some(value) if !value.is_null() => Some(x_api::poll_of(value)?),
        _ => None,
    };
    let rules = policy::require()?;
    if rules.confirms(policy::Confirmable::Post) {
        return confirm::ask(&confirm::shown(text, reply_to, poll));
    }
    deliver(
        &rules,
        &Action::Post { text: text.to_string(), reply_to, poll },
        transport,
        store,
        secrets,
        Counted::Own,
    )
    .map_err(|outcome| outcome.refusal())
}

/// A member that names a tweet — the snowflake a bare id or status url
/// resolves to, absent when the input carries none. Whitespace-only means
/// absent; there is no tweet with a blank id, but an agent may send `""` as
/// "nothing here".
fn resolve_named(raw: Option<&str>, param: &str) -> Result<Option<String>, String> {
    raw.map(str::trim)
        .filter(|raw| !raw.is_empty())
        .map(|raw| x_api::resolve_tweet_ref(param, raw))
        .transpose()
}

/// A repost: the connected account stamps another post. The daily cap
/// binds it like a post — it IS feed output — and under the owner's
/// `confirm` it waits for their signature like one.
fn retweet(
    input: &Input,
    transport: &dyn Transport,
    store: &dyn RecordStore,
    secrets: &mut Secrets,
) -> Result<Value, String> {
    let repost_of = resolve_named(input.tweet_id.as_deref(), "tweet_id")?
        .ok_or_else(|| "`tweet_id` is required: the repost stamps it".to_string())?;
    let rules = policy::require()?;
    if rules.confirms(policy::Confirmable::Repost) {
        return confirm::ask(&confirm::Prepared::Repost { repost_of });
    }
    deliver(&rules, &Action::Repost { repost_of }, transport, store, secrets, Counted::Own)
        .map_err(|outcome| outcome.refusal())
}

/// A repost taken back — only the account's own, X refusing the rest. The
/// eraser's brake is not on: the cap counts what is put out, not what is
/// removed.
fn unretweet(
    input: &Input,
    transport: &dyn Transport,
    store: &dyn RecordStore,
    secrets: &mut Secrets,
) -> Result<Value, String> {
    let repost_of = resolve_named(input.tweet_id.as_deref(), "tweet_id")?
        .ok_or_else(|| "`tweet_id` is required: the repost undone names it".to_string())?;
    let rules = policy::require()?;
    deliver(&rules, &Action::Unrepost { repost_of }, transport, store, secrets, Counted::Own)
        .map_err(|outcome| outcome.refusal())
}

/// A post withdrawn entirely — only one this account authored, X refusing
/// the rest. The cap does not reach it, but the owner does: with no
/// `confirm` in their policy, a delete waits for their signature, the one
/// action whose mistake is not undone by waiting.
fn delete_post(
    input: &Input,
    transport: &dyn Transport,
    store: &dyn RecordStore,
    secrets: &mut Secrets,
) -> Result<Value, String> {
    let delete_of = resolve_named(input.tweet_id.as_deref(), "tweet_id")?
        .ok_or_else(|| "`tweet_id` is required: the deleted post names it".to_string())?;
    let rules = policy::require()?;
    if rules.confirms(policy::Confirmable::Delete) {
        return confirm::ask(&confirm::Prepared::Delete { delete_of });
    }
    deliver(&rules, &Action::Delete { delete_of }, transport, store, secrets, Counted::Own)
        .map_err(|outcome| outcome.refusal())
}

/// A prepared action as the wire sees it: everything the call needs and
/// nothing of what a task seals. A post's text is sent as written — the
/// owner is shown the escaped form, the wire carries the raw one, exactly
/// as the answer posted what was written.
enum Action {
    Post { text: String, reply_to: Option<String>, poll: Option<x_api::Poll> },
    Repost { repost_of: String },
    Unrepost { repost_of: String },
    Delete { delete_of: String },
}

/// The count the answer carries, once the action happened: the place taken
/// before the call is kept after it returned, and named beside the cap of
/// the owner's where they set one.
fn kept_count(reservation: Option<(connector_core::Reservation<'_>, u32)>) -> Option<u32> {
    reservation.map(|(reservation, used)| {
        reservation.keep();
        used
    })
}

/// The wire call one prepared action asks for, after the owner's rules
/// passed it and the reservation, where one applies, is already taken.
///
/// The owner's own cap, if they set one, is taken BEFORE anything leaves —
/// atomically, so two calls at once cannot both see room for the last one.
/// Any return from here without `keep` gives it back; an outcome
/// that is unknown KEEPS it: a count one too high refuses a post, one too
/// low allows one. The cap reaches what the account PUTS OUT — a post, a
/// repost — and never what it withdraws: a delete answers to the owner,
/// not to a counter.
fn deliver(
    rules: &policy::Policy,
    action: &Action,
    transport: &dyn Transport,
    store: &dyn RecordStore,
    secrets: &mut Secrets,
    counted: Counted,
) -> Result<Value, Outcome> {
    let day = connector_core::day_key(connector_core::now_ms());
    let reservation = if matches!(action, Action::Post { .. } | Action::Repost { .. }) {
        match rules.max_per_day {
            Some(cap) => {
                let key = policy::count_key(&day, counted);
                let (reservation, used) =
                    connector_core::reserve(|key, delta| runtime::store_bump(store, key, delta), key, cap)
                        .map_err(Outcome::Refused)?;
                Some((reservation, used))
            }
            None => None,
        }
    } else {
        None
    };

    let credential = oauth::credential().map_err(Outcome::Refused)?;
    let granted =
        oauth::access_token(transport, store, &credential, connector_core::now_secs(), secrets).map_err(Outcome::Refused)?;
    if !granted.grants(x_api::TWEET_WRITE) {
        return Err(Outcome::Refused(connector_core::refusal::scope_missing(x_api::TWEET_WRITE, "X")));
    }

    // The one shape every unknown outcome answers with: a request gone out
    // or perhaps not, its place in today's count kept where one was taken —
    // a count one too high refuses a post, one too low allows one.
    macro_rules! wire {
        ($call:expr) => {
            match $call {
                Ok(answer) => answer,
                Err(unknown @ Outcome::Unknown(_)) => {
                    if let Some((reservation, _)) = reservation {
                        reservation.keep();
                    }
                    return Err(unknown);
                }
                Err(Outcome::Refused(why)) => return Err(Outcome::Refused(why)),
            }
        };
    }

    match action {
        Action::Post { text, reply_to, poll } => {
            // The handle, for the url; a `me` that fails says nothing about
            // the post, and the answer falls back to the handle-less form.
            let handle = x_api::me(transport, &granted).ok().map(|account| account.username);
            let tweet_id = wire!(x_api::tweet(transport, &granted, text, reply_to.as_deref(), poll.as_ref()));
            let sent_today = kept_count(reservation);
            let mut answer = json!({
                "tweet_id": tweet_id,
                "url": match handle {
                    Some(username) => format!("https://x.com/{username}/status/{tweet_id}"),
                    None => confirm::status_url(&tweet_id),
                },
                "text": text,
                "sent_today": sent_today,
                "remaining_today": sent_today.zip(rules.max_per_day).map(|(used, cap)| cap.saturating_sub(used)),
            });
            // The reply the post answered, as its id — evidence beside the
            // tweet's. Absent on a standalone post, whose answer is shaped
            // as it ever was.
            if let Some(reply_to) = reply_to {
                answer["reply_to"] = json!(reply_to);
            }
            // The poll the post opened, as the input named it.
            if let Some(poll) = poll {
                answer["poll"] = serde_json::to_value(poll).unwrap_or(Value::Null);
            }
            Ok(answer)
        }
        Action::Repost { repost_of } => {
            // X's endpoint names the account that stamps, so the `me` is a
            // load-bearing call here: no id, no repost.
            let me = x_api::me(transport, &granted).map_err(Outcome::Refused)?;
            let retweeted = wire!(x_api::retweet(transport, &granted, &me.id, repost_of));
            let sent_today = kept_count(reservation);
            Ok(json!({
                "retweeted": retweeted,
                "tweet_id": repost_of,
                "url": confirm::status_url(repost_of),
                "sent_today": sent_today,
                "remaining_today": sent_today.zip(rules.max_per_day).map(|(used, cap)| cap.saturating_sub(used)),
            }))
        }
        Action::Unrepost { repost_of } => {
            let me = x_api::me(transport, &granted).map_err(Outcome::Refused)?;
            wire!(x_api::unretweet(transport, &granted, &me.id, repost_of));
            Ok(json!({
                "retweeted": false,
                "tweet_id": repost_of,
                "url": confirm::status_url(repost_of),
            }))
        }
        Action::Delete { delete_of } => {
            wire!(x_api::delete_tweet(transport, &granted, delete_of));
            Ok(json!({
                "deleted": true,
                "tweet_id": delete_of,
                "url": confirm::status_url(delete_of),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_core::Envelope;
    use runtime::testing::{env_lock, MemStore, MockTransport};

    /// The full run's environment for a connected account: a refresh token
    /// in the row, our client as the author's, a policy of the owner's.
    struct Run {
        transport: MockTransport,
        store: MemStore,
        secrets: Secrets,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Run {
        fn with(answers: Vec<Result<runtime::Response, String>>, policy_json: &str) -> Self {
            let lock = env_lock();
            std::env::set_var(oauth::REFRESH_TOKEN_ENV, "1//row");
            std::env::set_var(oauth::OUR_CLIENT_ID_ENV, "our-id");
            std::env::set_var(oauth::OUR_CLIENT_SECRET_ENV, "our-secret");
            std::env::remove_var(oauth::CLIENT_ID_ENV);
            std::env::remove_var(oauth::CLIENT_SECRET_ENV);
            std::env::set_var(policy::POLICY_ENV, policy_json);
            // What main() does before anything answers: note every secret.
            let mut secrets = Secrets::default();
            secrets.note("refresh token", "1//row");
            secrets.note("client id", "our-id");
            secrets.note("client secret", "our-secret");
            Run { transport: MockTransport::with(answers), store: MemStore::default(), secrets, _lock: lock }
        }

        fn run(&mut self, op: &str, input: &Input) -> Result<Value, Refused> {
            answer(op, input, &self.transport, &self.store, &mut self.secrets)
        }
    }

    impl Drop for Run {
        fn drop(&mut self) {
            for name in [
                oauth::REFRESH_TOKEN_ENV,
                oauth::OUR_CLIENT_ID_ENV,
                oauth::OUR_CLIENT_SECRET_ENV,
                oauth::CLIENT_ID_ENV,
                oauth::CLIENT_SECRET_ENV,
                policy::POLICY_ENV,
            ] {
                std::env::remove_var(name);
            }
        }
    }

    fn grant() -> Result<runtime::Response, String> {
        MockTransport::ok(
            200,
            json!({"token_type": "bearer", "expires_in": 7200, "access_token": "AT", "scope": "tweet.write users.read"}),
        )
    }

    fn tweet_ok() -> Result<runtime::Response, String> {
        MockTransport::ok(201, json!({"data": {"id": "1901", "text": "gm"}}))
    }

    fn me_ok() -> Result<runtime::Response, String> {
        MockTransport::ok(200, json!({"data": {"id": "1", "username": "elliot", "name": "Elliot"}}))
    }

    fn post_input(text: &str) -> Input {
        Input { text: Some(text.into()), ..Input::default() }
    }

    fn tweet_input(tweet_id: &str) -> Input {
        Input { tweet_id: Some(tweet_id.into()), ..Input::default() }
    }

    /// The repost: the stamp lands on the wire as X's word, the cap counts
    /// it beside the posts, and the answer names the tweet it answered.
    #[test]
    fn a_retweet_stamps_x_and_counts_like_a_post() {
        let mut run = Run::with(
            vec![
                grant(),
                me_ok(),
                tweet_ok(),
                // The repost's own run: the token is cached, the handle is
                // the id's answer, X replying its own word.
                me_ok(),
                MockTransport::ok(200, json!({"data": {"retweeted": true}})),
            ],
            r#"{"max_per_day":10}"#,
        );
        let out = run.run("post", &post_input("gm")).unwrap();
        assert_eq!(out["sent_today"], json!(1));
        let out = run.run("retweet", &tweet_input("1901")).unwrap();
        assert_eq!(out["retweeted"], json!(true));
        assert_eq!(out["tweet_id"], "1901");
        assert_eq!(out["url"], "https://x.com/i/web/status/1901");
        assert_eq!(out["sent_today"], json!(2), "a repost is feed output; the cap reaches it");
        assert_eq!(out["remaining_today"], json!(8));
        // On the wire: the POST names the account, the body the tweet.
        let (method, url, body) = &run.transport.seen.borrow()[4];
        assert_eq!((method, url.as_str()), (&runtime::Method::Post, "https://api.x.com/2/users/1/retweets"));
        assert_eq!(serde_json::from_slice::<Value>(body).unwrap()["tweet_id"], json!("1901"));
    }

    /// A repost the owner confirms: under `confirm:["repost"]` the malformed
    /// target still refuses pre-run, at no cost — and the ask itself is
    /// exercised where the host answers (a real run).
    #[test]
    fn a_retweet_under_a_repost_refuses_a_malformed_target() {
        let mut run = Run::with(vec![], r#"{"confirm":["repost"]}"#);
        let said = run.run("retweet", &tweet_input("no url at all")).unwrap_err();
        assert!(said.refusal.starts_with("`tweet_id` must be a tweet id or a status url: "), "{said:?}");
        assert!(run.transport.seen.borrow().is_empty(), "nothing went out");
    }

    /// A malformed `tweet_id` refuses pre-run at no cost, for every op that
    /// names one — the same cost-free refusal a bad `text` gets.
    #[test]
    fn a_malformed_tweet_id_refuses_pre_run_at_no_cost() {
        let mut run = Run::with(
            vec![
                grant(),
                me_ok(),
                MockTransport::ok(200, json!({"data": {"retweeted": false}})),
                MockTransport::ok(200, json!({"data": {"deleted": true}})),
            ],
            r#"{"max_per_day":1}"#,
        );
        let key = policy::count_key(&connector_core::day_key(connector_core::now_ms()), Counted::Own);
        for op in ["retweet", "unretweet", "delete"] {
            let said = run.run(op, &tweet_input("https://example.com/elliot/status/1901")).unwrap_err();
            assert!(said.refusal.starts_with("`tweet_id` must be a tweet id or a status url: "), "{said:?}");
            assert!(run.transport.seen.borrow().is_empty(), "nothing went out for {op}");
            assert_eq!(run.store.count(&key), 0, "the cap was not taken for {op}");
        }
        // A url that resolves works straight through (the answers are queued).
        let out = run.run("unretweet", &tweet_input("https://x.com/elliot/status/1901")).unwrap();
        assert_eq!(out["tweet_id"], "1901");
    }

    /// A repost taken back: uncapped, uncounted, and its answer carries no
    /// count members at all — removal is not output.
    #[test]
    fn an_unretweet_takes_the_stamp_back_and_counts_nothing() {
        let mut run = Run::with(
            vec![
                grant(),
                me_ok(),
                MockTransport::ok(200, json!({"data": {"retweeted": false}})),
            ],
            r#"{"max_per_day":10}"#,
        );
        let out = run.run("unretweet", &tweet_input("1901")).unwrap();
        assert_eq!(out["retweeted"], json!(false));
        assert_eq!(out["tweet_id"], "1901");
        assert!(out.get("sent_today").is_none(), "no count members on a removal");
        assert!(out.get("remaining_today").is_none());
        let key = policy::count_key(&connector_core::day_key(connector_core::now_ms()), Counted::Own);
        assert_eq!(run.store.count(&key), 0, "nothing was counted");
        let (method, url, _) = &run.transport.seen.borrow()[2];
        assert_eq!((method, url.as_str()), (&runtime::Method::Delete, "https://api.x.com/2/users/1/retweets/1901"));
    }

    /// A post deleted: X's DELETE, the answer's word, no counts — and with
    /// no `confirm` in the policy the owner would have confirmed it first,
    /// so the only unattended run here is an explicit opt-out.
    #[test]
    fn a_delete_refuses_x_and_counts_nothing() {
        let mut run = Run::with(
            vec![
                grant(),
                MockTransport::ok(200, json!({"data": {"deleted": true}})),
            ],
            r#"{"max_per_day":10,"confirm":[]}"#,
        );
        let out = run.run("delete", &tweet_input("https://x.com/elliot/status/1901")).unwrap();
        assert_eq!(out["deleted"], json!(true));
        assert_eq!(out["tweet_id"], "1901");
        assert_eq!(out["url"], "https://x.com/i/web/status/1901");
        assert!(out.get("sent_today").is_none(), "no count members on a deletion");
        assert!(out.get("remaining_today").is_none());
        let key = policy::count_key(&connector_core::day_key(connector_core::now_ms()), Counted::Own);
        assert_eq!(run.store.count(&key), 0, "nothing was counted");
        // A delete carried no me: the first wire call is the DELETE itself.
        let seen = run.transport.seen.borrow();
        let (method, url, body) = &seen[1];
        assert_eq!((method, url.as_str(), body.is_empty()), (&runtime::Method::Delete, "https://api.x.com/2/tweets/1901", true));
    }

    /// A poll: validated before anything runs, on the wire as the poll
    /// member, echoed in the answer.
    #[test]
    fn a_post_with_a_poll_opens_one_on_the_wire() {
        let mut run = Run::with(vec![grant(), me_ok(), tweet_ok()], r#"{"max_per_day":10}"#);
        let mut input = post_input("gm or night");
        input.poll = Some(json!({"options": ["gm", "night"], "duration_minutes": 60}));
        let out = run.run("post", &input).unwrap();
        assert_eq!(out["tweet_id"], "1901");
        assert_eq!(out["poll"]["options"], json!(["gm", "night"]));
        assert_eq!(out["poll"]["duration_minutes"], json!(60));
        let body = serde_json::from_slice::<Value>(&run.transport.seen.borrow()[2].2).unwrap();
        assert_eq!(body["poll"]["options"], json!(["gm", "night"]));
        assert_eq!(body["poll"]["duration_minutes"], json!(60));
    }

    /// A malformed poll refuses pre-run at no cost, like a bad reply target.
    #[test]
    fn a_malformed_poll_refuses_pre_run_at_no_cost() {
        let mut run = Run::with(vec![], r#"{"max_per_day":1}"#);
        let mut input = post_input("gm");
        input.poll = Some(json!({"options": ["gm"], "duration_minutes": 60}));
        let said = run.run("post", &input).unwrap_err();
        assert!(said.refusal.contains("2 to 4"), "{said:?}");
        assert!(run.transport.seen.borrow().is_empty(), "nothing went out");
        let key = policy::count_key(&connector_core::day_key(connector_core::now_ms()), Counted::Own);
        assert_eq!(run.store.count(&key), 0, "the cap was not taken");
    }

    /// A post, end to end against the mock: refresh (the credential proof),
    /// the handle, the post, and the answer with the tweet id and url.
    #[test]
    fn a_post_refreshes_posts_and_answers_with_the_tweet_id_and_url() {
        let mut run = Run::with(vec![grant(), me_ok(), tweet_ok()], r#"{"max_per_day":10}"#);
        let out = run.run("post", &post_input("gm")).unwrap();
        assert_eq!(out["tweet_id"], "1901");
        assert_eq!(out["url"], "https://x.com/elliot/status/1901");
        assert_eq!(out["text"], "gm");
        assert_eq!(out["sent_today"], json!(1), "the cap is set, so the count is kept");
        assert_eq!(out["remaining_today"], json!(9));

        // The post went out third (refresh, handle, post), and carried exactly the text.
        let (method, url, body) = &run.transport.seen.borrow()[2];
        assert_eq!((method, url.as_str()), (&runtime::Method::Post, "https://api.x.com/2/tweets"));
        assert_eq!(serde_json::from_slice::<Value>(body).unwrap()["text"], json!("gm"));
    }

    #[test]
    fn with_no_cap_nothing_counts_and_the_answer_says_so() {
        let mut run = Run::with(vec![grant(), me_ok(), tweet_ok()], "{}");
        let out = run.run("post", &post_input("gm")).unwrap();
        assert_eq!(out["sent_today"], Value::Null, "no cap of the owner's, no count");
        assert_eq!(out["remaining_today"], Value::Null);
        assert_eq!(run.store.count("x:count"), 0, "nothing was counted");
    }

    /// A reply: the reply target is resolved before anything runs, carried
    /// on the wire as the reply object, and named in the answer beside the
    /// tweet's own evidence.
    #[test]
    fn a_post_with_reply_to_answers_as_a_reply_on_the_wire_and_in_the_answer() {
        let mut run = Run::with(vec![grant(), me_ok(), tweet_ok()], r#"{"max_per_day":10}"#);
        let mut input = post_input("gm");
        input.reply_to = Some("https://x.com/elliot/status/1901?media=1".into());
        let out = run.run("post", &input).unwrap();
        assert_eq!(out["tweet_id"], "1901");
        assert_eq!(out["reply_to"], "1901", "the answer names the reply the post answered");
        let body = serde_json::from_slice::<Value>(&run.transport.seen.borrow()[2].2).unwrap();
        assert_eq!(body["reply"]["in_reply_to_tweet_id"], json!("1901"));
        assert_eq!(body["text"], json!("gm"));
    }

    /// A malformed `reply_to` refuses before anything runs — no X call, no
    /// cap taken — the same cost-free pre-run refusal a bad text gets.
    #[test]
    fn a_malformed_reply_to_refuses_pre_run_at_no_cost() {
        for bad in ["not a tweet", "https://example.com/elliot/status/1901"] {
            let mut run = Run::with(vec![], r#"{"max_per_day":1}"#);
            let mut input = post_input("gm");
            input.reply_to = Some(bad.into());
            let said = run.run("post", &input).unwrap_err();
            assert!(said.refusal.starts_with("`reply_to` must be a tweet id or a status url: "), "{said:?}");
            assert!(run.transport.seen.borrow().is_empty(), "nothing went out");
            let key = policy::count_key(&connector_core::day_key(connector_core::now_ms()), Counted::Own);
            assert_eq!(run.store.count(&key), 0, "the cap was not taken");
        }
    }

    /// The daily cap: the place is taken before the post leaves and given
    /// back when X refuses it; a post that may have left keeps it.
    #[test]
    fn the_cap_is_taken_before_and_given_back_on_a_refusal() {
        // The cap of one, used up: the next post is refused with the
        // owner's word, before X is asked.
        {
            let mut run = Run::with(vec![], r#"{"max_per_day":1}"#);
            let key = policy::count_key(&connector_core::day_key(connector_core::now_ms()), Counted::Own);
            run.store.set(&key, b"1");
            let said = run.run("post", &post_input("gm")).unwrap_err();
            assert!(said.refusal.starts_with("policy_denied: 1 of the owner's 1 a day are used"), "{said:?}");
            assert_eq!(run.store.count(&key), 1, "the refused post gave its place back");
            assert!(run.transport.seen.borrow().is_empty(), "X was not asked");
        }

        // X refusing outright: the place is given back too.
        {
            let mut run = Run::with(
                vec![grant(), me_ok(), MockTransport::ok(400, json!({"detail": "could not authenticate you"}))],
                r#"{"max_per_day":10}"#,
            );
            let said = run.run("post", &post_input("gm")).unwrap_err();
            assert!(said.refusal.contains("could not authenticate you"), "{said:?}");
            let key = policy::count_key(&connector_core::day_key(connector_core::now_ms()), Counted::Own);
            assert_eq!(run.store.count(&key), 0, "a refused post costs no place");
        }

        // X's answer lost: the post MAY have left — the place stays.
        {
            let mut run =
                Run::with(vec![grant(), me_ok(), MockTransport::network("connection reset")], r#"{"max_per_day":10}"#);
            let said = run.run("post", &post_input("gm")).unwrap_err();
            assert!(said.refusal.contains("outcome is unknown"), "{said:?}");
            let key = policy::count_key(&connector_core::day_key(connector_core::now_ms()), Counted::Own);
            assert_eq!(run.store.count(&key), 1, "an unknown outcome keeps its place");
            assert_eq!(run.store.get(&key).as_deref(), Some(b"1".as_slice()));
        }
    }

    /// Every branch a caller branches on, through the run's own door.
    #[test]
    fn the_refusal_matrix_through_the_run() {
        // No credential: the row is the caller's to connect or grant.
        {
            let mut run = Run::with(vec![], r#"{"max_per_day":10}"#);
            std::env::remove_var(oauth::REFRESH_TOKEN_ENV);
            let said = run.run("post", &post_input("gm")).unwrap_err();
            assert!(said.refusal.starts_with("no credential reached this run"), "{said:?}");
            let said = run.run("status", &Input::default()).unwrap_err();
            assert!(said.refusal.starts_with("no credential reached this run"), "{said:?}");
            assert!(said.refusal.contains(oauth::CONNECT_PAGE), "{said:?}");
            std::env::set_var(oauth::REFRESH_TOKEN_ENV, "1//row");
        }

        // No policy: fail-closed, and the sentence says who fixes it.
        {
            let mut run = Run::with(vec![grant()], "{}");
            std::env::remove_var(policy::POLICY_ENV);
            let said = run.run("post", &post_input("gm")).unwrap_err();
            assert!(said.refusal.starts_with("policy_denied: the secrets row this call names holds no X_POLICY"), "{said:?}");
            let said = run.run("status", &Input::default()).unwrap();
            assert_eq!(said["policy"]["present"], json!(false), "status still answers: the credential is fine");
        }

        // An unreadable policy: refused too.
        {
            let mut run = Run::with(vec![], r#"{"surprise":1}"#);
            let said = run.run("post", &post_input("gm")).unwrap_err();
            assert!(said.refusal.starts_with("policy_denied: X_POLICY could not be read"), "{said:?}");
        }

        // The scope missing: refused before X is asked for the post.
        {
            let mut run = Run::with(
                vec![MockTransport::ok(200, json!({"expires_in": 7200, "access_token": "AT", "scope": "users.read"}))],
                r#"{"max_per_day":10}"#,
            );
            let said = run.run("post", &post_input("gm")).unwrap_err();
            assert!(said.refusal.starts_with("scope_missing: ") && said.refusal.contains("tweet.write"), "{said:?}");
            let key = policy::count_key(&connector_core::day_key(connector_core::now_ms()), Counted::Own);
            assert_eq!(run.store.count(&key), 0, "the place was given back");
        }

        // A text that is nothing: the caller's error, before anything.
        {
            let mut run = Run::with(vec![], r#"{"max_per_day":10}"#);
            let said = run.run("post", &post_input("   ")).unwrap_err();
            assert!(said.refusal.contains("`text` is required"), "{said:?}");
            assert_eq!(run.transport.seen.borrow().len(), 0, "nothing went out");
        }

        // An unknown operation: the list, not a guess.
        {
            let mut run = Run::with(vec![], r#"{"max_per_day":10}"#);
            let said = run.run("destroy", &Input::default()).unwrap_err();
            assert!(said.refusal.contains("unknown operation `destroy`"), "{said:?}");
            assert!(said.refusal.contains("status, me, post, retweet"), "{said:?}");
        }
    }

    #[test]
    fn me_answers_the_handle_for_the_ui() {
        let mut run = Run::with(vec![grant(), me_ok()], "{}");
        let out = run.run("me", &Input::default()).unwrap();
        assert_eq!(out["username"], "elliot");
        assert_eq!(out["id"], "1");
        assert_eq!(out["name"], "Elliot");
    }

    #[test]
    fn status_proves_the_credential_and_reports_what_a_post_would_use() {
        let mut run = Run::with(vec![grant()], r#"{"max_per_day":3,"confirm":["post"]}"#);
        let out = run.run("status", &Input::default()).unwrap();
        assert_eq!(out["credential"], "ok", "the refresh IS the proof");
        assert_eq!(out["oauth_client"], "this connector's");
        assert_eq!(out["policy"]["present"], json!(true));
        assert_eq!(out["policy"]["max_per_day"], json!(3));
        assert_eq!(out["policy"]["confirm"], json!(["post"]));
        assert_eq!(out["sent_today"], json!(0));
        assert_eq!(
            out["next"],
            "`post` with `text` (and `reply_to`, a tweet id or status url; `poll` to open one), \
             `retweet`/`unretweet`/`delete` with `tweet_id`"
        );
    }

    /// The owner's own client is visible in what status reports: evidence,
    /// not a guess, and it changes what a run would count on.
    #[test]
    fn status_names_which_oauth_client_the_run_used() {
        let mut run = Run::with(vec![grant()], "{}");
        std::env::set_var(oauth::CLIENT_ID_ENV, "own-id");
        std::env::set_var(oauth::CLIENT_SECRET_ENV, "own-secret");
        let out = run.run("status", &Input::default()).unwrap();
        assert_eq!(out["oauth_client"], "the owner's own");
    }

    /// The guard: no secret value is reachable from any output, through any
    /// operation, in any member.
    #[test]
    fn no_output_carries_a_secret() {
        // A secret echoed into an answer, if the connector were careless:
        // the sweep refuses the run instead, and names no value.
        {
            let run = Run::with(vec![], r#"{"max_per_day":10}"#);
            let env = Envelope {
                success: true,
                operation: "post".into(),
                output: Some(json!({"echo": "1//row"})),
                error: None,
                logs: Vec::new(),
            };
            let said = connector_core::sweep(&env, run.secrets.list()).unwrap_err();
            assert!(said.starts_with("internal: "), "{said}");
            assert!(!said.contains("1//row"), "{said}");
        }

        // And through the run itself: a normal answer carries none of the
        // values the run held, and the sweep over the real envelope passes.
        let mut run = Run::with(vec![grant(), me_ok(), tweet_ok()], r#"{"max_per_day":10}"#);
        let out = run.run("post", &post_input("gm")).unwrap();
        let spelled = out.to_string();
        for secret in ["1//row", "our-id", "our-secret", "AT"] {
            assert!(!spelled.contains(secret), "`{secret}` in {spelled}");
        }
        assert!(connector_core::sweep(&envelope("post".into(), Ok(out)), run.secrets.list()).is_ok());
    }
}
