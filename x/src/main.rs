//! The x connector: an agent posts to X as the owner's connected account,
//! under the owner's policy, without ever holding the credential.
//!
//! | `operation` | class | what it does |
//! |---|---|---|
//! | `status` | read | whether the credential works — proved by refreshing it — which OAuth client the run used, the policy's caps, the caller's own posts today |
//! | `me` | read | the connected account's handle, for the UI |
//! | `post` | write | one post, policy-checked first; a task for the owner when their policy says `confirm` |
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
}

/// Everything this connector sells. A name not here is refused with the list.
const OPERATIONS: &[&str] = &[
    "status",
    "me",
    "post",
    "confirm",
    "task_status",
    "task_cancel",
    "task_delete",
    "tasks",
    "tasks_unlock",
];

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
        "task_status" => confirm::task(op, input),
        "task_cancel" => confirm::task(op, input),
        "task_delete" => confirm::task(op, input),
        "tasks" => confirm::task(op, input),
        "tasks_unlock" => confirm::task(op, input),
        "" => Err(format!(
            "no `operation` in the input. This connector sells: {}",
            OPERATIONS.join(", ")
        )),
        other => Err(format!(
            "unknown operation `{other}`. This connector sells: {}",
            OPERATIONS.join(", ")
        )),
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
        "next": "`post` with `text`",
    }))
}

/// The connected account's handle, for the UI.
fn me(transport: &dyn Transport, store: &dyn RecordStore, secrets: &mut Secrets) -> Result<Value, String> {
    let credential = oauth::credential()?;
    let granted = oauth::access_token(transport, store, &credential, connector_core::now_secs(), secrets)?;
    let account = x_api::me(transport, &granted)?;
    Ok(json!({"id": account.id, "username": account.username, "name": account.name}))
}

/// One post, policy-checked first.
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
    let rules = policy::require()?;
    if rules.confirms(policy::Confirmable::Post) {
        return confirm::ask(text);
    }
    let prepared = confirm::Prepared { text: text.to_string() };
    deliver(&rules, &prepared, transport, store, secrets, Counted::Own).map_err(|outcome| outcome.refusal())
}

/// Post a text that passed the owner's rules, counted as `counted` says.
///
/// The owner's own cap, if they set one, is taken BEFORE anything leaves —
/// atomically, so two calls at once cannot both see room for the last
/// post. Any return from here without `keep` gives it back; an outcome
/// that is unknown KEEPS it: a count one too high refuses a post, one too
/// low allows one.
fn deliver(
    rules: &policy::Policy,
    prepared: &confirm::Prepared,
    transport: &dyn Transport,
    store: &dyn RecordStore,
    secrets: &mut Secrets,
    counted: Counted,
) -> Result<Value, Outcome> {
    let day = connector_core::day_key(connector_core::now_ms());
    let key = policy::count_key(&day, counted);
    let reservation = match rules.max_per_day {
        Some(cap) => {
            let (reservation, used) =
                connector_core::reserve(|key, delta| runtime::store_bump(store, key, delta), key, cap)
                    .map_err(Outcome::Refused)?;
            Some((reservation, used))
        }
        None => None,
    };

    let credential = oauth::credential().map_err(Outcome::Refused)?;
    let granted =
        oauth::access_token(transport, store, &credential, connector_core::now_secs(), secrets).map_err(Outcome::Refused)?;
    if !granted.grants(x_api::TWEET_WRITE) {
        return Err(Outcome::Refused(connector_core::refusal::scope_missing(x_api::TWEET_WRITE, "X")));
    }

    // The handle, for the url; a `me` that fails says nothing about the
    // post, and the answer falls back to the handle-less form.
    let handle = x_api::me(transport, &granted).ok().map(|account| account.username);

    let tweet_id = match x_api::tweet(transport, &granted, &prepared.text) {
        Ok(id) => id,
        // A post that may have left keeps its place in today's count: a
        // count one too high refuses a post, one too low allows one.
        Err(unknown @ Outcome::Unknown(_)) => {
            if let Some((reservation, _)) = reservation {
                reservation.keep();
            }
            return Err(unknown);
        }
        Err(Outcome::Refused(why)) => return Err(Outcome::Refused(why)),
    };
    let sent_today = reservation.map(|(reservation, used)| {
        reservation.keep();
        used
    });

    let url = match handle {
        Some(username) => format!("https://x.com/{username}/status/{tweet_id}"),
        None => format!("https://x.com/i/web/status/{tweet_id}"),
    };
    Ok(json!({
        "tweet_id": tweet_id,
        "url": url,
        "text": prepared.text,
        "sent_today": sent_today,
        "remaining_today": rules.max_per_day.zip(sent_today).map(|(cap, used)| cap.saturating_sub(used)),
    }))
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
            let said = run.run("delete", &Input::default()).unwrap_err();
            assert!(said.refusal.contains("unknown operation `delete`"), "{said:?}");
            assert!(said.refusal.contains("status, me, post"), "{said:?}");
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
        assert_eq!(out["next"], "`post` with `text`");
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
