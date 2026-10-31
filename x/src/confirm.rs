//! A post the owner asked to confirm.
//!
//! When the owner's policy lists `post` under `confirm`, the agent's `post`
//! checks the text against the policy, and instead of posting it leaves it
//! as a task: the owner is shown exactly what would go out. The owner
//! approves with one signature of their wallet, and the platform starts
//! `confirm` as a run of the agent that prepared the task — on the agent's
//! own payment key — with the approval in its input. That run takes the
//! text back, checks it against the policy the task was made under — a task
//! made under another is void — and posts it.
//!
//! `awaiting_owner` is a SUCCESS: the owner's confirmation is pending, and
//! the caller does not retry. The outcome is read with `task_status`.

use crate::{oauth, policy, x_api};
use crate::runtime::{RecordStore, Secrets, Transport};
use connector_core::Outcome;
use outlayer::tasks::{self, Display, FieldKind, WrittenBy};
use serde_json::Value;

/// The operation the platform starts, as the agent, on the owner's approval.
pub const ANSWERED_BY: &str = "confirm";

/// What a confirmed action holds, sealed as the task's state. An untagged
/// enum, deliberately: a state sealed by an earlier build is the post's
/// text alone — its reply target and poll optional members — so it reads
/// as a Post, and every new kind names itself. No `deny_unknown_fields`
/// here ON PURPOSE: serde's untagged matching reads that attribute as
/// "field names are variant names" and refuses every honest state — the
/// kinds still cannot be told apart wrong, each carrying a member the
/// other two lack (a text, a `repost_of`, a `delete_of`).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Prepared {
    Post {
        text: String,
        /// When the post answers another post: its snowflake id, resolved
        /// before the post was prepared.
        #[serde(default)]
        reply_to: Option<String>,
        /// When the post opens a poll: options and minutes, validated
        /// before the post was prepared.
        #[serde(default)]
        poll: Option<x_api::Poll>,
    },
    /// The tweet being stamped, as its snowflake id.
    Repost { repost_of: String },
    /// The tweet being withdrawn, as its snowflake id. X refuses anything
    /// the account did not author; the owner's signature says the rest.
    Delete { delete_of: String },
}

/// The post as the owner reads it: what is shown is what is sent — the
/// reply target and the poll beside the text, when the post carries them.
pub fn shown(text: &str, reply_to: Option<String>, poll: Option<x_api::Poll>) -> Prepared {
    Prepared::Post { text: text.replace("\r\n", "\n"), reply_to, poll }
}

fn display(prepared: &Prepared) -> Result<Display, String> {
    match prepared {
        Prepared::Post { text, reply_to, poll } => {
            let mut display = Display::new("Post to X").field("Text", FieldKind::LongText, text, WrittenBy::Agent);
            if let Some(id) = reply_to {
                display = display.field("Reply to", FieldKind::Text, &status_url(id), WrittenBy::Project);
            }
            match poll {
                Some(poll) => Ok(display
                    .list("Poll options", &poll.options, WrittenBy::Agent)
                    .field("Poll open for", FieldKind::Text, &format!("{} minutes", poll.duration_minutes), WrittenBy::Project)),
                None => Ok(display),
            }
        }
        Prepared::Repost { repost_of } => Ok(Display::new("Repost to X")
            .field("Repost of", FieldKind::Text, &status_url(repost_of), WrittenBy::Agent)),
        Prepared::Delete { delete_of } => Ok(Display::new("Delete from X")
            .field("Delete", FieldKind::Text, &status_url(delete_of), WrittenBy::Agent)),
    }
}

/// A tweet's url as anyone reaches it: the handleless form is exact for
/// every tweet, whoever wrote it.
pub fn status_url(id: &str) -> String {
    format!("https://x.com/i/web/status/{id}")
}

/// Leave a post, a repost or a delete, which passed the owner's rules, as a
/// task for the owner.
pub fn ask(prepared: &Prepared) -> Result<Value, String> {
    let state = serde_json::to_vec(prepared).map_err(|e| format!("the action could not be kept: {e}"))?;
    let task = tasks::confirm(display(prepared)?, ANSWERED_BY, &state, &policy::stored());
    let opened = task.open().map_err(|e| e.refusal())?;
    Ok(tasks::awaiting_owner(&opened))
}

fn named<'a>(value: &'a Option<String>, member: &str) -> Result<&'a str, String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("task_answer_invalid: the call names no `{member}`"))
}

/// What is checked before the owner's answer is taken: that the call names
/// the task, its hash and the owner's approval, and that the owner's policy
/// is there and readable.
fn before_answer(input: &super::Input, loaded: policy::Loaded<policy::Policy>) -> Result<(Value, policy::Policy), String> {
    let id = named(&input.task_id, "task_id")?;
    let hash = named(&input.task_hash, "task_hash")?;
    let approval = input.approval.clone().ok_or("task_answer_invalid: the call carries no `approval`")?;
    let call = serde_json::json!({ "task_id": id, "task_hash": hash, "approval": approval, "note": input.note });
    Ok((call, policy::required(loaded, oauth::POLICY_ENV, oauth::CONNECT_PAGE)?))
}

/// The action a task held.
fn held(state: &[u8]) -> Result<Prepared, String> {
    serde_json::from_slice(state).map_err(|_| "task_unreadable: the task does not hold a post, a repost or a delete".to_string())
}

/// The run the platform starts on the owner's approval: carry out what the
/// task holds — the post, the repost or the delete its preparer sealed.
///
/// **Refused before the answer is taken** — a call that names no `task_id`,
/// `task_hash` or `approval`; a policy that is absent or cannot be read;
/// everything the host refuses the answer for. The task fails when the run
/// ends (`run_refused:…`) and the agent prepares again.
///
/// **Refused after the answer is taken** — the task ends as failed, and the
/// refusal's sentence says so. A post whose outcome is not known is NOT
/// reported as not carried out: the task ends `run_unreported` — "it may
/// have acted".
pub fn confirm(
    input: &super::Input,
    transport: &dyn Transport,
    store: &dyn RecordStore,
    secrets: &mut Secrets,
) -> Result<Value, tasks::Refused> {
    let (call, rules) = before_answer(input, policy::load())?;
    let answer = tasks::answered_for(ANSWERED_BY, &call, &policy::stored()).map_err(|e| e.refusal())?;
    let notice = std::cell::RefCell::new(None);
    after_answer(
        &rules,
        &answer,
        transport,
        store,
        secrets,
        |id, result| tasks::report(id, result).map_err(|e| e.refusal()),
        |id, refusal| {
            let told = tasks::failed_and_told(id, refusal, &policy::stored());
            *notice.borrow_mut() = told.notice;
            told.reported.map_err(|e| e.refusal())
        },
    )
    .map_err(|refusal| tasks::Refused { refusal, notice: notice.take() })
}

/// Everything that follows the answer: the task is `answering`, and any
/// refusal from here ends it. `send` posts and `report` leaves the result
/// for the agent — the host's doing in a run. A post whose outcome is not
/// known is NOT reported as not carried out: the task ends
/// `run_unreported`, and the refusal still answers.
fn after_answer(
    rules: &policy::Policy,
    answer: &tasks::Answer,
    transport: &dyn Transport,
    store: &dyn RecordStore,
    secrets: &mut Secrets,
    report: impl FnOnce(&str, &[u8]) -> Result<(), String>,
    fail: impl FnOnce(&str, &str) -> Result<(), String>,
) -> Result<Value, String> {
    // Nothing was posted: the agent reads why as the failed task's result.
    let refused = |why: String| {
        let refusal = closed(why);
        let _ = fail(&answer.id, &refusal);
        Err(refusal)
    };
    let prepared = match held(&answer.state) {
        Ok(prepared) => prepared,
        Err(why) => return refused(why),
    };
    // A post's text passes the rules again — every other kind carries no
    // text that X would weigh.
    if let Prepared::Post { text, .. } = &prepared {
        if let Err(why) = policy::check_text(text) {
            return refused(why);
        }
    }
    // The wire call the kind asks for, counted in this run's own cell,
    // beside the agent's direct posts: the cap is the owner's bound on this
    // agent, confirmed or not.
    let action = match &prepared {
        Prepared::Post { text, reply_to, poll } => super::Action::Post {
            text: text.clone(),
            reply_to: reply_to.clone(),
            poll: poll.clone(),
        },
        Prepared::Repost { repost_of } => super::Action::Repost { repost_of: repost_of.clone() },
        Prepared::Delete { delete_of } => super::Action::Delete { delete_of: delete_of.clone() },
    };
    let mut posted =
        match super::deliver(rules, &action, transport, store, secrets, policy::Counted::Confirmed) {
            Ok(posted) => posted,
            Err(Outcome::Refused(why)) => return refused(why),
            Err(unknown @ Outcome::Unknown(_)) => return Err(unknown.refusal()),
        };
    if let Some(note) = answer.note.as_deref().and_then(|n| std::str::from_utf8(n).ok()) {
        posted["note"] = serde_json::json!(note);
    }
    // The agent reads the whole of it: the host seals a report for the
    // preparer. A post is public by nature, so the report holds everything.
    report(&answer.id, posted.to_string().as_bytes())
        .map_err(|e| sent_unreported(e, posted.get("tweet_id").and_then(Value::as_str).unwrap_or("unknown")))?;
    let mut out = posted;
    out["status"] = serde_json::json!("done");
    out["task_id"] = serde_json::json!(answer.id);
    Ok(out)
}

/// What every refusal after the answer was taken ends with.
const CLOSED: &str = "The task is closed: to post this, prepare it again";

fn closed(refusal: String) -> String {
    format!("{}. {CLOSED}", refusal.trim_end().trim_end_matches('.'))
}

/// The refusal when the action left and its result could not be left for
/// the agent: the task ends as failed although the action went through, so
/// the sentence says which of the two is true — and the agent carries its
/// evidence (the tweet id) either way.
fn sent_unreported(refusal: String, tweet_id: &str) -> String {
    format!(
        "{}. The tweet was acted on (tweet {tweet_id}) and the task is closed without its result: do not carry it out again",
        refusal.trim_end().trim_end_matches('.')
    )
}

/// The operations every project that uses tasks answers alike.
pub fn task(operation: &str, input: &super::Input) -> Result<Value, String> {
    let call = serde_json::json!({ "task_id": input.task_id });
    tasks::dispatch(operation, &call).unwrap_or_else(|| Err(format!("unknown operation `{operation}`")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Input;
    use crate::runtime::testing::{env_lock, MemStore, MockTransport};
    use std::cell::RefCell;

    fn rules() -> policy::Policy {
        serde_json::from_str(r#"{"max_per_day":10}"#).unwrap()
    }

    fn answer_holding(text: &str) -> tasks::Answer {
        tasks::Answer {
            id: "run-0".into(),
            thread: "run-0".into(),
            preparer: "agent.testnet".into(),
            kind: tasks::TaskKind::Confirm,
            operation: ANSWERED_BY.into(),
            state: serde_json::to_vec(&shown(text, None, None)).unwrap(),
            files: Vec::new(),
            supplied: None,
            note: None,
        }
    }

    fn posted() -> Value {
        serde_json::json!({
            "tweet_id": "1901", "url": "https://x.com/elliot/status/1901", "text": "gm",
            "sent_today": 1, "remaining_today": 9
        })
    }

    fn never_reports(_: &str, _: &[u8]) -> Result<(), String> {
        panic!("a refusal is never reported as carried out")
    }

    /// The owner's row in the environment, for the whole test: a refresh
    /// token, and our client to complete it. The lock is the env's: macOS's
    /// setenv is thread-unsafe, and tests that set the run's environment
    /// take it before they touch a variable.
    fn env_row() -> std::sync::MutexGuard<'static, ()> {
        let lock = env_lock();
        std::env::set_var(oauth::REFRESH_TOKEN_ENV, "1//row");
        std::env::set_var(oauth::OUR_CLIENT_ID_ENV, "our-id");
        std::env::set_var(oauth::OUR_CLIENT_SECRET_ENV, "our-secret");
        lock
    }

    fn never_fails(_: &str, _: &str) -> Result<(), String> {
        panic!("nothing is reported as not carried out")
    }

    /// A refusal from before the answer says nothing of a closed task: the
    /// task is as it was.
    #[test]
    fn before_the_answer_a_refusal_leaves_the_task_as_it_was() {
        let _row = env_row();
        let call = || Input {
            operation: String::new(),
            text: None,
            task_id: Some("run-0".into()),
            task_hash: Some("ab".repeat(32)),
            approval: Some(serde_json::json!({"at": 1, "public_key": "k", "signature": "s", "nonce": "n"})),
            note: None,
            reply_to: None, poll: None, tweet_id: None,
        };
        let no_policy = before_answer(&call(), policy::Loaded::None).unwrap_err();
        assert!(no_policy.starts_with("policy_denied: "), "{no_policy}");
        let unnamed = before_answer(&Input::default(), policy::Loaded::Some(rules())).unwrap_err();
        assert!(unnamed.starts_with("task_answer_invalid: ") && unnamed.contains("task_id"), "{unnamed}");
        let unsigned =
            before_answer(&Input { approval: None, ..call() }, policy::Loaded::Some(rules())).unwrap_err();
        assert!(unsigned.starts_with("task_answer_invalid: ") && unsigned.contains("approval"), "{unsigned}");
        for said in [no_policy, unnamed, unsigned] {
            assert!(!said.contains("closed") && !said.contains("prepare again"), "{said}");
        }
    }

    /// After the answer: every refusal keeps its code and says the task is
    /// closed — and is left for the agent as the failed task's result. The
    /// failures arrive through the mock, exactly as they arrive from X.
    #[test]
    fn after_the_answer_every_refusal_keeps_its_code_and_says_the_task_is_closed() {
        let _row = env_row();

        // A state that is not a post: refused before anything is sent.
        let failed: RefCell<Option<(String, String)>> = RefCell::new(None);
        let transport = MockTransport::with(vec![]);
        let store = MemStore::default();
        let mut secrets = Secrets::default();
        let fails = |id: &str, why: &str| {
            *failed.borrow_mut() = Some((id.to_string(), why.to_string()));
            Ok(())
        };
        let broken = tasks::Answer { state: b"not a post".to_vec(), ..answer_holding("gm") };
        let said = after_answer(&rules(), &broken, &transport, &store, &mut secrets, never_reports, fails).unwrap_err();
        assert!(said.starts_with("task_unreadable: "), "{said}");
        assert!(said.ends_with(CLOSED), "{said}");
        let (id, why) = failed.borrow_mut().take().expect("the refusal is reported as not carried out");
        assert_eq!((id.as_str(), why.as_str()), ("run-0", said.as_str()));

        // A post the rules refuse: an empty text, under any rules.
        let empty = tasks::Answer {
            state: serde_json::to_vec(&shown("   ", None, None)).unwrap(),
            ..answer_holding("gm")
        };
        let said = after_answer(&rules(), &empty, &transport, &store, &mut secrets, never_reports, fails).unwrap_err();
        assert!(said.starts_with("`text` is required"), "{said}");
        assert!(said.ends_with(CLOSED), "{said}");
        failed.borrow_mut().take();

        // Whatever the send refuses — a dead credential, X's throttle, X's
        // own refusal — ends the task with the same code, through the mock.
        // The calls in order: the refresh, the handle, the post.
        for failure in [
            // The refresh refused: the credential is dead.
            vec![MockTransport::ok(
                400,
                serde_json::json!({"error": "invalid_grant", "error_description": "Token expired"}),
            )],
            // The refresh ok, the handle ok, the post throttled.
            vec![MockTransport::ok(200, serde_json::json!({"expires_in": 7200, "access_token": "AT", "scope": "tweet.write users.read"})), MockTransport::ok(200, serde_json::json!({"data": {"id": "1", "username": "elliot", "name": "Elliot"}})), MockTransport::ok(429, serde_json::json!({"detail": "Rate limit exceeded"}))],
            // The refresh ok, the post refused outright in X's own words.
            vec![MockTransport::ok(200, serde_json::json!({"expires_in": 7200, "access_token": "AT", "scope": "tweet.write users.read"})), MockTransport::ok(200, serde_json::json!({"data": {"id": "1", "username": "elliot", "name": "Elliot"}})), MockTransport::ok(400, serde_json::json!({"detail": "could not authenticate you"}))],
        ] {
            let transport = MockTransport::with(failure);
            let store = MemStore::default();
            let mut secrets = Secrets::default();
            let failed: RefCell<Option<(String, String)>> = RefCell::new(None);
            let fails = |id: &str, why: &str| {
                *failed.borrow_mut() = Some((id.to_string(), why.to_string()));
                Ok(())
            };
            let said = after_answer(&rules(), &answer_holding("gm"), &transport, &store, &mut secrets, never_reports, fails).unwrap_err();
            assert!(said.ends_with(CLOSED), "{said}");
            let (id, why) = failed.borrow_mut().take().expect("the refusal is reported as not carried out");
            assert_eq!((id.as_str(), why.as_str()), ("run-0", said.as_str()));
        }
    }

    /// What is sent is what the task held, what is reported is whole, and
    /// what is answered carries the tweet id and the task's.
    #[test]
    fn a_confirmed_post_is_posted_reported_and_answered() {
        let _row = env_row();
        let transport = MockTransport::with(vec![
            MockTransport::ok(200, serde_json::json!({"expires_in": 7200, "access_token": "AT", "scope": "tweet.write users.read"})),
            MockTransport::ok(200, serde_json::json!({"data": {"id": "1", "username": "elliot", "name": "Elliot"}})),
            MockTransport::ok(201, serde_json::json!({"data": {"id": "1901", "text": "gm"}})),
        ]);
        let store = MemStore::default();
        let mut secrets = Secrets::default();
        let reported = RefCell::new(None);
        let report = |id: &str, result: &[u8]| {
            *reported.borrow_mut() = Some((id.to_string(), serde_json::from_slice::<Value>(result).unwrap()));
            Ok(())
        };
        let out = after_answer(&rules(), &answer_holding("gm"), &transport, &store, &mut secrets, report, never_fails).unwrap();
        assert_eq!(out["status"], "done");
        assert_eq!(out["task_id"], "run-0");
        assert_eq!(out["tweet_id"], "1901");
        let (id, result) = reported.borrow().clone().expect("a result was left");
        assert_eq!((id.as_str(), &result), ("run-0", &posted()));
        // Counted in the confirmed count, beside the agent's own.
        let day = connector_core::day_key(connector_core::now_ms());
        let key = policy::count_key(&day, policy::Counted::Confirmed);
        assert_eq!(store.count(&key), 1);
    }

    /// A task that holds a reply posts as a reply on the wire, and the
    /// reply target rides in the result the agent reads back.
    #[test]
    fn a_confirmed_task_that_holds_a_reply_posts_and_reports_a_reply() {
        let _row = env_row();
        let transport = MockTransport::with(vec![
            MockTransport::ok(200, serde_json::json!({"expires_in": 7200, "access_token": "AT", "scope": "tweet.write users.read"})),
            MockTransport::ok(200, serde_json::json!({"data": {"id": "1", "username": "elliot", "name": "Elliot"}})),
            MockTransport::ok(201, serde_json::json!({"data": {"id": "1902", "text": "gm"}})),
        ]);
        let store = MemStore::default();
        let mut secrets = Secrets::default();
        let answer =
            tasks::Answer { state: serde_json::to_vec(&shown("gm", Some("1901".into()), None)).unwrap(), ..answer_holding("gm") };
        let out =
            after_answer(&rules(), &answer, &transport, &store, &mut secrets, |_, _| Ok(()), never_fails).unwrap();
        assert_eq!(out["tweet_id"], "1902");
        assert_eq!(out["reply_to"], "1901");
        let body = serde_json::from_slice::<Value>(&transport.seen.borrow()[2].2).unwrap();
        assert_eq!(body["reply"]["in_reply_to_tweet_id"], serde_json::json!("1901"), "{body}");
    }

    /// A task sealed by an older build holds a text alone: it reads as a
    /// standalone post, not as unreadable.
    #[test]
    fn a_state_of_an_older_build_reads_as_a_standalone_post() {
        let prepared = held(b"{\"text\":\"gm\"}").unwrap();
        assert_eq!(prepared, Prepared::Post { text: "gm".into(), reply_to: None, poll: None });
    }

    /// What `ask` seals is read back exactly — the reply target and the
    /// poll ride beside the text, and every kind names itself: the owner
    /// approves what the run will do.
    #[test]
    fn what_the_task_seals_of_any_kind_reads_back_whole() {
        for prepared in [
            shown("gm", Some("1901".into()), None),
            shown("gm", None, None),
            shown("gm\r\njust text", Some("1901".into()), None),
            Prepared::Post {
                text: "gm".into(),
                reply_to: None,
                poll: Some(x_api::Poll { options: vec!["gm".into(), "night".into()], duration_minutes: 60 }),
            },
            Prepared::Repost { repost_of: "1901".into() },
            Prepared::Delete { delete_of: "1901".into() },
        ] {
            assert_eq!(held(&serde_json::to_vec(&prepared).unwrap()).unwrap(), prepared);
        }
    }

    /// A repost the owner confirmed: the run stamps the tweet, the confirmed
    /// count takes it like a post, and the report carries the wire's word.
    #[test]
    fn a_confirmed_repost_stamps_x_and_counts_like_a_post() {
        let _row = env_row();
        let transport = MockTransport::with(vec![
            MockTransport::ok(200, serde_json::json!({"expires_in": 7200, "access_token": "AT", "scope": "tweet.write users.read"})),
            MockTransport::ok(200, serde_json::json!({"data": {"id": "1", "username": "elliot", "name": "Elliot"}})),
            MockTransport::ok(200, serde_json::json!({"data": {"retweeted": true}})),
        ]);
        let store = MemStore::default();
        let mut secrets = Secrets::default();
        let report = |_: &str, _: &[u8]| Ok(());
        let prepared = Prepared::Repost { repost_of: "1901".into() };
        let answer = tasks::Answer { state: serde_json::to_vec(&prepared).unwrap(), ..answer_holding("gm") };
        let out = after_answer(&rules(), &answer, &transport, &store, &mut secrets, report, never_fails).unwrap();
        assert_eq!(out["status"], "done");
        assert_eq!(out["retweeted"], true);
        assert_eq!(out["tweet_id"], "1901");
        let (method, url, body) = &transport.seen.borrow()[2];
        assert_eq!((method, url.as_str()), (&crate::runtime::Method::Post, "https://api.x.com/2/users/1/retweets"));
        assert_eq!(serde_json::from_slice::<Value>(body).unwrap()["tweet_id"], serde_json::json!("1901"));
        // The confirmed count, beside the agent's own.
        let day = connector_core::day_key(connector_core::now_ms());
        let key = policy::count_key(&day, policy::Counted::Confirmed);
        assert_eq!(store.count(&key), 1);
    }

    /// A delete the owner confirmed: X's DELETE leaves, nothing is counted —
    /// removal is not output — and the report says what is gone.
    #[test]
    fn a_confirmed_delete_refuses_x_and_carries_no_count() {
        let _row = env_row();
        let transport = MockTransport::with(vec![
            MockTransport::ok(200, serde_json::json!({"expires_in": 7200, "access_token": "AT", "scope": "tweet.write users.read"})),
            MockTransport::ok(200, serde_json::json!({"data": {"deleted": true}})),
        ]);
        let store = MemStore::default();
        let mut secrets = Secrets::default();
        let reported = RefCell::new(None);
        let report = |id: &str, result: &[u8]| {
            *reported.borrow_mut() = Some((id.to_string(), serde_json::from_slice::<Value>(result).unwrap()));
            Ok(())
        };
        let prepared = Prepared::Delete { delete_of: "1901".into() };
        let answer = tasks::Answer { state: serde_json::to_vec(&prepared).unwrap(), ..answer_holding("gm") };
        let out = after_answer(&rules(), &answer, &transport, &store, &mut secrets, report, never_fails).unwrap();
        assert_eq!(out["deleted"], true);
        assert_eq!(out["tweet_id"], "1901");
        assert_eq!(out["status"], "done");
        for counted in [policy::Counted::Own, policy::Counted::Confirmed] {
            let day = connector_core::day_key(connector_core::now_ms());
            let key = policy::count_key(&day, counted);
            assert_eq!(store.count(&key), 0, "a delete is not feed output");
        }
        let result = reported.borrow().clone().expect("a result was left");
        assert_eq!(result.1["deleted"], serde_json::json!(true));
    }

    /// A confirmed delete whose outcome is lost: the task ends unreported —
    /// the delete may have left — and it counts nothing either way.
    #[test]
    fn a_confirmed_delete_whose_outcome_is_lost_is_never_reported() {
        let _row = env_row();
        let transport = MockTransport::with(vec![
            MockTransport::ok(200, serde_json::json!({"expires_in": 7200, "access_token": "AT", "scope": "tweet.write users.read"})),
            MockTransport::network("connection reset"),
        ]);
        let store = MemStore::default();
        let mut secrets = Secrets::default();
        let prepared = Prepared::Delete { delete_of: "1901".into() };
        let answer = tasks::Answer { state: serde_json::to_vec(&prepared).unwrap(), ..answer_holding("gm") };
        let said = after_answer(&rules(), &answer, &transport, &store, &mut secrets, never_reports, never_fails).unwrap_err();
        assert!(said.contains("outcome is unknown"), "{said}");
        assert!(!said.contains(CLOSED), "{said}");
        for counted in [policy::Counted::Own, policy::Counted::Confirmed] {
            let day = connector_core::day_key(connector_core::now_ms());
            let key = policy::count_key(&day, counted);
            assert_eq!(store.count(&key), 0, "nothing was counted");
        }
    }

    /// The owner's note reaches the agent with the result, and changes
    /// nothing of what was posted.
    #[test]
    fn the_owners_note_rides_with_the_result() {
        let _row = env_row();
        let transport = MockTransport::with(vec![
            MockTransport::ok(200, serde_json::json!({"expires_in": 7200, "access_token": "AT", "scope": "tweet.write users.read"})),
            MockTransport::ok(200, serde_json::json!({"data": {"id": "1", "username": "elliot", "name": "Elliot"}})),
            MockTransport::ok(201, serde_json::json!({"data": {"id": "1901", "text": "gm"}})),
        ]);
        let store = MemStore::default();
        let mut secrets = Secrets::default();
        let mut answer = answer_holding("gm");
        answer.note = Some("today only".as_bytes().to_vec());
        let report = |_: &str, _: &[u8]| Ok(());
        let out = after_answer(&rules(), &answer, &transport, &store, &mut secrets, report, never_fails).unwrap();
        assert_eq!(out["note"], "today only");
        assert_eq!(out["tweet_id"], "1901", "the note changes nothing of the post");
    }

    /// A post whose outcome is lost is reported NEITHER way: the task ends
    /// `run_unreported` — the post may have gone out.
    #[test]
    fn a_post_whose_outcome_is_lost_is_never_reported_as_not_sent() {
        let _row = env_row();
        let transport = MockTransport::with(vec![
            MockTransport::ok(200, serde_json::json!({"expires_in": 7200, "access_token": "AT", "scope": "tweet.write users.read"})),
            MockTransport::ok(200, serde_json::json!({"data": {"id": "1", "username": "elliot", "name": "Elliot"}})),
            MockTransport::network("connection reset"),
        ]);
        let store = MemStore::default();
        let mut secrets = Secrets::default();
        let said = after_answer(&rules(), &answer_holding("gm"), &transport, &store, &mut secrets, never_reports, never_fails).unwrap_err();
        assert!(said.contains("outcome is unknown"), "{said}");
        assert!(!said.contains(CLOSED), "{said}");
        // The place in the count is kept: the post may have left.
        let day = connector_core::day_key(connector_core::now_ms());
        let key = policy::count_key(&day, policy::Counted::Confirmed);
        assert_eq!(store.count(&key), 1);
    }

    /// A post that left and was not reported: the task ends failed, and
    /// the sentence says the post WAS sent.
    #[test]
    fn a_post_that_left_and_was_not_reported_is_said_to_have_left() {
        let _row = env_row();
        let transport = MockTransport::with(vec![
            MockTransport::ok(200, serde_json::json!({"expires_in": 7200, "access_token": "AT", "scope": "tweet.write users.read"})),
            MockTransport::ok(200, serde_json::json!({"data": {"id": "1", "username": "elliot", "name": "Elliot"}})),
            MockTransport::ok(201, serde_json::json!({"data": {"id": "1901", "text": "gm"}})),
        ]);
        let store = MemStore::default();
        let mut secrets = Secrets::default();
        let report = |_: &str, _: &[u8]| Err("task_store_unavailable: the task store did not answer".into());
        let said = after_answer(&rules(), &answer_holding("gm"), &transport, &store, &mut secrets, report, never_fails).unwrap_err();
        assert!(said.starts_with("task_store_unavailable: "), "{said}");
        assert!(said.contains("was acted on") && said.contains("1901") && said.contains("do not carry it out again"), "{said}");
        assert!(!said.contains(CLOSED), "{said}");
    }
}
