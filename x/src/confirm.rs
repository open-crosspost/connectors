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

use crate::{oauth, policy};
use crate::runtime::{RecordStore, Secrets, Transport};
use connector_core::Outcome;
use outlayer::tasks::{self, Display, FieldKind, WrittenBy};
use serde_json::Value;

/// The operation the platform starts, as the agent, on the owner's approval.
pub const ANSWERED_BY: &str = "confirm";

/// What a confirmed post holds, sealed as the task's state. No attachments,
/// no recipients: a post is its text.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepared {
    pub text: String,
}

/// The post as the owner reads it: what is shown is what is sent.
fn shown(text: &str) -> Prepared {
    Prepared { text: text.replace("\r\n", "\n") }
}

fn display(prepared: &Prepared) -> Result<Display, String> {
    Ok(Display::new("Post to X").field("Text", FieldKind::LongText, &prepared.text, WrittenBy::Agent))
}

/// Leave `text`, which passed the owner's rules, as a task for the owner.
pub fn ask(text: &str) -> Result<Value, String> {
    let prepared = shown(text);
    let state = serde_json::to_vec(&prepared).map_err(|e| format!("the post could not be kept: {e}"))?;
    let task = tasks::confirm(display(&prepared)?, ANSWERED_BY, &state, &policy::stored());
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

/// The post a task held.
fn held(state: &[u8]) -> Result<Prepared, String> {
    serde_json::from_slice(state).map_err(|_| "task_unreadable: the task does not hold a post".to_string())
}

/// The run the platform starts on the owner's approval: post the text the
/// task holds.
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
    let prepared = match held(&answer.state).and_then(|p| policy::check_text(&p.text).map(|_| p)) {
        Ok(prepared) => prepared,
        Err(why) => return refused(why),
    };
    // Counted in this run's own cell, beside the agent's direct posts: the
    // cap is the owner's bound on this agent, confirmed or not.
    let mut posted = match super::deliver(rules, &prepared, transport, store, secrets, policy::Counted::Confirmed) {
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

/// The refusal when the post left and its result could not be left for the
/// agent: the task ends as failed although the post went out, so the
/// sentence says which of the two is true.
fn sent_unreported(refusal: String, tweet_id: &str) -> String {
    format!(
        "{}. The post WAS sent (tweet {tweet_id}) and the task is closed without its result: do not post it again",
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
            state: serde_json::to_vec(&shown(text)).unwrap(),
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
        let empty = tasks::Answer { state: serde_json::to_vec(&shown("   ")).unwrap(), ..answer_holding("gm") };
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
        assert!(said.contains("WAS sent") && said.contains("1901") && said.contains("do not post it again"), "{said}");
        assert!(!said.contains(CLOSED), "{said}");
    }
}
