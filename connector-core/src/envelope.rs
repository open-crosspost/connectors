//! The answer shape every connector in the family speaks, and the run
//! refusal that rides beside it.
//!
//! The connector's own answer is `{success, operation, output, error, logs}`
//! — the field is `error`, never `error_message` — and it is what the
//! platform puts inside the `output` of a call. A refusal is HTTP 200 with
//! `success: false`; the agent branches on the sentence's prefix, so the
//! prefixes are the connector family's contract (see [`crate::refusal`]).
//!
//! Modeled on the platform's own connectors (`gmail-connector` in
//! `out-layer/outlayer`); a run whose input never parsed answers a bare
//! failure with an empty `operation`.

use serde::Serialize;
use serde_json::Value;

/// The envelope of every run: the operation as it was asked (empty when the
/// input never parsed), the output on success, and the refusal on failure.
///
/// `output` and `error` are absent rather than `null` when they have nothing
/// to say: a reader that checks `output` must not mistake a present-but-null
/// member for an answer.
#[derive(Debug, Serialize, PartialEq)]
pub struct Envelope {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
    pub logs: Vec<Value>,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A run refused: the sentence the agent reads, and — for a refusal that
/// reached the owner through a task — the notice that told them why.
#[derive(Debug, Clone)]
pub struct Refused {
    pub refusal: String,
    pub notice: Option<Value>,
}

impl Refused {
    /// What the answer's `output` holds: nothing for a plain refusal; the
    /// notice that reached the owner beside a refused confirmation.
    pub fn output(&self) -> Option<Value> {
        self.notice.as_ref().map(|notice| serde_json::json!({ "notice": notice }))
    }
}

impl From<String> for Refused {
    fn from(refusal: String) -> Self {
        Refused { refusal, notice: None }
    }
}

impl From<&str> for Refused {
    fn from(refusal: &str) -> Self {
        Refused::from(refusal.to_string())
    }
}

/// The envelope of a run that read its input: the output, or the refusal and
/// what the refusal names beside it.
pub fn envelope(operation: String, answered: Result<Value, Refused>) -> Envelope {
    match answered {
        Ok(output) => {
            Envelope { success: true, operation, error: None, output: Some(output), logs: Vec::new() }
        }
        Err(r) => Envelope {
            success: false,
            operation,
            output: r.output(),
            error: Some(r.refusal),
            logs: Vec::new(),
        },
    }
}

/// The envelope of a run whose input never parsed: a bare failure that names
/// no operation, since there is not one to name.
pub fn undecodable(why: String) -> Envelope {
    Envelope {
        success: false,
        operation: String::new(),
        error: Some(why),
        output: None,
        logs: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_answer_carries_the_operation_and_the_output() {
        let out = envelope("ping".into(), Ok(json!({ "ok": true })));
        assert_eq!(out.success, true);
        assert_eq!(out.operation, "ping");
        assert_eq!(out.output, Some(json!({ "ok": true })));
        assert!(out.error.is_none(), "a success carries no error member");
    }

    /// The field is `error`. `error_message` is the one shape this family
    /// never speaks: callers branch on `error`'s prefix.
    #[test]
    fn the_error_field_is_error_and_nothing_else() {
        let spelled = serde_json::to_value(envelope("post".into(), Err(Refused::from("rate_limited: slow down"))))
            .unwrap();
        assert_eq!(spelled["error"], json!("rate_limited: slow down"));
        assert_eq!(spelled["success"], json!(false));
        assert!(spelled.get("error_message").is_none(), "{spelled}");
        assert!(spelled.get("output").is_none(), "a refusal that told nobody answers no output");
        assert!(spelled.get("message").is_none(), "{spelled}");
    }

    #[test]
    fn a_refusal_that_told_the_owner_names_the_notice_beside_it() {
        let refused = Refused {
            refusal: "bank refused".into(),
            notice: Some(json!({ "task_id": "run-7", "task_hash": "c0ffee" })),
        };
        let spelled = serde_json::to_value(envelope("confirm".into(), Err(refused))).unwrap();
        assert_eq!(spelled["output"]["notice"]["task_id"], json!("run-7"));
        assert_eq!(spelled["error"], json!("bank refused"));
    }

    #[test]
    fn an_undecodable_input_names_no_operation() {
        let out = undecodable("input is not the expected JSON: x".into());
        assert_eq!(out.success, false);
        assert_eq!(out.operation, "");
        assert_eq!(out.error.as_deref(), Some("input is not the expected JSON: x"));
    }
}
