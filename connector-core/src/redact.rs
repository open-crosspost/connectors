//! The guard between a connector and its answer: no secret value is ever
//! reachable from any output.
//!
//! The values a run holds — the owner's refresh token, the access token
//! minted from it, the OAuth client secret — must never appear in what the
//! run answers. The discipline is to build answers from things worth
//! saying; this guard is the check that the discipline held. A connector
//! calls [`sweep`] on its envelope before writing it, with every secret
//! value it read from the environment and every credential value it minted.
//! A value that appears anywhere in the answer fails the run with a
//! sentence that names no value — echoing the value in the refusal would be
//! the leak it exists to stop.
//!
//! Presence is judged on the serialized envelope, so a secret hiding inside
//! a nested member, a log row or an error sentence is caught all the same.

use crate::envelope::Envelope;

/// Fail the run if any secret value appears anywhere in the envelope.
///
/// `secrets` are the values as they were read — trimmed or not, they are
/// judged both ways. Empty and very short values (a credential could be one
/// character, but three characters of it are not a signature of anything)
/// are skipped: they would match ordinary words in every sentence. The
/// error names WHICH kind of secret leaked, never the value.
pub fn sweep(envelope: &Envelope, secrets: &[(&str, String)]) -> Result<(), String> {
    let spelled = serde_json::to_string(envelope).unwrap_or_default();
    let lower = spelled.to_lowercase();
    for (kind, value) in secrets {
        for candidate in [value.as_str(), value.trim()] {
            if candidate.len() < 4 {
                continue;
            }
            if spelled.contains(candidate) || lower.contains(&candidate.to_lowercase()) {
                return Err(format!(
                    "internal: the answer to `{operation}` would echo a {kind}; refused, and nothing \
                     of it is said here — the run ends without an output",
                    operation = envelope.operation
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn env_with(output: serde_json::Value) -> Envelope {
        Envelope { success: true, operation: "post".into(), output: Some(output), error: None, logs: Vec::new() }
    }

    fn secrets() -> Vec<(&'static str, String)> {
        vec![
            ("refresh token", "1//0hCANNOTbeReal_ABC".into()),
            ("access token", "AAAAAAAAAAtoken".into()),
            ("client secret", "s3cr3t-client-secret".into()),
        ]
    }

    #[test]
    fn a_clean_answer_passes() {
        let env = env_with(json!({ "tweet_id": "1", "url": "https://x.com/a/status/1" }));
        assert!(sweep(&env, &secrets()).is_ok());
    }

    #[test]
    fn a_secret_in_any_member_fails_the_run() {
        // In the output, nested.
        let env = env_with(json!({ "detail": "token 1//0hCANNOTbeReal_ABC failed" }));
        let said = sweep(&env, &secrets()).unwrap_err();
        assert!(said.starts_with("internal: "), "{said}");
        assert!(said.contains("refresh token") && !said.contains("1//0h"), "the refusal names no value: {said}");

        // In a log row.
        let mut env = env_with(json!({}));
        env.logs = vec![json!("sent AAAAAAAAAAAtoken to X")];
        assert!(sweep(&env, &secrets()).is_err());

        // In an error sentence.
        let mut env = env_with(json!({}));
        env.success = false;
        env.error = Some("s3cr3t-client-secret was wrong".into());
        assert!(sweep(&env, &secrets()).is_err());
    }

    /// Case-insensitive, and both the raw and the trimmed value are judged.
    #[test]
    fn a_secret_is_joined_case_and_whitespace_be_damned() {
        let mut env = env_with(json!({}));
        env.error = Some("S3CR3T-CLIENT-SECRET".into());
        assert!(sweep(&env, &secrets()).is_err());
        let env = env_with(json!("1//0hcannotbereal_abc"));
        assert!(sweep(&env, &secrets()).is_err(), "lowercased in the output: {env:?}");
    }

    /// A short value would match ordinary words in every sentence, so short
    /// candidates are skipped rather than made useless by false positives.
    #[test]
    fn a_too_short_value_catches_nothing() {
        let env = env_with(json!("ab is here"));
        assert!(sweep(&env, &[("short", "ab".into())]).is_ok());
        assert!(sweep(&env, &[("short", "  ".into())]).is_ok());
    }
}
