//! Every record a connector keeps, sealed under an encryption key declared
//! in the connector's `manifest.json` (`encryption_keys[].path`), derived for
//! the caller: the value is encrypted inside the run and stored raw, so no
//! storage operation calls the keystore, and the storage operator sees a
//! keyed tag and a ciphertext — never a record's name or value. Records
//! written without sealing are not read.
//!
//! The one primitive the family builds budgets on is [`increment`]: atomic
//! (a compare-and-set on the sealed record, retried while another call
//! changed it first). Never read a counter and then write it back — two
//! calls of one agent can run at once, and a read-then-write lets both see
//! room for one more.

use outlayer::storage::sealed;
use outlayer::storage::{Result, StorageError};

/// How many times [`increment`] retries a counter another call changed
/// first.
const INCREMENT_ATTEMPTS: usize = 16;

/// Record `name`, opened; `None` when there is none.
pub fn get(path: &str, name: &str) -> Result<Option<Vec<u8>>> {
    Ok(sealed::get(path, None, name)?.map(|s| s.into_plaintext()))
}

pub fn set(path: &str, name: &str, value: &[u8]) -> Result<()> {
    sealed::set(path, None, name, value)
}

/// Set only when the record is absent; answers whether it was set.
pub fn set_if_absent(path: &str, name: &str, value: &[u8]) -> Result<bool> {
    sealed::set_if_absent(path, None, name, value)
}

/// Set `name` to `next` only when it currently holds `current` (compared as
/// plaintext, CAS'd on the sealed record). Answers whether it was written:
/// the caller treats a `false` the same as a storage failure — the counter
/// moved under it, and the retry loop starts over.
pub fn set_if_equals_plaintext(path: &str, name: &str, current: &[u8], next: &[u8]) -> Result<bool> {
    match sealed::get(path, None, name)? {
        None => {
            if current.is_empty() {
                Ok(sealed::set_if_absent(path, None, name, next)?)
            } else {
                Ok(false)
            }
        }
        Some(record) if record.plaintext() == current => {
            Ok(sealed::set_if_equals(path, None, name, &record, next).map(|(written, _)| written)?)
        }
        Some(_) => Ok(false),
    }
}

/// Add `delta` to counter `name` and answer the new value, atomically: a
/// compare-and-set on the sealed record, retried while another call changed
/// it first. A missing counter starts at zero; `delta` 0 reads it.
pub fn increment(path: &str, name: &str, delta: i64) -> Result<i64> {
    cas_increment(
        |name| sealed::get(path, None, name).map(|r| r.map(|r| r.into_plaintext())).map_err(|e| e.to_string()),
        |name, value| sealed::set_if_absent(path, None, name, value).map_err(|e| e.to_string()),
        |name, current, next| {
            // `current` came back as plaintext from `get`; to CAS on the
            // sealed record the record itself is fetched again — one read
            // more, and the compare-and-set stays the host's.
            match sealed::get(path, None, name) {
                Ok(Some(record)) if record.plaintext() == current => sealed
                    ::set_if_equals(path, None, name, &record, next)
                    .map(|(written, _)| written)
                    .map_err(|e| e.to_string()),
                Ok(_) => Ok(false),
                Err(e) => Err(e.to_string()),
            }
        },
        name,
        delta,
    )
    .map_err(StorageError)
}

/// The one compare-and-set loop the family counts through, generic over
/// the storage primitives: `delta` 0 reads, a missing counter starts at
/// zero, and a counter another call changed first is retried —
/// `attempts` times, then refused. A refusal is the safe direction for a
/// budget: the caller counts one too few, never lets one too many
/// through.
pub fn cas_increment(
    get: impl Fn(&str) -> std::result::Result<Option<Vec<u8>>, String>,
    set_if_absent: impl Fn(&str, &[u8]) -> std::result::Result<bool, String>,
    set_if_equals: impl Fn(&str, &[u8], &[u8]) -> std::result::Result<bool, String>,
    name: &str,
    delta: i64,
) -> std::result::Result<i64, String> {
    for _ in 0..INCREMENT_ATTEMPTS {
        match get(name)? {
            None => {
                if delta == 0 {
                    return Ok(0);
                }
                if set_if_absent(name, delta.to_string().as_bytes())? {
                    return Ok(delta);
                }
            }
            Some(current) => {
                let now: i64 = std::str::from_utf8(&current)
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| format!("counter {name} does not hold a number"))?;
                if delta == 0 {
                    return Ok(now);
                }
                let next = now + delta;
                if set_if_equals(name, &current, next.to_string().as_bytes())? {
                    return Ok(next);
                }
            }
        }
    }
    Err(format!("counter {name} kept changing under concurrent calls ({INCREMENT_ATTEMPTS} attempts)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The loop is exercised to its cap through `reserve`'s tests (the
    /// stand-in there is the same shape); what is tested here is the
    /// refusal after `INCREMENT_ATTEMPTS` lost races, which no amount of
    /// threading reaches in a unit test.
    #[test]
    fn a_counter_that_keeps_changing_is_retried_then_refused() {
        let said = cas_increment(
            |_| Ok(Some(b"1".to_vec())),
            |_, _| Ok(false),
            |_, _, _| Ok(false),
            "c",
            1,
        );
        assert!(said.is_err() && said.unwrap_err().contains("kept changing"), "lost races refuse the bump");
    }

    #[test]
    fn a_read_of_a_missing_counter_is_zero_and_a_parse_failure_is_refused() {
        let said = cas_increment(|_| Ok(None), |_, _| Ok(true), |_, _, _| Ok(false), "absent", 0);
        assert_eq!(said.unwrap(), 0);
        let said = cas_increment(|_| Ok(Some(b"not a number".to_vec())), |_, _| Ok(true), |_, _, _| Ok(false), "junk", 1);
        assert!(said.unwrap_err().contains("does not hold a number"));
    }

    #[test]
    fn a_store_failure_is_refused_not_zero() {
        fn read_down(_name: &str) -> std::result::Result<Option<Vec<u8>>, String> {
            Err("down".into())
        }
        let said = cas_increment(read_down, |_, _| Ok(true), |_, _, _| Ok(false), "x", 1);
        assert!(said.unwrap_err().contains("down"), "a store that did not answer is never read as an empty counter");
    }
}

/// The encryption key a connector's records are sealed under, as the
/// connector's `manifest.json` declares it (`encryption_keys[].path`).
/// One namespace per connector; `bump` is the [`crate::policy::Bump`] the
/// budgets count through.
pub const RECORDS_PATH: &str = "records";

/// The [`crate::policy::Bump`] over this connector's sealed counters.
pub fn bump(name: &str, delta: i64) -> std::result::Result<i64, String> {
    increment(RECORDS_PATH, name, delta).map_err(|e| e.to_string())
}
