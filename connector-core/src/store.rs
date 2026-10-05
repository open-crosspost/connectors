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

/// Add `delta` to counter `name` and answer the new value, atomically: a
/// compare-and-set on the sealed record, retried while another call changed
/// it first. A missing counter starts at zero; `delta` 0 reads it.
pub fn increment(path: &str, name: &str, delta: i64) -> Result<i64> {
    for _ in 0..INCREMENT_ATTEMPTS {
        match sealed::get(path, None, name)? {
            None => {
                if delta == 0 {
                    return Ok(0);
                }
                if sealed::set_if_absent(path, None, name, delta.to_string().as_bytes())? {
                    return Ok(delta);
                }
            }
            Some(current) => {
                let now: i64 = std::str::from_utf8(current.plaintext())
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| StorageError(format!("counter {name} does not hold a number")))?;
                if delta == 0 {
                    return Ok(now);
                }
                let next = now + delta;
                let (written, _) = sealed::set_if_equals(path, None, name, &current, next.to_string().as_bytes())?;
                if written {
                    return Ok(next);
                }
            }
        }
    }
    Err(StorageError(format!(
        "counter {name} kept changing under concurrent calls ({INCREMENT_ATTEMPTS} attempts)"
    )))
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
