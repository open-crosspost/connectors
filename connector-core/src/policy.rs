//! The owner's policy: how a secrets row's policy is loaded, judged and
//! counted against — the machinery every connector in the family shares.
//!
//! The policy struct itself is the connector's (its fields are the
//! connector's business); this module carries what does not change between
//! connectors:
//!
//! * **Fail-closed loading.** No policy means nothing is done. A policy this
//!   build cannot read refuses too — an unknown field is a parse error, not
//!   something to ignore, because the field somebody added is probably the
//!   restriction they cared about. (The connector's struct says
//!   `deny_unknown_fields`; this module only ever reports what it loaded.)
//! * **UTC-day counting.** Every cap is counted per calling wallet in UTC
//!   days, in the run's own project storage — atomically, so two calls at
//!   once cannot both see room for the last one.
//! * **The reservation.** A place in the day's budget is taken BEFORE the
//!   work happens and given back when it does not happen: any early return
//!   between reserving and a done thing — a refused token, a service saying
//!   no — releases it. Only the thing that actually happened is counted.
//!   An outcome that is *unknown* (the request went out, the answer was
//!   lost) keeps its place: a count one too high refuses a thing, one too
//!   low allows one.

use serde::de::DeserializeOwned;

/// The env var the owner's policy arrives in, named per connector by the
/// connector itself.
pub type PolicyEnv = &'static str;

/// A policy as it was loaded from the owner's secrets row.
#[derive(Debug)]
pub enum Loaded<T> {
    /// The row carries no policy at all: fail-closed.
    None,
    /// The row carries a policy this build cannot read: fail-closed, with
    /// the sentence that says so.
    Unreadable(String),
    Some(T),
}

/// Read the owner's policy out of the run's environment. `describe` is what
/// an `Unreadable` refusal says; it names the field that failed to parse.
pub fn load<T: DeserializeOwned>(env: PolicyEnv) -> Loaded<T> {
    match std::env::var(env) {
        Err(_) => Loaded::None,
        Ok(raw) if raw.trim().is_empty() => Loaded::None,
        Ok(raw) => match serde_json::from_str::<T>(&raw) {
            Ok(policy) => Loaded::Some(policy),
            Err(e) => Loaded::Unreadable(format!("{env} could not be read ({e})")),
        },
    }
}

/// The policy a doing-thing needs, or the refusal to answer with. The
/// sentence says who fixes it: the OWNER of the row, at the connect page.
pub fn required<T>(loaded: Loaded<T>, env: PolicyEnv, connect_url: &str) -> Result<T, String> {
    match loaded {
        Loaded::Some(policy) => Ok(policy),
        Loaded::Unreadable(e) => Err(format!(
            "policy_denied: {e}. Until the owner of the secrets row stores one that can be read, \
             at {connect_url}, nothing is done"
        )),
        Loaded::None => Err(format!(
            "policy_denied: the secrets row this call names holds no {env}, so nothing is done. \
             The OWNER of the row stores the policy beside the credential, at {connect_url} — a \
             JSON object naming what their agent may do — and admits an agent by naming its \
             account in the row's access condition"
        )),
    }
}

// ==================== the clock and the day ====================

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub fn now_secs() -> u64 {
    now_ms() / 1000
}

/// `YYYY-MM-DD` in UTC for a millisecond timestamp — the day every
/// windowed count turns over at.
pub fn day_key(ms: u64) -> String {
    let days = (ms / 86_400_000) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

// ==================== the day's count ====================

/// Which count a thing is taken from.
///
/// Every count is a record in the storage cell of the account that makes the
/// run. A thing the caller does itself and one the owner confirmed for it
/// are two counts — the run that confirms is the caller's own too — and the
/// cap bounds each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Counted {
    /// A thing the caller does itself: one count a day.
    Own,
    /// A thing the owner confirmed, done by the run started for it: one
    /// count a day, beside the caller's own.
    Confirmed,
}

/// The counter key for `counted` on `day`, under `prefix` (the connector's
/// own namespace, e.g. `gm`, `x`).
pub fn count_key(prefix: &str, day: &str, counted: Counted) -> String {
    match counted {
        Counted::Own => format!("{prefix}:count:{day}"),
        Counted::Confirmed => format!("{prefix}:count:{day}:confirmed"),
    }
}

/// How a day's count is changed: the storage primitive in a run, a stand-in
/// in the tests. A closure, so a reservation can carry it into `Drop` (and
/// a run can count through its own store — [`crate::store`] for the real
/// one, which is a sealed compare-and-swap; never read a counter and then
/// write it back: two calls of one agent can run at once, and a
/// read-then-write lets both see room for one more).
pub type Bump<'a> = Box<dyn Fn(&str, i64) -> Result<i64, String> + 'a>;

/// The caller's own things counted today, including any a call in flight has
/// reserved.
pub fn sent_today(bump: impl Fn(&str, i64) -> Result<i64, String>, key: &str) -> Result<u32, String> {
    let count = bump(key, 0).map_err(|e| format!("the day's count could not be read: {e}"))?;
    Ok(count.max(0) as u32)
}

/// One thing's place in today's budget, taken BEFORE it happens.
///
/// The reservation is released when it is dropped without being kept, so
/// every early return between here and the done thing gives the place back,
/// and the owner's budget is spent only by things that happened. An outcome
/// that is unknown is KEPT: see the module comment.
pub struct Reservation<'a> {
    key: String,
    kept: bool,
    bump: Bump<'a>,
}

impl Reservation<'_> {
    /// The thing happened: the place stays taken.
    pub fn keep(mut self) {
        self.kept = true;
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if !self.kept {
            // A release that fails leaves the count one too high, which
            // refuses a thing rather than allowing one: the safe direction.
            let _ = (self.bump)(&self.key, -1);
        }
    }
}

/// Take a place in today's budget of `counted`, or refuse with the owner's
/// word if the cap is full. Returns the count including this one.
pub fn reserve<'a>(
    bump: impl Fn(&str, i64) -> Result<i64, String> + 'a,
    key: String,
    cap: u32,
) -> Result<(Reservation<'a>, u32), String> {
    let after = bump(&key, 1).map_err(|e| format!("the day's count could not be updated: {e}"))?;
    let reservation = Reservation { key, kept: false, bump: Box::new(bump) };
    if after > cap as i64 {
        // Dropping it gives the place back.
        drop(reservation);
        return Err(format!(
            "policy_denied: {} of the owner's {cap} a day are used; this one would pass it",
            after - 1
        ));
    }
    Ok((reservation, after as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_day_key_is_utc_and_changes_at_midnight() {
        assert_eq!(day_key(0), "1970-01-01");
        assert_eq!(day_key(86_400_000 - 1), "1970-01-01");
        assert_eq!(day_key(86_400_000), "1970-01-02");
        assert_eq!(day_key(1_757_600_000_000), "2025-09-11");
    }

    #[test]
    fn each_count_has_a_record_of_its_own() {
        assert_eq!(count_key("x", "2026-09-30", Counted::Own), "x:count:2026-09-30");
        assert_eq!(count_key("x", "2026-09-30", Counted::Confirmed), "x:count:2026-09-30:confirmed");
        assert_ne!(count_key("x", "d", Counted::Confirmed), count_key("x", "d", Counted::Own));
        // Another connector's counts never meet this one's.
        assert_ne!(count_key("gm", "d", Counted::Own), count_key("x", "d", Counted::Own));
    }

    #[derive(serde::Deserialize)]
    #[derive(Debug)]
    #[serde(deny_unknown_fields)]
    struct TestPolicy {
        max_per_day: Option<u32>,
    }

    /// A policy this build does not know is a parse error, not a quieter
    /// policy: the field somebody added is probably the restriction they
    /// cared about.
    #[test]
    fn an_unknown_field_refuses_to_parse() {
        assert!(serde_json::from_str::<TestPolicy>(r#"{"max_per_day":5,"allow_delete":true}"#).is_err());
        assert!(serde_json::from_str::<TestPolicy>(r#"{"max_per_day":5}"#).is_ok());
    }

    #[test]
    fn a_refusal_for_want_of_a_policy_tells_the_owner_what_to_store() {
        let none = required::<TestPolicy>(Loaded::None, "X_POLICY", "https://c.test/x").unwrap_err();
        assert!(none.starts_with("policy_denied: the secrets row this call names holds no X_POLICY"), "{none}");
        assert!(none.contains("https://c.test/x") && none.contains("access condition"), "{none}");
        let unread = required::<TestPolicy>(
            Loaded::Unreadable("X_POLICY could not be read (x)".into()),
            "X_POLICY",
            "https://c.test/x",
        )
        .unwrap_err();
        assert!(unread.starts_with("policy_denied: X_POLICY could not be read"), "{unread}");
    }

    // ===== the reservation, against a stand-in for the atomic counter =====
    //
    // The platform's increment is a compare-and-swap on a sealed record. The
    // stand-in is a mutex-guarded map: atomic in the same sense, so what
    // these tests show is that the reservation logic on top of an atomic
    // counter never lets more through than the cap, and gives back what it
    // does not use.

    use std::collections::HashMap;
    use std::sync::Mutex;

    static COUNTERS: Mutex<Option<HashMap<String, i64>>> = Mutex::new(None);

    fn test_bump(key: &str, delta: i64) -> Result<i64, String> {
        let mut guard = COUNTERS.lock().unwrap();
        let map = guard.get_or_insert_with(HashMap::new);
        let value = map.entry(key.to_string()).or_insert(0);
        *value += delta;
        Ok(*value)
    }

    fn count(key: &str) -> i64 {
        test_bump(key, 0).unwrap()
    }

    #[test]
    fn a_stored_policy_loads_and_an_empty_one_is_none() {
        std::env::set_var("X_POLICY_TEST_OK", r#"{"max_per_day":3}"#);
        let good = load::<TestPolicy>("X_POLICY_TEST_OK");
        std::env::remove_var("X_POLICY_TEST_OK");
        assert!(required(good, "X_POLICY_TEST_OK", "u").is_ok());
        std::env::set_var("X_POLICY_TEST_EMPTY", "  ");
        let empty = load::<TestPolicy>("X_POLICY_TEST_EMPTY");
        std::env::remove_var("X_POLICY_TEST_EMPTY");
        assert!(matches!(empty, Loaded::None), "whitespace is no policy: {empty:?}");
    }

    #[test]
    fn the_cap_admits_exactly_its_number_and_a_refusal_takes_nothing() {
        let key = count_key("test1", "2026-01-01", Counted::Own);
        let mut kept = Vec::new();
        for n in 1..=3 {
            let (reservation, after) = reserve(test_bump, key.clone(), 3).unwrap();
            assert_eq!(after, n);
            kept.push(reservation);
        }
        let err = reserve(test_bump, key.clone(), 3).err().expect("the fourth is refused");
        assert!(err.contains("3 of the owner's 3"), "{err}");
        assert_eq!(count(&key), 3, "the refused one gave its place back");
        for reservation in kept {
            reservation.keep();
        }
        assert_eq!(count(&key), 3);
    }

    #[test]
    fn a_reservation_dropped_unkept_gives_its_place_back() {
        let key = count_key("test2", "2026-01-01", Counted::Own);
        {
            let (_reservation, after) = reserve(test_bump, key.clone(), 10).unwrap();
            assert_eq!(after, 1);
            // Dropped here, as it is on any early return before the work.
        }
        assert_eq!(count(&key), 0);
        let (reservation, _) = reserve(test_bump, key.clone(), 10).unwrap();
        reservation.keep();
        assert_eq!(count(&key), 1, "a kept one stays");
    }

    #[test]
    fn a_confirmed_thing_is_counted_beside_the_callers_own_and_each_count_is_bounded() {
        let day = "2026-01-01";
        let own = count_key("test3", day, Counted::Own);
        let confirmed = count_key("test3", day, Counted::Confirmed);
        for n in 1..=2 {
            let (reservation, after) = reserve(test_bump, confirmed.clone(), 2).unwrap();
            assert_eq!(after, n);
            reservation.keep();
        }
        let err = reserve(test_bump, confirmed.clone(), 2).err().expect("the third is refused");
        assert!(err.starts_with("policy_denied: 2 of the owner's 2"), "{err}");
        let (reservation, after) = reserve(test_bump, own.clone(), 2).unwrap();
        assert_eq!(after, 1, "the confirmed sends used up take nothing from the caller's own");
        drop(reservation);
        assert_eq!(count(&confirmed), 2);
        assert_eq!(count(&own), 0);
    }

    /// Many calls at once, the case read-then-write got wrong: every one of
    /// them read the same total and saw room. On an atomic counter exactly
    /// the cap gets through, however the threads interleave.
    #[test]
    fn parallel_callers_never_pass_the_cap() {
        let key = count_key("test4", "2026-01-01", Counted::Own);
        let handles: Vec<_> = (0..48)
            .map(|_| {
                let key = key.clone();
                std::thread::spawn(move || match reserve(test_bump, key, 5) {
                    Ok((reservation, _)) => {
                        reservation.keep();
                        true
                    }
                    Err(_) => false,
                })
            })
            .collect();
        let admitted = handles.into_iter().map(|h| h.join().unwrap()).filter(|ok| *ok).count();
        assert_eq!(admitted, 5);
        assert_eq!(count(&key), 5);
    }

    #[test]
    fn sent_today_never_reads_negative() {
        let key = count_key("test5", "2026-01-01", Counted::Own);
        test_bump(&key, -3).unwrap();
        assert_eq!(sent_today(test_bump, &key).unwrap(), 0);
    }
}
