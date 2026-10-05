//! The dual OAuth credential: whose client completes the owner's refresh
//! token.
//!
//! An account connected through the platform's connect page stores only a
//! refresh token, and the connector AUTHOR's own OAuth client — an author
//! secret — completes it at run time. An owner who brings their own OAuth
//! app stores their client beside the refresh token, and *theirs wins*:
//! nothing of ours enters their run.
//!
//! The author's client is stored under DIFFERENT names than an owner's own
//! client, deliberately: a key defined by both the author and the caller
//! refuses the run, and a user who brought their own client must keep
//! working.
//!
//! The access token is cached in the project's sealed storage until shortly
//! before it expires — storage is scoped by the platform to this connector
//! and this paying account, so one caller's token is not another's. The
//! cache is keyed by a digest of the credential it was minted from, so a
//! token minted from one credential is never used after the owner replaced
//! it with another.
//!
//! This module never speaks HTTP: the refresh request differs per service
//! and stays in the connector. What it carries is the credential resolution,
//! the cache, and the form-encoding a credential needs before it can travel.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The names the credential's values arrive under. `client_*` are an OWNER's
/// own client; `our_client_*` are the AUTHOR's, held as author secrets.
pub struct Names {
    /// e.g. `X_CLIENT_ID`
    pub client_id: &'static str,
    /// e.g. `X_CLIENT_SECRET`
    pub client_secret: &'static str,
    /// e.g. `X_REFRESH_TOKEN`
    pub refresh_token: &'static str,
    /// e.g. `X_OAUTH_CLIENT_ID` — the author's client, from the manifest's
    /// `author_secrets.profile` row.
    pub our_client_id: &'static str,
    /// e.g. `X_OAUTH_CLIENT_SECRET`
    pub our_client_secret: &'static str,
}

/// The credential this run sends with.
#[derive(Debug, Clone, PartialEq)]
pub struct Credential {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
}

fn read(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

impl Credential {
    /// The credential this run sends with, or the refusal that says what is
    /// missing and who stores it.
    ///
    /// Two shapes, and the caller's OWN client wins. Someone who brought
    /// their own OAuth app keeps using it and nothing of ours enters their
    /// run. An account connected through the connect page stores only a
    /// refresh token, and our client — the author secret — completes it.
    pub fn from_env(names: &Names, connect_url: &str) -> Result<Self, String> {
        let refresh_token = read(names.refresh_token).ok_or_else(|| {
            crate::refusal::no_credential(names.refresh_token, (names.client_id, names.client_secret), connect_url)
        })?;
        if let (Some(client_id), Some(client_secret)) = (read(names.client_id), read(names.client_secret)) {
            return Ok(Self { client_id, client_secret, refresh_token });
        }
        match (read(names.our_client_id), read(names.our_client_secret)) {
            (Some(client_id), Some(client_secret)) => Ok(Self { client_id, client_secret, refresh_token }),
            _ => Err(crate::refusal::no_client(names.refresh_token, (names.client_id, names.client_secret), connect_url)),
        }
    }

    /// Whether the author's client reached this run (for `status`, which
    /// reports what a run would use).
    pub fn has_own_client(names: &Names) -> bool {
        read(names.client_id).is_some() && read(names.client_secret).is_some()
    }
}

/// Where a credential's access token is cached, in the project's sealed
/// storage: a digest of the credential itself, so a token minted from one
/// credential is never used after the owner replaced it with another — a
/// cache that outlived its credential would keep acting from the previous
/// account. The key carries the digest, never the token.
pub fn cache_key(credential: &Credential, prefix: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(credential.client_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(credential.refresh_token.as_bytes());
    let digest = hasher.finalize();
    let short: String = digest.iter().take(12).map(|b| format!("{b:02x}")).collect();
    format!("{prefix}:token:{short}")
}

/// The cached token as it is stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cached {
    pub access_token: String,
    /// Unix seconds at which this token stops being used here.
    pub good_until: u64,
}

/// Refreshed this long before the service's own expiry, so a token cannot
/// die between the check and the call that uses it.
pub const SAFETY_MARGIN_SECS: u64 = 120;

/// The cached token, if it is still good at `now_secs`.
pub fn cached(bytes: Option<Vec<u8>>, now_secs: u64) -> Option<String> {
    let record: Cached = serde_json::from_slice(&bytes?).ok()?;
    (record.good_until > now_secs).then_some(record.access_token)
}

/// The record to store for a freshly minted token, `expires_in` seconds
/// long by the service's word. A life shorter than the margin would mean
/// never caching anything, so it is floored.
pub fn fresh(access_token: String, expires_in: u64, now_secs: u64) -> Cached {
    Cached {
        access_token,
        good_until: now_secs + expires_in.max(SAFETY_MARGIN_SECS + 60).saturating_sub(SAFETY_MARGIN_SECS),
    }
}

/// Percent-encode a form value. The credential is not ours to assume
/// anything about, and an unescaped `&` in a secret would silently send a
/// different request.
pub fn form(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> Names {
        Names {
            client_id: "T_CLIENT_ID",
            client_secret: "T_CLIENT_SECRET",
            refresh_token: "T_REFRESH_TOKEN",
            our_client_id: "T_OUR_CLIENT_ID",
            our_client_secret: "T_OUR_CLIENT_SECRET",
        }
    }

    /// Environment variables are process-global, and tests of the dual
    /// model run in parallel: every test works on names unique to itself
    /// and saves/restores whatever was there, so a test cannot leave a
    /// value for another to find.
    struct Env {
        set: Vec<&'static str>,
    }

    impl Env {
        fn set(names: &[&'static str], values: &[&str]) -> Self {
            let mut set = Vec::new();
            for (name, value) in names.iter().zip(values.iter()) {
                std::env::set_var(name, value);
                set.push(*name);
            }
            Env { set }
        }
    }

    impl Drop for Env {
        fn drop(&mut self) {
            for name in &self.set {
                std::env::remove_var(name);
            }
        }
    }

    #[test]
    fn an_own_client_wins_and_only_a_refresh_token_still_finds_ours() {
        let n = names();
        let url = "https://c.test/x";

        // Nothing at all: the refusal names what to connect and where.
        let e = Credential::from_env(&n, url).unwrap_err();
        assert!(e.contains("no credential reached this run") && e.contains("T_REFRESH_TOKEN"), "{e}");

        // A refresh token with no client anywhere: the refusal names both
        // ways to fix it — the owner's own client names, and the connect page.
        let _e = Env::set(&["T_REFRESH_TOKEN"], &["1//r"]);
        let e = Credential::from_env(&n, url).unwrap_err();
        assert!(e.contains("no OAuth client to use it with"), "{e}");
        assert!(e.contains("T_CLIENT_ID") && e.contains("https://c.test/x"), "{e}");

        // Connected through the page: only a refresh token, ours completes.
        let _ours = Env::set(&["T_OUR_CLIENT_ID", "T_OUR_CLIENT_SECRET"], &["our-id", "our-secret"]);
        let c = Credential::from_env(&n, url).unwrap();
        assert_eq!((c.client_id.as_str(), c.refresh_token.as_str()), ("our-id", "1//r"));

        // An owner who brought their own client: THEIRS wins.
        let _own = Env::set(&["T_CLIENT_ID", "T_CLIENT_SECRET"], &["own-id", "own-secret"]);
        let c = Credential::from_env(&n, url).unwrap();
        assert_eq!(c.client_id, "own-id", "the owner's own client wins: nothing of ours enters their run");
        assert!(Credential::has_own_client(&n));
    }

    #[test]
    fn each_credential_has_its_own_cache_entry_and_none_carries_the_token() {
        let a = Credential { client_id: "id".into(), client_secret: "s".into(), refresh_token: "1//one".into() };
        let b = Credential { client_id: "id".into(), client_secret: "s".into(), refresh_token: "1//two".into() };
        let c = Credential { client_id: "other".into(), client_secret: "s".into(), refresh_token: "1//one".into() };
        assert_ne!(cache_key(&a, "x"), cache_key(&b, "x"), "a new refresh token is a new entry");
        assert_ne!(cache_key(&a, "x"), cache_key(&c, "x"), "a new client is a new entry");
        assert_eq!(cache_key(&a, "x"), cache_key(&a, "x"));
        assert!(!cache_key(&a, "x").contains("one"), "the key carries a digest, never the token");
        // Two connectors' caches never meet.
        assert_ne!(cache_key(&a, "x"), cache_key(&a, "gm"));
    }

    #[test]
    fn a_cached_token_is_used_only_while_it_is_good() {
        let record = fresh("tok".into(), 3600, 1_000_000);
        let bytes = serde_json::to_vec(&record).unwrap();
        assert_eq!(cached(Some(bytes.clone()), 1_000_000).as_deref(), Some("tok"));
        assert!(cached(Some(bytes), 1_000_000 + 3600).is_none(), "an expired cache is not a token");
        assert!(cached(None, 0).is_none(), "no record, no token");
        assert!(cached(Some(b"not json".to_vec()), 0).is_none(), "a record this build cannot read is no token");
    }

    /// The stored life is floored: a service saying "0 seconds" must never
    /// store a token that is dead on arrival, and the safety margin is
    /// already taken out of a real answer.
    #[test]
    fn a_fresh_token_never_outlives_its_service_answer_by_the_margin() {
        let at = 1_000_000u64;
        assert_eq!(fresh("t".into(), 3600, at).good_until, at + 3600 - 120);
        assert_eq!(fresh("t".into(), 120, at).good_until, at + 60, "floored to the margin plus a minute");
        assert_eq!(fresh("t".into(), 0, at).good_until, at + 60);
    }

    #[test]
    fn a_form_value_survives_every_byte_a_secret_may_hold() {
        assert_eq!(form("abcXYZ019-_.~"), "abcXYZ019-_.~");
        assert_eq!(form("a&b=c d"), "a%26b%3Dc%20d");
        assert_eq!(form("1//04xyz"), "1%2F%2F04xyz", "OAuth refresh tokens start like this");
    }
}
