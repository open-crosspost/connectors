//! The access token, from the refresh token the owner stored.
//!
//! X's refresh token ROTATES: every refresh voids the token it used and
//! issues a new one. The owner's secrets row can never keep up — it holds
//! the token from the day they connected, and the connector cannot write to
//! a row stored under the owner's account. So the newest refresh token
//! lives in the project's own sealed storage, keyed to the credential it
//! was minted from, and the row's token is the seed of that lineage. The
//! owner replacing their row changes the key, and the old lineage is
//! orphaned — the same safety the access-token cache relies on.
//!
//! What this costs is stated plainly in the refusal for a token request
//! whose outcome is unknown: if the request landed, the token it used is
//! already void and a live one was issued to nobody. The access-token cache
//! (X's tokens live about two hours) is what keeps refreshes rare, which is
//! the honest mitigation: a connector that refreshed on every call would
//! destroy its credential on the first lost packet.

use crate::runtime::{Method, RecordStore, Secrets, Transport};
use connector_core::oauth::{self, Credential, Names};
use serde_json::Value;

pub const TOKEN_URL: &str = "https://api.twitter.com/2/oauth2/token";

/// An owner's own OAuth app, when they brought one: THEIRS wins.
pub const CLIENT_ID_ENV: &str = "X_CLIENT_ID";
pub const CLIENT_SECRET_ENV: &str = "X_CLIENT_SECRET";
/// The owner's credential, from the row the call names.
pub const REFRESH_TOKEN_ENV: &str = "X_REFRESH_TOKEN";
/// The owner's policy, beside the credential in the same row.
pub const POLICY_ENV: &str = "X_POLICY";

/// The connector author's own OAuth client — stored by the publishing
/// account under the manifest's `author_secrets.profile`. Deliberately NOT
/// the names above: a key defined by both the author and the caller refuses
/// the run, and a user who brought their own client must keep working.
pub const OUR_CLIENT_ID_ENV: &str = "X_OAUTH_CLIENT_ID";
pub const OUR_CLIENT_SECRET_ENV: &str = "X_OAUTH_CLIENT_SECRET";

/// Where the owner connects an account and stores its credential and
/// policy. (The connect handoff is ticket #18; the URL is the canonical one
/// the refusals have pointed at since day one.)
pub const CONNECT_PAGE: &str = "https://app.outlayer.ai/connect/x";

/// The names the credential's values arrive under, as [`core`] reads them.
pub const NAMES: Names = Names {
    client_id: CLIENT_ID_ENV,
    client_secret: CLIENT_SECRET_ENV,
    refresh_token: REFRESH_TOKEN_ENV,
    our_client_id: OUR_CLIENT_ID_ENV,
    our_client_secret: OUR_CLIENT_SECRET_ENV,
};

/// What a refresh granted: the access token, what it may do, and — because
/// X rotates — the refresh token to carry forward, if X issued one.
#[derive(Debug, Clone, PartialEq)]
pub struct Granted {
    pub access_token: String,
    pub scope: String,
    /// The refresh token X issued on this refresh. `None` when the token
    /// came from the cache (no request was made).
    pub rotated_to: Option<String>,
    /// Seconds X says this access token is good for.
    pub expires_in: u64,
}

impl Granted {
    /// Does the grant carry `scope`? X spells scopes space-separated.
    pub fn grants(&self, scope: &str) -> bool {
        self.scope.split_whitespace().any(|s| s == scope)
    }
}

/// Where a credential's records live: keyed by a digest of the credential
/// the row holds, so a replaced credential never inherits an old lineage.
fn lineage(credential: &Credential) -> String {
    oauth::cache_key(credential, "x")
}

/// The newest refresh token of a credential's lineage, or the row's own.
fn current_refresh(store: &dyn RecordStore, credential: &Credential) -> String {
    store
        .get(&format!("{}:refresh", lineage(credential)))
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| credential.refresh_token.clone())
}

/// The cached grant, if it is still good at `now_secs`.
fn cached_grant(store: &dyn RecordStore, credential: &Credential, now_secs: u64) -> Option<Granted> {
    let bytes = store.get(&format!("{}:grant", lineage(credential)))?;
    let record: CachedGrant = serde_json::from_slice(&bytes).ok()?;
    (record.good_until > now_secs).then(|| Granted {
        access_token: record.access_token,
        scope: record.scope,
        rotated_to: None,
        expires_in: record.expires_in,
    })
}

/// The grant as it is cached. X's answer carries the scope it granted, and
/// the checks a post and a `me` make depend on it — so the scope rides in
/// the cache beside the token.
#[derive(serde::Serialize, serde::Deserialize)]
struct CachedGrant {
    access_token: String,
    scope: String,
    expires_in: u64,
    good_until: u64,
}

fn cache_grant(store: &dyn RecordStore, credential: &Credential, granted: &Granted, now_secs: u64) {
    let record = CachedGrant {
        access_token: granted.access_token.clone(),
        scope: granted.scope.clone(),
        expires_in: granted.expires_in,
        good_until: now_secs + granted.expires_in.max(oauth::SAFETY_MARGIN_SECS + 60)
            - oauth::SAFETY_MARGIN_SECS,
    };
    if let Ok(bytes) = serde_json::to_vec(&record) {
        store.set(&format!("{}:grant", lineage(credential)), &bytes);
    }
}

/// The credential this run sends with, reading the run's environment.
pub fn credential() -> Result<Credential, String> {
    Credential::from_env(&NAMES, CONNECT_PAGE)
}

/// A usable grant: the cached one while it lasts, a fresh one otherwise —
/// and, on a fresh one, X's rotation carried into the lineage's record.
///
/// Values are noted for the redaction sweep as they are seen: the cached or
/// minted access token, and a rotated refresh token.
pub fn access_token(
    transport: &dyn Transport,
    store: &dyn RecordStore,
    credential: &Credential,
    now_secs: u64,
    secrets: &mut Secrets,
) -> Result<Granted, String> {
    if let Some(granted) = cached_grant(store, credential, now_secs) {
        secrets.note("access token", &granted.access_token);
        return Ok(granted);
    }
    let granted = refresh(transport, credential, current_refresh(store, credential))?;
    if let Some(next) = &granted.rotated_to {
        store.set(&format!("{}:refresh", lineage(credential)), next.as_bytes());
        secrets.note("refresh token", next);
    }
    cache_grant(store, credential, &granted, now_secs);
    secrets.note("access token", &granted.access_token);
    Ok(granted)
}

/// One refresh request, answered as what it was: the token and its scope,
/// the credential being dead, the client being wrong, or an outcome that
/// may have voided the credential. Never retried here — X's rotation makes
/// a second blind refresh dangerous.
fn refresh(transport: &dyn Transport, credential: &Credential, current: String) -> Result<Granted, String> {
    // X authenticates a confidential client over HTTP Basic; the values are
    // form-encoded first, because a client secret is not ours to assume
    // anything about.
    let basic = {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        BASE64.encode(format!(
            "{}:{}",
            oauth::form(&credential.client_id),
            oauth::form(&credential.client_secret)
        ))
    };
    let body = format!(
        "grant_type=refresh_token&refresh_token={}",
        oauth::form(&current)
    );
    let response = transport
        .send(
            Method::Post,
            TOKEN_URL,
            &[
                ("Content-Type", "application/x-www-form-urlencoded".to_string()),
                ("Authorization", format!("Basic {basic}")),
            ],
            Some(body.as_bytes()),
        )
        .map_err(|e| {
            // The request went out, or may have — and with rotation, a
            // landed-but-lost refresh has voided the token it used.
            format!(
                "X's token endpoint could not be reached: {e}. The refresh request went out, or may \
                 have; X rotates refresh tokens, so if the credential stops answering, the owner \
                 reconnects the account at {CONNECT_PAGE}"
            )
        })?;
    let value = response.json();

    if response.status != 200 {
        let code = value.get("error").and_then(Value::as_str).unwrap_or("");
        let described = value
            .get("error_description")
            .and_then(Value::as_str)
            .unwrap_or_else(|| if response.body.is_empty() { "no detail" } else { "" });
        if code == "invalid_grant" {
            return Err(connector_core::refusal::credential_expired("X", &smart(detail(code, described)), CONNECT_PAGE));
        }
        if code == "invalid_client" {
            return Err(connector_core::refusal::credential_rejected(
                "X",
                &format!("the OAuth client was refused (invalid_client: {}); the client id or secret this run holds is not a live X app", smart(detail(code, described))),
                CONNECT_PAGE,
            ));
        }
        return Err(format!("X refused the token request: HTTP {} {code} {}", response.status, smart(detail(code, described))));
    }

    let access_token = value
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "X's token answer carries no access_token".to_string())?
        .to_string();
    let scope = value.get("scope").and_then(Value::as_str).unwrap_or_default().to_string();
    let expires_in = value.get("expires_in").and_then(Value::as_u64).unwrap_or(7200);
    let rotated_to = value
        .get("refresh_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string);
    Ok(Granted { access_token, scope, rotated_to, expires_in })
}

/// A detail worth repeating, or the word `none`. A refusal that names no
/// detail tells the owner nothing they can act on.
fn detail(code: &str, described: &str) -> String {
    if described.trim().is_empty() {
        code.to_string()
    } else {
        described.to_string()
    }
}

fn smart(detail: String) -> String {
    detail.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{testing::MockTransport, Response};
    use crate::runtime::testing::{env_lock, MemStore};
    use connector_core::refusal;

    const NOW: u64 = 1_800_000_000;

    fn row_credential() -> Credential {
        Credential { client_id: "our-id".into(), client_secret: "our-secret".into(), refresh_token: "1//row".into() }
    }

    fn secrets_env(names: &[(&'static str, &str)]) {
        for (name, value) in names {
            std::env::set_var(name, value);
        }
    }

    fn clear_env(names: &[&'static str]) {
        for name in names {
            std::env::remove_var(name);
        }
    }

    fn token_ok(access: &str, scope: &str, rotated: Option<&str>) -> Result<Response, String> {
        let mut body = serde_json::json!({
            "token_type": "bearer", "expires_in": 7200, "access_token": access, "scope": scope
        });
        if let Some(r) = rotated {
            body["refresh_token"] = serde_json::json!(r);
        }
        Ok(Response { status: 200, body: serde_json::to_vec(&body).unwrap() })
    }

    /// Every response the run sweeps must not echo — the access token and
    /// the rotated refresh token land in the sweep list as they are minted.
    #[test]
    fn the_first_refresh_uses_the_rows_token_and_carries_the_rotation() {
        let credential = row_credential();
        let transport = MockTransport::with(vec![token_ok("AT1", "tweet.write users.read", Some("1//new"))]);
        let store = MemStore::default();
        let mut secrets = Secrets::default();

        let granted = access_token(&transport, &store, &credential, NOW, &mut secrets).unwrap();
        assert_eq!(granted.access_token, "AT1");
        assert_eq!(granted.rotated_to.as_deref(), Some("1//new"));
        assert!(granted.grants("tweet.write") && !granted.grants("tweet.delete"), "scopes parse");

        // The rotation is recorded in the lineage, the row's token is not
        // overwritten anywhere, and the secrets are noted for the sweep.
        assert_eq!(store.get(&format!("{}:refresh", lineage(&credential))).as_deref(), Some(b"1//new".as_slice()));
        let noted: Vec<&str> = secrets.list().iter().map(|(k, _)| *k).collect();
        assert_eq!(noted, ["refresh token", "access token"], "{:?}", secrets.list());
        let (kind, value) = &secrets.list()[0];
        assert_eq!((kind, value.as_str()), (&"refresh token", "1//new"));

        // A second call within the token's life uses the cache: no more
        // requests, no second rotation.
        let second = access_token(&transport, &store, &credential, NOW + 60, &mut secrets).unwrap();
        assert_eq!(second.access_token, "AT1", "the cached grant is used while it lasts");
        assert_eq!(second.rotated_to, None, "a cached grant carried no request");
        assert_eq!(transport.seen.borrow().len(), 1);
    }

    /// The cache is keyed to the credential: a replaced row never inherits
    /// the previous credential's grant, and a replaced credential does not
    /// read the old lineage's rotation.
    #[test]
    fn a_replaced_credential_starts_fresh() {
        let old = row_credential();
        let transport = MockTransport::with(vec![token_ok("AT-old", "tweet.write", Some("1//new"))]);
        let store = MemStore::default();
        let mut secrets = Secrets::default();
        access_token(&transport, &store, &old, NOW, &mut secrets).unwrap();

        let new = Credential { refresh_token: "1//row2".into(), ..old.clone() };
        let fresh_transport = MockTransport::with(vec![token_ok("AT-new", "tweet.write", None)]);
        let mut secrets2 = Secrets::default();
        let granted = access_token(&fresh_transport, &store, &new, NOW, &mut secrets2).unwrap();
        assert_eq!(granted.access_token, "AT-new", "a new credential never uses the old one's cache");
        assert_eq!(granted.rotated_to, None);
        assert_eq!(fresh_transport.seen.borrow()[0].2, *b"grant_type=refresh_token&refresh_token=1%2F%2Frow2",
            "the refresh request carries the NEW row's token, form-encoded");
    }

    #[test]
    fn the_newest_refresh_token_of_a_lineage_is_used_not_the_rows() {
        let credential = row_credential();
        let store = MemStore::default();
        let mut secrets = Secrets::default();

        // A lineage that already rotated: the stored "1//new" is the live
        // token; the row's "1//row" is void.
        store.set(&format!("{}:refresh", lineage(&credential)), b"1//new");
        let transport = MockTransport::with(vec![token_ok("AT2", "tweet.write", Some("1//newer"))]);
        access_token(&transport, &store, &credential, NOW, &mut secrets).unwrap();
        let (method, _, body) = &transport.seen.borrow()[0];
        assert_eq!((method, body.as_slice()), (&Method::Post, b"grant_type=refresh_token&refresh_token=1%2F%2Fnew".as_slice()));
        // And the rotation carried forward.
        assert_eq!(store.get(&format!("{}:refresh", lineage(&credential))).as_deref(), Some(b"1//newer".as_slice()));
    }

    #[test]
    fn a_dead_refresh_token_is_said_to_be_dead_not_broken() {
        let credential = row_credential();
        let store = MemStore::default();
        let mut secrets = Secrets::default();
        let transport = MockTransport::with(vec![Ok(Response {
            status: 400,
            body: serde_json::to_vec(&serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Token expired"
            })).unwrap(),
        })]);
        let said = access_token(&transport, &store, &credential, NOW, &mut secrets).unwrap_err();
        assert!(said.starts_with("credential_expired: "), "{said}");
        assert!(said.contains("Token expired") && said.contains(CONNECT_PAGE), "{said}");
        assert!(said.contains("retrying will not help"), "{said}");
    }

    /// An invalid CLIENT is a different death from a dead token: the row
    /// may be perfectly good and the client wrong.
    #[test]
    fn a_refused_client_is_named_as_such() {
        let credential = row_credential();
        let store = MemStore::default();
        let mut secrets = Secrets::default();
        let transport = MockTransport::with(vec![Ok(Response {
            status: 401,
            body: serde_json::to_vec(&serde_json::json!({
                "error": "invalid_client",
                "error_description": "Invalid client_id"
            })).unwrap(),
        })]);
        let said = access_token(&transport, &store, &credential, NOW, &mut secrets).unwrap_err();
        assert!(said.starts_with("credential_rejected: "), "{said}");
        assert!(said.contains("invalid_client"), "{said}");
    }

    /// A lost token request may have voided the credential (rotation): the
    /// refusal says so, and it is not the same as a refusal from X.
    #[test]
    fn a_lost_token_request_is_not_retried_and_warns_of_the_rotation() {
        let credential = row_credential();
        let store = MemStore::default();
        let mut secrets = Secrets::default();
        let transport = MockTransport::with(vec![MockTransport::network("connection reset")]);
        let said = access_token(&transport, &store, &credential, NOW, &mut secrets).unwrap_err();
        assert!(said.contains("went out, or may have"), "{said}");
        assert!(said.contains("rotates"), "{said}");
        assert!(said.contains(CONNECT_PAGE), "{said}");
        // No rotation was recorded, no cache was written: a next call tries
        // the row's token again.
        assert!(store.get(&format!("{}:refresh", lineage(&credential))).is_none());
        assert!(store.get(&format!("{}:grant", lineage(&credential))).is_none());
        assert_eq!(transport.seen.borrow().len(), 1, "never retried here");
    }

    /// The env names an author who stores their client under, spelled in
    /// one place: the refusals name them from here on.
    #[test]
    fn the_env_names_are_the_ones_the_documentation_spells() {
        assert_eq!(CLIENT_ID_ENV, "X_CLIENT_ID");
        assert_eq!(CLIENT_SECRET_ENV, "X_CLIENT_SECRET");
        assert_eq!(REFRESH_TOKEN_ENV, "X_REFRESH_TOKEN");
        assert_eq!(OUR_CLIENT_ID_ENV, "X_OAUTH_CLIENT_ID");
        assert_eq!(OUR_CLIENT_SECRET_ENV, "X_OAUTH_CLIENT_SECRET");
        assert_eq!(POLICY_ENV, "X_POLICY");
        let _ = secrets_env(&[]);
        let _ = clear_env(&[]);
        assert!(refusal::is_terminal(&refusal::scope_missing("tweet.write", "X")));
    }

    /// The dual credential: an owner's own client wins over ours, and a
    /// refresh token with no client anywhere is refused with both ways out.
    #[test]
    fn the_dual_model_resolves_before_any_request_is_made() {
        let _lock = env_lock();
        let env = [
            REFRESH_TOKEN_ENV, CLIENT_ID_ENV, CLIENT_SECRET_ENV, OUR_CLIENT_ID_ENV, OUR_CLIENT_SECRET_ENV,
        ];
        clear_env(&env);
        secrets_env(&[
            (REFRESH_TOKEN_ENV, "1//r"),
            (CLIENT_ID_ENV, "own-id"),
            (CLIENT_SECRET_ENV, "own-secret"),
            (OUR_CLIENT_ID_ENV, "our-id"),
            (OUR_CLIENT_SECRET_ENV, "our-secret"),
        ]);
        let c = credential().unwrap();
        assert_eq!((c.client_id.as_str(), c.refresh_token.as_str()), ("own-id", "1//r"), "the owner's own client wins");
        clear_env(&[CLIENT_ID_ENV, CLIENT_SECRET_ENV]);
        let c = credential().unwrap();
        assert_eq!(c.client_id, "our-id", "connected through the page: ours completes it");
        clear_env(&env);
    }
}
