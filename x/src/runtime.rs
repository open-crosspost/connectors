//! The run's edges: how the connector reaches X, and how it keeps its
//! records.
//!
//! Two small ports, so that everything the connector does on top of them —
//! the refresh flow, the rotation, the policy, the budget — is testable
//! against mocks (`cargo test` runs native, where the host functions do not
//! exist to call):
//!
//! * [`Transport`] — one HTTPS exchange. The real one is [`WasiTransport`],
//!   over `wasi:http`, the only way out of the enclave: no sockets, and the
//!   worker admits only the hosts the manifest declares.
//! * [`RecordStore`] — the project's sealed storage. The real one is
//!   [`WasiStore`], over the platform's sealed records: the operator sees a
//!   keyed tag and a ciphertext, never a name or a value.

/// One HTTP answer, as the ports hand it around.
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    /// The body as JSON, or `Null` when it is not: a refusal's body is
    /// judged even when it is not the JSON the service documents.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

/// The method of one HTTPS exchange. GET is safe to retry; POST is what
/// every unknown-outcome question is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

pub trait Transport {
    /// One HTTPS exchange, or the network's refusal. A transport error is
    /// ALWAYS worded as "the request went out, or may have" by the callers —
    /// the port cannot know which.
    fn send(
        &self,
        method: Method,
        url: &str,
        headers: &[(&'static str, String)],
        body: Option<&[u8]>,
    ) -> Result<Response, String>;
}

/// The real transport: `wasi:http`, the only way out of the enclave.
pub struct WasiTransport;

impl Transport for WasiTransport {
    fn send(
        &self,
        method: Method,
        url: &str,
        headers: &[(&'static str, String)],
        body: Option<&[u8]>,
    ) -> Result<Response, String> {
        let builder = wasi_http_client::Client::new();
        let builder = match method {
            Method::Get => builder.get(url),
            Method::Post => builder.post(url),
        };
        let mut builder = builder;
        for (name, value) in headers {
            builder = builder.header(*name, value.as_str());
        }
        if let Some(bytes) = body {
            builder = builder.body(bytes);
        }
        let response = builder
            .connect_timeout(std::time::Duration::from_secs(20))
            .send()
            .map_err(|e| format!("{e}"))?;
        let status = response.status();
        let bytes = response.body().map_err(|e| format!("{e}"))?;
        Ok(Response { status, body: bytes })
    }
}

/// The project's sealed storage, as the connector sees it.
pub trait RecordStore {
    fn get(&self, name: &str) -> Option<Vec<u8>>;
    fn set(&self, name: &str, value: &[u8]);
    /// Set only when absent; answers whether it was set. Used for the
    /// day's first count.
    fn set_if_absent(&self, name: &str, value: &[u8]) -> bool;
    /// Compare-and-set; answers whether it was written.
    fn set_if_equals(&self, name: &str, current: &[u8], next: &[u8]) -> bool;
}

/// The real store: the platform's sealed records, under the encryption key
/// the manifest declares (`encryption_keys[].path = "records"`).
pub struct WasiStore;

impl RecordStore for WasiStore {
    fn get(&self, name: &str) -> Option<Vec<u8>> {
        connector_core::store::get(connector_core::store::RECORDS_PATH, name).ok().flatten()
    }
    fn set(&self, name: &str, value: &[u8]) {
        let _ = connector_core::store::set(connector_core::store::RECORDS_PATH, name, value);
    }
    fn set_if_absent(&self, name: &str, value: &[u8]) -> bool {
        connector_core::store::set_if_absent(connector_core::store::RECORDS_PATH, name, value)
            .unwrap_or(false)
    }
    fn set_if_equals(&self, name: &str, current: &[u8], next: &[u8]) -> bool {
        connector_core::store::set_if_equals_plaintext(
            connector_core::store::RECORDS_PATH,
            name,
            current,
            next,
        )
        .unwrap_or(false)
    }
}

/// The day's budget, counted through the store. A `Bump` over a
/// [`RecordStore`], standing in for the sealed compare-and-swap in tests.
pub fn store_bump(store: &dyn RecordStore, key: &str, delta: i64) -> Result<i64, String> {
    match store.get(key) {
        None => {
            if delta == 0 {
                return Ok(0);
            }
            if store.set_if_absent(key, delta.to_string().as_bytes()) {
                Ok(delta)
            } else {
                Err("the counter kept changing under concurrent calls".into())
            }
        }
        Some(current) => {
            let now: i64 = std::str::from_utf8(&current)
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| format!("counter {key} does not hold a number"))?;
            if delta == 0 {
                return Ok(now);
            }
            let next = now + delta;
            if store.set_if_equals(key, &current, next.to_string().as_bytes()) {
                Ok(next)
            } else {
                Err("the counter kept changing under concurrent calls".into())
            }
        }
    }
}

/// Every secret value this run has seen, to sweep the answer with before it
/// leaves. Values are noted as they are read or minted; the guard never
/// names a value in a refusal.
#[derive(Default)]
pub struct Secrets {
    values: Vec<(&'static str, String)>,
}

impl Secrets {
    pub fn note(&mut self, kind: &'static str, value: &str) {
        self.values.push((kind, value.to_string()));
    }

    pub fn list(&self) -> &[(&'static str, String)] {
        &self.values
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{HashMap, VecDeque};

    /// Environment variables are process-global and tests of the run run in
    /// parallel: every test that sets one takes this lock first.
    pub fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A canned X API: every test answers per (method, url), in the order
    /// the calls arrive, so a test can script a whole conversation.
    #[derive(Default)]
    pub struct MockTransport {
        pub answers: RefCell<VecDeque<Result<Response, String>>>,
        pub seen: RefCell<Vec<(Method, String, Vec<u8>)>>,
    }

    impl MockTransport {
        pub fn with(answers: Vec<Result<Response, String>>) -> Self {
            MockTransport {
                answers: RefCell::new(answers.into()),
                seen: RefCell::new(Vec::new()),
            }
        }

        pub fn ok(status: u16, body: serde_json::Value) -> Result<Response, String> {
            Ok(Response { status, body: serde_json::to_vec(&body).unwrap() })
        }

        pub fn network(why: &str) -> Result<Response, String> {
            Err(why.to_string())
        }
    }

    impl Transport for MockTransport {
        fn send(
            &self,
            method: Method,
            url: &str,
            _headers: &[(&'static str, String)],
            body: Option<&[u8]>,
        ) -> Result<Response, String> {
            self.seen.borrow_mut().push((method, url.to_string(), body.unwrap_or_default().to_vec()));
            self.answers
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Err("the mock has no more answers".into()))
        }
    }

    /// The records, in memory.
    #[derive(Default)]
    pub struct MemStore {
        pub records: RefCell<HashMap<String, Vec<u8>>>,
    }

    impl RecordStore for MemStore {
        fn get(&self, name: &str) -> Option<Vec<u8>> {
            self.records.borrow().get(name).cloned()
        }
        fn set(&self, name: &str, value: &[u8]) {
            self.records.borrow_mut().insert(name.to_string(), value.to_vec());
        }
        fn set_if_absent(&self, name: &str, value: &[u8]) -> bool {
            let mut records = self.records.borrow_mut();
            if records.contains_key(name) {
                false
            } else {
                records.insert(name.to_string(), value.to_vec());
                true
            }
        }
        fn set_if_equals(&self, name: &str, current: &[u8], next: &[u8]) -> bool {
            let mut records = self.records.borrow_mut();
            match records.get(name) {
                Some(have) if have == current => {
                    records.insert(name.to_string(), next.to_vec());
                    true
                }
                _ => false,
            }
        }
    }

    impl MemStore {
        pub fn count(&self, name: &str) -> i64 {
            self.get(name).and_then(|b| String::from_utf8(b).ok().and_then(|s| s.parse().ok())).unwrap_or(0)
        }
    }
}
