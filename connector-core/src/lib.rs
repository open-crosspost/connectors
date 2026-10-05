//! connector-core: the boilerplate every connector in the open-crosspost
//! family reuses, so the security-critical parts are written once, tested
//! once, and never drift apart between connectors.
//!
//! Modeled on the platform's own connectors (`out-layer/outlayer`:
//! `gmail-connector`, `connector-probe`); one crate per connector rides on
//! this core and supplies only what is genuinely its own — the service's
//! endpoints, its refusal wording, its policy fields.
//!
//! | module | what every connector gets from it |
//! |---|---|
//! | [`envelope`] | the answer shape `{success, operation, output, error, logs}` — the field is `error`, never `error_message` |
//! | [`refusal`] | the refusal vocabulary and its helpers: the prefixes are the family's contract, the sentences say who fixes what |
//! | [`policy`] | fail-closed loading of the owner's policy, UTC-day counting, the reserve/release budget |
//! | [`store`] | sealed project storage and the atomic increment the budgets count through |
//! | [`oauth`] | the dual credential (the owner's own client wins; the author's completes a connected account) and the token cache |
//! | [`manifest`] | the manifest embedded in the wasm, and the words it may use |
//! | [`redact`] | the guard: no secret value reachable from any output |

pub mod envelope;
pub mod manifest;
pub mod oauth;
pub mod policy;
pub mod redact;
pub mod refusal;
pub mod store;

pub use envelope::{envelope, undecodable, Envelope, Refused};
pub use manifest::Manifest;
pub use oauth::Credential;
pub use policy::{day_key, now_ms, now_secs, reserve, sent_today, Counted, Loaded, Reservation};
pub use redact::sweep;
pub use refusal::Outcome;
pub use store::bump as sealed_bump;
