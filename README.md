# open-crosspost/connectors

OutLayer connectors for the open-crosspost family — one crate per connector,
a shared core, a common contract.

A connector is a WASI P2 module (Rust → `wasm32-wasip2`) that runs inside the
same TEE as an OutLayer custody wallet: the owner's credential is sealed in
the enclave, the owner's policy is checked on every call, and the module
reaches only the hosts its manifest declares. It is published under the
platform's curated namespace (`connectors.outlayer.testnet/<id>` on testnet,
`connectors.outlayer.near/<id>` on mainnet), priced per operation, and called
by any agent over HTTPS:

```
POST https://api.outlayer.ai/call/connectors.outlayer.near/x
X-Payment-Key: <a payment key the calling wallet owns>
Content-Type: application/json

{"input": {"operation": "post", "text": "gm"},
 "secrets_ref": {"account_id": "the-owner.near", "profile": "x"}}
```

The connector's own answer — `{success, operation, output, error, logs}` —
comes back inside the platform's `output`. The field is `error`, never
`error_message`; callers branch on `error`'s prefix, so the prefixes are the
contract (see `connector-core/src/refusal.rs`).

## Layout

| crate | what it is |
|---|---|
| `connector-core` | the boilerplate every connector in the family reuses, written and tested once: the answer shape, the refusal vocabulary, the owner-policy model (fail-closed, UTC-day counting, reserve/release budget), the atomic sealed counter, the dual OAuth credential (the owner's own client wins; the author's completes a connected account), the token cache, the manifest embedding, and the redaction guard |
| `x` | the X (Twitter) connector: `status`, `me`, `post` (+ `confirm` and the task operations), under the owner's policy |
| `farcaster` *(planned, #23)* | the Farcaster connector: `status`, `cast`, `delete` |

## The program structure

One crate per connector, riding on the shared core. A connector supplies
only what is genuinely its own:

* its `manifest.json` — the connector id, the exact outbound host allowlist
  the TEE enforces, the per-wallet caps it declares, its author-secrets
  profile, and the `describe` block the developer page renders;
* its service endpoints and their refusal wording;
* its policy fields and their checks.

Everything else — the answer shape, the policy machinery, the budget, the
credential resolution, the cache, the refusals, the guard — comes from
`connector-core` and is never edited per connector. The test of the core is
that the second connector rides on it unchanged.

## Building

```bash
cargo test                     # the whole family, native
cd x && ./build.sh             # wasm32-wasip2 + every fail-closed check
```

`build.sh` hard-fails when the `outlayer.manifest` custom section is missing
from the artefact, when the manifest's words are ones the platform does not
know, or when the manifest, the code and the README disagree about the
operations. It prints the wasm's SHA256 — the value `add_version` records and
the worker verifies.

## Publishing (OutLayer signs)

The namespace account (`connectors.outlayer.testnet`) signs `add_version`
(with `set_active: false` first, so nothing any caller runs changes until the
activation) and `set_active_version`. A one-call rollback is
`set_active_version` back to the prior hash. See the runbooks under `docs/`
once publishing starts.

## Secrets rows

| row | stored by | profile | values |
|---|---|---|---|
| the owner's credential | the owner | `x` | `X_REFRESH_TOKEN` (or, with an OAuth app of their own: `X_CLIENT_ID`, `X_CLIENT_SECRET`, `X_REFRESH_TOKEN` — theirs wins) |
| the owner's policy | the owner | `x` | `X_POLICY` |
| the connector's OAuth client | the author (publisher) | `author` | `X_OAUTH_CLIENT_ID`, `X_OAUTH_CLIENT_SECRET` |

The author's client is stored under different NAMES than an owner's own
client, deliberately: a key defined by both the author and the caller refuses
the run, and a user who brought their own client must keep working.
