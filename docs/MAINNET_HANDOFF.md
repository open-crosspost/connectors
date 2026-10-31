# MAINNET HANDOFF — the x connector → OutLayer

Everything the OutLayer team needs to make `connectors.outlayer.near/x` a
curated connector on mainnet. Send as one package (DM @out_layer, or the
channel the program agreement names). The review is the program agreement's
curation gate — nothing runs on mainnet before their side acts.

## The project

- **project id:** `connectors.outlayer.near/x`
- **connector_id:** `x`
- **source:** https://github.com/open-crosspost/connectors (tag `v0.1.2`)
- **wasm:** https://github.com/open-crosspost/connectors/releases/download/v0.1.2/x-connector.wasm
- **SHA256:** `d8c2e0f615713109413d283407b27c20a2101344490741947bf046e2b465eb45`
  (the release URL serves exactly these bytes — verified; the worker verifies
  the same hash before executing)
- **target:** `wasm32-wasip2`, 540 KB
- **what this version adds** (issue #1): `post` carries an optional
  `reply_to` — a tweet id or a status url, resolved pre-run at no cost —
  and `/2/tweets` gains the `reply` object; absent `reply_to`, the wire
  and the answer are exactly as v0.1.0's. No new operation, so the price
  rows and the author row carry over unchanged.

## 1. add_version — signed by `connectors.outlayer.near`, `set_active: false`

```bash
near contract call-function as-transaction outlayer.near add_version \
  json-args '{"project_name":"x",
              "source":{"WasmUrl":{"url":"https://github.com/open-crosspost/connectors/releases/download/v0.1.2/x-connector.wasm",
                                   "hash":"d8c2e0f615713109413d283407b27c20a2101344490741947bf046e2b465eb45",
                                   "build_target":"wasm32-wasip2"}},
              "set_active":false}' \
  prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \
  sign-as connectors.outlayer.near network-config mainnet sign-with-legacy-keychain send
```

`set_active: false` first: nothing any caller runs changes until the
activation — v0.1.0 (sha256 `d382383a2ab088f46b24090ae0c269e01c8c21e25f6721f4769ec947f8dcdb44`,
still fetched from its own release URL) stays published, and a rollback
is one `set_active_version` naming its hash.

## 2. Price rows — no change

Every operation of v0.1.0 is priced already, and v0.1.2 adds none
(`reply_to` is a parameter of `post`, not an operation). Only touch
`x/set-prices.sh` if a price should move with this release.

## 3. Activate

```bash
HASH=d8c2e0f615713109413d283407b27c20a2101344490741947bf046e2b465eb45 \
  scripts/publish.sh x mainnet activate
```

## 4. The author row — stored by the publishing account

The manifest names `author_secrets.profile = "author"`. The row makes
"connect your X account, bring only a refresh token" work: the author's OAuth
client completes it at run time, inside the enclave.

```bash
outlayer secrets set '{"X_OAUTH_CLIENT_ID":"<our client id>","X_OAUTH_CLIENT_SECRET":"<our client secret>"}' \
  --project connectors.outlayer.near/x --profile author
```

The client must be the one the connect handoff (#18) mints refresh tokens
with — an X app with OAuth 2.0, `offline.access`, `tweet.write`, `tweet.read`,
`users.read`, and the handoff's redirect URI registered.

## What to review

- the wasm is the tagged release; its manifest (inside the artefact) declares
  exactly two outbound hosts, `api.twitter.com` and `api.x.com`, exact
  hostnames; a 500/day ceiling on `post` and on `confirm` (`limits`)
- the connector never echoes a secret: every run sweeps its answer against
  every value it read or minted (connector-core/src/redact.rs, tested)
- the refusal set is terminal/retryable-classified and prefix-stable
  (connector-core/src/refusal.rs; the runbook exercises it live)
- the smoke test that follows activation is documented in
  `docs/MAINNET_RUNBOOK.md` with what each pass looks like
