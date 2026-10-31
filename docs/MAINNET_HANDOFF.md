# MAINNET HANDOFF — the x connector → OutLayer

Everything the OutLayer team needs to make `connectors.outlayer.near/x` a
curated connector on mainnet. Send as one package (DM @out_layer, or the
channel the program agreement names). The review is the program agreement's
curation gate — nothing runs on mainnet before their side acts.

## The project

- **project id:** `connectors.outlayer.near/x`
- **connector_id:** `x`
- **source:** https://github.com/open-crosspost/connectors (tag `v0.2.0`)
- **wasm:** https://github.com/open-crosspost/connectors/releases/download/v0.2.0/x-connector.wasm
- **SHA256:** `8dc9bb10479186c81f691773889574addbf2a8627bd869a2a54cc65268d0aa91`
  (the release URL serves exactly these bytes — verified; the worker verifies
  the same hash before executing)
- **target:** `wasm32-wasip2`, 580 KB
- **what this bundle adds** (issue #2, superseding the un-activated
  v0.1.2 — this is THE one upgrade to sign): `retweet` (X's repost,
  counted with the posts in the daily cap, confirmable as `repost`),
  `unretweet` (the account's own stamp back; never counted), `delete`
  (only the account's own post; **the owner confirms by default** — an
  absent `confirm` member asks, a spelled one, even `[]`, is the whole
  word), and `poll` on `post`. Every tweet-ref (`reply_to`, each
  `tweet_id`) accepts a bare id or a status url; malformed input refuses
  pre-run at no cost. Same credential, same scopes, same hosts: no
  re-consent for existing connections. v0.1.2's reply support is included.

## 1. add_version — signed by `connectors.outlayer.near`, `set_active: false`

```bash
near contract call-function as-transaction outlayer.near add_version \
  json-args '{"project_name":"x",
              "source":{"WasmUrl":{"url":"https://github.com/open-crosspost/connectors/releases/download/v0.2.0/x-connector.wasm",
                                   "hash":"8dc9bb10479186c81f691773889574addbf2a8627bd869a2a54cc65268d0aa91",
                                   "build_target":"wasm32-wasip2"}},
              "set_active":false}' \
  prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \
  sign-as connectors.outlayer.near network-config mainnet sign-with-legacy-keychain send
```

`set_active: false` first: nothing any caller runs changes until the
activation — v0.1.0 (sha256 `d382383a2ab088f46b24090ae0c269e01c8c21e25f6721f4769ec947f8dcdb44`,
still fetched from its own release URL) stays published, and a rollback
is one `set_active_version` naming its hash.

## 2. Price rows — one call, this bundle's only pricing change

The manifest now declares three operations more than the priced rows
hold, and an unpriced operation is refused `unknown_operation` before it
runs. `x/set-prices.sh mainnet` writes the whole table in one call:
`retweet` rides with `post` at $0.01 (X bills the app for every write
either way); `unretweet` and `delete` are free — safety operations.
Rows, coordinator refresh, both halves, one run:

```bash
CONTRACT=outlayer.near OWNER=<owner> ./x/set-prices.sh mainnet
```

## 3. Activate

```bash
HASH=8dc9bb10479186c81f691773889574addbf2a8627bd869a2a54cc65268d0aa91 \
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
