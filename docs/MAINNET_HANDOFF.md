# MAINNET HANDOFF — the x connector → OutLayer

Everything the OutLayer team needs to make `connectors.outlayer.near/x` a
curated connector on mainnet. Send as one package (DM @out_layer, or the
channel the program agreement names). The review is the program agreement's
curation gate — nothing runs on mainnet before their side acts.

## The project

- **project id:** `connectors.outlayer.near/x`
- **connector_id:** `x`
- **source:** https://github.com/open-crosspost/connectors (tag `v0.1.0`)
- **wasm:** https://github.com/open-crosspost/connectors/releases/download/v0.1.0/x-connector.wasm
- **SHA256:** `d382383a2ab088f46b24090ae0c269e01c8c21e25f6721f4769ec947f8dcdb44`
  (the release URL serves exactly these bytes — verified; the worker verifies
  the same hash before executing)
- **target:** `wasm32-wasip2`, 534 KB

## 1. add_version — signed by `connectors.outlayer.near`, `set_active: false`

```bash
near contract call-function as-transaction outlayer.near add_version \
  json-args '{"project_name":"x",
              "source":{"WasmUrl":{"url":"https://github.com/open-crosspost/connectors/releases/download/v0.1.0/x-connector.wasm",
                                   "hash":"d382383a2ab088f46b24090ae0c269e01c8c21e25f6721f4769ec947f8dcdb44",
                                   "build_target":"wasm32-wasip2"}},
              "set_active":false}' \
  prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \
  sign-as connectors.outlayer.near network-config mainnet sign-with-legacy-keychain send
```

`set_active: false` first: nothing any caller runs changes until the
activation, the previous version (there is none — this is v1) stays
published, and a rollback is one `set_active_version`.

## 2. Price rows — signed by the contract owner

```bash
CONTRACT=outlayer.near OWNER=<owner> ./x/set-prices.sh mainnet
```

The script refuses to price anything the manifest does not declare (and vice
versa). The rows: `status`, `me`, `confirm`, `task_*` — free;
`post` — $0.01 (`10000`), `developer_share_bp: 0` (the author is the
namespace; the whole fee stays with the project's owner). Then the
coordinator refresh (the script does both halves).

## 3. Activate

```bash
HASH=d382383a2ab088f46b24090ae0c269e01c8c21e25f6721f4769ec947f8dcdb44 \
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
