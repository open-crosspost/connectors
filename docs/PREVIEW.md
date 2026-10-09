# PREVIEW — the x connector, e2e, before OutLayer activates

The curated connector (`connectors.outlayer.near/x`) cannot exist before the
namespace account signs its version — that is the curation gate. This preview
does not wait for it: **the same wasm, deployed as an ordinary project under
your own account**, called end to end through the real platform.

## What this proves — and what it does not

| | |
|---|---|
| ✓ the real wasm running in the real TEE | the same artefact the curated connector will run (`x/build.sh` fail-closed checks included) |
| ✓ the real credential | your wallet's row — X refresh against the real X API, the dual-credential model, the policy |
| ✓ the real X operations | `status`, `me`, `post` with your real account — a real tweet |
| ✓ the update loop | redeploy any time; `<you>/x` is yours, no round-trip with anyone |
| ✗ curation and per-operation pricing | an ordinary project runs without price rows; the curated namespace's registry work is the OutLayer team's |
| ✗ the `X-Use-Owner-Secret` header path | that header takes effect only on a curated connector — the preview calls with `secrets_ref` instead, so the activation-day free `status` remains the production proof |

## Prerequisites

- `outlayer` CLI, logged in (`outlayer whoami` answers)
- an X developer app with OAuth 2.0 user context: your redirect URI registered
  as a Callback URI, the scopes (`offline.access tweet.read tweet.write
  users.read`) permitted
- `scripts/.env` with `X_CLIENT_ID`, `X_CLIENT_SECRET`, `X_REDIRECT_URI` (the
  connect flow) and `OUTLAYER_WALLET_API_KEY` (`wk_…`)

## 1. Deploy

```bash
scripts/preview-deploy.sh
```

Builds the wasm (fail-closed), uploads it to FastFS, and `outlayer deploy`s it
under your own account — `<you>/x`. Redeploy any time: a fix is one run of
this script, no signature, no review.

## 2. Store the row

```bash
PROJECT=<you>/x scripts/x-connect.sh
```

The one human step (the X consent click). The row lands under your wallet's
own account for project `<you>/x` — same agent-secret route as production,
different project. If the endpoint refuses a non-curated project, fall back to
the classic owner's row: app.outlayer.ai/secrets → "Secret for an agent", for
project `<you>/x`, and pass its label to `x-run.sh --profile <label>`.

## 3. A funded key

The **trial key reaches curated connectors only** — the preview needs a funded
key (cents; compute is ~$0.001 a call and there are no operation fees here):

```bash
outlayer keys create
outlayer keys topup
```

## 4. Call it

```bash
scripts/x-run.sh <you>/x '{"operation":"status"}'
scripts/x-run.sh <you>/x '{"operation":"me"}'
scripts/x-run.sh <you>/x '{"operation":"post","text":"gm — first post through the x connector (preview)"}'
```

What a pass looks like:

| call | pass |
|---|---|
| `status` | `output.success: true`, `credential: "ok"`, the granted scope, the policy, `sent_today: 0` — **the refresh IS the proof** |
| `me` | `{"id", "username", "name"}` of the connected account |
| `post` | `output.success: true`, a `tweet_id`, a `url` that opens on x.com, `sent_today: 1`, `remaining_today: 9` |
| `status` again | `sent_today: 1` — the count moved |

A refusal before the run is an HTTP 4xx with a machine-readable `reason`
(`project_not_found`, `invalid_secrets_ref`, `missing_payment_key` — the full
list in the [connectors skill](https://skills.outlayer.ai/outlayer-connectors/SKILL.md),
"Reading a refusal"). The connector's own refusals arrive as
`output.success: false` with `output.error` — branch on its prefix
(`credential_expired:`, `scope_missing:`, `policy_denied:`, `rate_limited:` —
`connector-core/src/refusal.rs`).

Spot-check the refusal matrix the runbook exercises (cheap; every refused
attempt still counts against the day's cap by design):

```bash
scripts/x-run.sh <you>/x '{"operation":"post","text":"'"$(python3 -c 'print("x"*281)')"'"}'   # → `text` holds 281 characters, refused before X is asked
scripts/x-run.sh <you>/x '{"operation":"post","text":"gm"}'   # → 429 operation_limit_reached once 10 posts happened today
```

## 5. Then activation

When the OutLayer team signs the version (the handoff package:
`docs/MAINNET_HANDOFF.md`), the free `status` through
`connectors.outlayer.near/x` — with `X-Use-Owner-Secret: 1`, the row the UI's
connect flow already stored — is the production proof:

```bash
scripts/x-run.sh connectors.outlayer.near/x '{"operation":"status"}'
```

`post` follows the same shape (the priced operation, $0.01).

## Updates after activation

Staged by design — nothing any caller runs changes until the activation:

```bash
scripts/publish.sh x mainnet build          # the new hash
scripts/publish.sh x mainnet upload         # FastFS url (anyone may upload)
# the namespace account signs add_version (set_active: false), then:
scripts/publish.sh x mainnet activate HASH=<new-sha256>
scripts/publish.sh x mainnet rollback HASH=<prior-sha256>   # one call, any time
```

The previous version stays published until the activation, so a bad activate
is one rollback. Prices are per-operation, not per-version — a new operation
needs a new price row (`x/set-prices.sh`); existing operations keep theirs
(the table caches for up to a minute).
