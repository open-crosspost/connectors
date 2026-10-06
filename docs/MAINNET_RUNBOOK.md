# MAINNET RUNBOOK — the x connector

The mainnet twin of [TESTNET_RUNBOOK.md](TESTNET_RUNBOOK.md): the names move,
the money becomes real, and the account that signs is
`connectors.outlayer.near`. Nothing here runs before the curation review has
passed (the program agreement) and the testnet runbook is fully green.

## The names

| | testnet | mainnet |
|---|---|---|
| API base | `https://testnet-api.outlayer.ai` | `https://api.outlayer.ai` |
| contract | `outlayer.testnet` | `outlayer.near` |
| namespace | `connectors.outlayer.testnet` | `connectors.outlayer.near` |
| project | `connectors.outlayer.testnet/x` | `connectors.outlayer.near/x` |
| FastFS | `test.fastfs.io` | `main.fastfs.io` |

There is no network parameter anywhere — the host is the network. A testnet
key means nothing on mainnet, and **existing testnet keys mean nothing after
the move**: every user re-provisions against `api.outlayer.ai`, or is
grandfathered by the provisioning flow re-running for them (ticket #11's
flow, pointed at the mainnet host).

## The sequence (same shape as testnet)

1. **Publish.** `scripts/publish.sh x mainnet build|upload|version` — the
   namespace account signs `add_version` with `set_active: false` first.
2. **Price rows.** `x/set-prices.sh mainnet` — the contract owner signs, the
   coordinator refresh picks it up.
3. **Activate.** `scripts/publish.sh x mainnet activate HASH=<sha256>` — the
   first mainnet run becomes possible.
4. **The author's row.** `outlayer secrets set '{"X_OAUTH_CLIENT_ID":…,
   "X_OAUTH_CLIENT_SECRET":…}' --project connectors.outlayer.near/x --profile
   author` — a MAINNET row; the testnet author row does not follow.
5. **Curation.** the review gates 1–4; the wasm published here is the exact
   bytes the tests validated (same SHA256 discipline).

**Status (2026-10-06):** the wasm is published at a fetchable URL and the
handoff package is ready — `docs/MAINNET_HANDOFF.md` holds the exact calls
(add_version `set_active: false`, the price rows, the activation, the author
row) for the OutLayer team, who sign everything under the curated namespace.
The wallet's trial payment key is claimed (50 calls, expires 2026-10-13).

## The credential route (no OutLayer UI, no whitelist)

The crosspost UI's own flow — the row is stored **under the user's own
custody wallet**, so the caller and the row's owner are the same account and
no access rule exists to maintain:

1. the user links X in the crosspost UI (our OAuth PKCE page — today,
   `scripts/x-connect.sh` does the same flow by hand: consent click → token
   exchange → row store, and the refresh token is never printed);
2. the row is stored with `POST /wallet/v1/agent-secret` (the user's wallet
   signs with its `wk_`; `…/prepare` lets the author pay the storage when the
   wallet has no NEAR): project `connectors.outlayer.near/x`, values
   `X_REFRESH_TOKEN`, `X_POLICY` (the caps the user chose in OUR UI), and —
   when they bring their own X app — `X_CLIENT_ID`/`X_CLIENT_SECRET` (the
   dual model: theirs wins over the author's);
3. every connector call carries `X-Use-Owner-Secret: 1` and **no
   `secrets_ref`**.

The owner-row + whitelist route remains for a user granting a THIRD-PARTY
agent access to their X — not for this product's own path.

## Mainnet-only work

### Sponsor codes (the user never pays)

```bash
# OutLayer provisions codes; each redeems to a subscription on the wallet's nonce-0 key:
outlayer redeem spn_... --api-key wk_...
```

Provisioned in bulk, wired into the app's signup flow (#15): a new user's
custody wallet redeems a code at signup, and the nonce-0 key pays every
connector call. **Pass:** a fresh signup posts without funding anything.

### Migration checklist

- [ ] provisioning/call base URLs in the app move to `api.outlayer.ai` (#11's flow, #13's routes)
- [ ] existing test users re-provisioned (the flow re-run) or grandfathered, per the program agreement
- [ ] testnet secrets rows NOT copied — a user reconnects on mainnet, their row is theirs to store again
- [ ] the connect handoff (#18) points at the mainnet dashboard page

### Launch monitoring

- [ ] refusal-rate dashboards per class: `credential_expired` (owner churn),
      `credential_rejected` (mid-flight revocations), `scope_missing`
      (consent gaps), `policy_denied` (owner caps biting), `rate_limited`
      (X throttling), `operation_limit_reached` (runaway loops — spikes here
      are agents to talk to, not outages)
- [ ] sponsor-burn telemetry: codes redeemed vs. calls made per sponsor
- [ ] X tier utilization: posts/day against the app's API tier, so a tier
      change is seen before callers meet it as `rate_limited`
- [ ] `outlayer logs` + the coordinator's `earnings history` as the ledger

### Rollback

One call, same as testnet — `scripts/publish.sh x mainnet rollback
HASH=<prior>` — and the prior version is active again. **Exercised on
mainnet too**, with the first two versions, before anyone depends on the
connector.

## Results

| check | date | result |
|---|---|---|
| wasm published at a fetchable URL (release v0.1.0, hash verified) | 2026-10-06 | ✓ |
| trial payment key claimed (50 calls) | 2026-10-06 | ✓ |
| handoff package ready (docs/MAINNET_HANDOFF.md) | 2026-10-06 | ✓ |
| curation review passed | — | ☐ |
| publish (version → prices → activate) | — | ☐ |
| author row on mainnet | — | ☐ |
| X account linked (agent-secret route) | — | ☐ |
| real mainnet post from a real user wallet | — | ☐ |
| sponsor path live (new signups never pay) | — | ☐ |
| monitoring/telemetry live | — | ☐ |
| migration of base URLs + users | — | ☐ |
| rollback path exercised | — | ☐ |
