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
   bytes the testnet runbook validated (same SHA256 discipline).

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
| curation review passed | — | ☐ |
| publish (version → prices → activate) | — | ☐ |
| author row on mainnet | — | ☐ |
| real mainnet post from a real user wallet | — | ☐ |
| sponsor path live (new signups never pay) | — | ☐ |
| monitoring/telemetry live | — | ☐ |
| migration of base URLs + users | — | ☐ |
| rollback path exercised | — | ☐ |
