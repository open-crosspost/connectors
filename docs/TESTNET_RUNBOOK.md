# TESTNET RUNBOOK — the x connector

The ordered list of steps that puts `connectors.outlayer.testnet/x` live and
checks each limit and each refusal, with what a pass looks like. Modelled on
the platform's own (`connector-probe`'s README and the coordinator's testnet
runbook); filled in as results land, so the repo carries the record.

## Who signs what

| step | signed by | tool |
|---|---|---|
| upload (FastFS) | any NEAR key — the uploader shows in the URL only | `outlayer upload` (needs `near_key` auth, not `wallet_key`) |
| `add_version`, `set_active_version` | **the namespace account** `connectors.outlayer.testnet` | near-cli |
| price rows | the **contract owner** | `x/set-prices.sh` |
| secrets rows | the **owner of each row** (the author's = the publishing account) | `outlayer secrets` |

Prerequisites: `outlayer` CLI (`curl -fsSL https://raw.githubusercontent.com/out-layer/outlayer-cli/main/install.sh | sh`
— or move the binary to a PATH dir; no sudo needed), `near-cli` (`near`),
`wasm-tools`, python3, and the rust `wasm32-wasip2` target.

## 0. Build

```bash
./x/build.sh
```

**Pass:** wasm ≤ 2MB, `Manifest section: present`, `outlayer:tasks is
imported`, `9 operations agree with the code and the README`, a SHA256. The
SHA256 is the `version_key` everywhere below.

**Fail-closed proof (once):** strip the section
(`wasm-tools strip <wasm> -o /tmp/stripped.wasm`) and confirm
`grep -qa outlayer.manifest /tmp/stripped.wasm` finds nothing — a wasm like
that is refused at build time, because a connector without the section reaches
nothing.

## 1. Publish

```bash
scripts/publish.sh x testnet build
scripts/publish.sh x testnet upload          # → FastFS url; verify it serves those bytes
URL=<fastfs-url> HASH=<sha256> scripts/publish.sh x testnet version
x/set-prices.sh testnet                      # contract owner; then the coordinator refresh
scripts/publish.sh x testnet activate HASH=<sha256>
```

**Pass:** `add_version` succeeded with `set_active: false` (nothing any caller
runs changed yet); the FastFS URL serves exactly the hashed bytes
(`curl -fsSL <url> | shasum -a 256` = the SHA256); the price row reads back
from `get_project_pricing`; the activation names the same hash.

**Refusal to expect first:** a call BEFORE the price rows exist answers
`400 unknown_operation` — an unpriced project is not a free one. That is the
first live check of the matrix.

## 2. Secrets rows

The AUTHOR's row (the publishing account stores it; the manifest names
`author_secrets.profile = author`):

```bash
outlayer secrets set '{"X_OAUTH_CLIENT_ID":"<our client id>","X_OAUTH_CLIENT_SECRET":"<our client secret>"}' \
  --project connectors.outlayer.testnet/x --profile author
```

The OWNER's row (a real test X account, connected through the connect handoff
or stored by hand; the agent's wallet account is whitelisted by name):

```bash
outlayer secrets set '{"X_REFRESH_TOKEN":"<refresh token from the test account>"}' \
  --project connectors.outlayer.testnet/x --profile x \
  --access whitelist:<owner.testnet>,<agent wallet account>
outlayer secrets update '{"X_POLICY":"{\"max_per_day\":10}"}' \
  --project connectors.outlayer.testnet/x --profile x
```

**Pass:** `outlayer secrets list` shows both profiles under the project; the
policy parses (the connector refuses an unreadable one — fail-closed).

X's refresh token ROTATES on every refresh; the connector keeps the newest one
in its own sealed storage, so the row never has to change. If the credential
dies anyway (a lost refresh mid-rotation), the row is re-stored or the account
reconnects.

## 3. The smoke test

With a payment key of the calling wallet (`outlayer keys create`, or the
trial), the calls in order — each one's answer is evidence:

| # | call | what a pass looks like |
|---|---|---|
| 3.1 | `outlayer run connectors.outlayer.testnet/x '{"operation":"status"}'` | HTTP 200, `output.success: true`, `credential: "ok"`, `oauth_client`, `granted_scope` carrying `tweet.write`, the policy, `sent_today: 0` — the refresh IS the proof |
| 3.2 | `{"operation":"me"}` | `{"id", "username", "name"}` of the test account |
| 3.3 | `{"operation":"post","text":"gm — first post through the x connector"}` | `output.success: true`, a `tweet_id`, a `url` that opens on x.com, `sent_today: 1`, `remaining_today: 9` |
| 3.4 | `{"operation":"status"}` again | `sent_today: 1` — the count moved |

## 4. The refusal matrix, live

| # | call | refusal | what a pass looks like |
|---|---|---|---|
| 4.1 | an operation with no price row (e.g. `{"operation":"unpriced"}`) | `400 unknown_operation` | refused BEFORE anything runs; costs nothing |
| 4.2 | the same calls with NO `secrets_ref` | `no credential reached this run` | terminal wording; names the connect page |
| 4.3 | `secrets_ref` naming an account that never granted the caller | the same | the row's access condition decides; a grant may expire with a date |
| 4.4 | a wallet with no policy stored (`X_POLICY` deleted) | `policy_denied: … holds no X_POLICY` | nothing posted; the sentence says the OWNER stores it |
| 4.5 | a policy this build cannot read (`{"surprise":1}`) | `policy_denied: X_POLICY could not be read` | fail-closed: an unknown field is a parse error |
| 4.6 | text over 280 characters | `` `text` holds N characters `` | refused before X is asked; the daily count NOT moved |
| 4.7 | the daily cap at the edge (`{"max_per_day":1}` then post twice) | the second: `policy_denied: 1 of the owner's 1 a day are used` | the refused post gave its place back; `sent_today` unchanged |
| 4.8 | the technical ceiling (`{"operation":"post"}` ×500 in a day) | `429 operation_limit_reached` + `retry_after_seconds` | refused attempts still count toward it — wait it out (usually proven on the probe's `budget`, not by 500 real posts) |
| 4.9 | `confirm: ["post"]` policy, then `post` | `{"status":"awaiting_owner","task_id","task_hash","link"}` | a SUCCESS — do not retry; the owner approves; the platform runs `confirm` as the agent; `task_status` reads the outcome (`done` + tweet id, or `rejected` with the owner's reason) |
| 4.10 | an undeclared host | — | not reachable live from x (it only ever calls `api.twitter.com`/`api.x.com`); the probe's `forbidden_fetch` proves the enforcement itself. `wasm-tools component wit <wasm>` shows the component imports no other door |

**Unknown outcome (no blind resend)** is proven in the unit tests against the
mock (a lost answer KEEPS its place in the count and the refusal says "do not
resend blind"); live, it is the case you hope never to meet — if a post ever
answers that way, check the profile before doing anything.

## 5. Payment semantics

| key | how to get it | what a pass looks like |
|---|---|---|
| trial | `outlayer keys trial-key --api-key wk_...` in the wallet's first week | the free `status` counts against the 50; the priced `post` too; `trial_exhausted` after |
| sponsored | `outlayer redeem spn_... --api-key wk_...` | the subscription key pays; the user never does |
| funded | `outlayer keys create` + `keys topup` | no call limit; `post` spends its cent |

**Pass:** all three paths call `status` successfully on testnet; only the
money differs.

## 6. Rollback

```bash
# The hash of the PRIOR version, then one call:
HASH=<prior-sha256> scripts/publish.sh x testnet rollback
```

**Pass:** `status` still answers (the previous version is active); the ledger
shows the switch. Exercised ONCE and recorded below.

## Results

| check | date | result |
|---|---|---|
| 0. build + fail-closed proof | — | ☐ |
| 1. publish (version → prices → activate) | — | ☐ |
| 2. secrets rows (author + owner + policy) | — | ☐ |
| 3.1 status proves the credential | — | ☐ |
| 3.2 me → handle | — | ☐ |
| 3.3 post → REAL tweet | — | ☐ |
| 3.4 count moved | — | ☐ |
| 4.1–4.7 refusal matrix | — | ☐ |
| 4.9 awaiting_owner flow | — | ☐ |
| 5. trial / sponsored / funded | — | ☐ |
| 6. rollback exercised | — | ☐ |
