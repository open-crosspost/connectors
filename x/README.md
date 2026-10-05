# x — the X (Twitter) connector

An agent posts to X as the owner's connected account, under the owner's
policy, without ever holding the credential outside the enclave.

The owner connects their account once — the connect page stores a refresh
token for it under the owner's secrets row, profile `x` — and grants an
agent's wallet on that row. This connector's own OAuth client completes the
token at run time (an author secret, profile `author`) and never enters
anyone's stored row. An owner who brings their own OAuth app stores
`X_CLIENT_ID` and `X_CLIENT_SECRET` beside their refresh token, and theirs
wins.

Everything else happens inside the enclave: the refresh token is exchanged
for an access token, the access token posts through X's REST API, and
neither ever appears in an answer.

Two hosts, both in the manifest: `api.twitter.com` (the token endpoint) and
`api.x.com` (the API) — exact hostnames, no wildcard.

## Operations

| `operation` | class | what it does |
|---|---|---|
| `status` | read | whether the credential works — **proved by refreshing it**, not guessed — which OAuth client the run used, the policy's caps, and the caller's own posts today |
| `me` | read | the connected account's handle, id and display name, for the UI |
| `post` | write | one post, policy-checked first; left as a task for the owner when their policy lists `post` under `confirm` |
| `confirm` | write | run by the platform as the agent on the owner's approval: posts the text the task holds |
| `task_status`, `task_cancel`, `task_delete`, `tasks`, `tasks_unlock` | | the tasks this caller made, and the owner's devices |

## The policy

The owner's rules, stored beside the credential as `X_POLICY`. Fail-closed:
no policy means nothing is posted, and a policy this build cannot read
refuses too — an unknown field is a parse error, not something to ignore.

| field | absent means | set means |
|---|---|---|
| `max_per_day` | the owner is not capping you | that many posts a day, counted per calling wallet in UTC days; a post refused before it leaves gives its place back |
| `confirm` | you post without asking | `["post"]`: every post waits for the owner's confirmation, answered `awaiting_owner` — a success, not to be retried |

## The daily ceiling

The connector itself carries one technical ceiling against a runaway loop —
**500 posts in a UTC day per calling wallet**, declared in the manifest's
`limits` and enforced by the coordinator, answered `operation_limit_reached`
with `retry_after_seconds`. An attempt that ceiling refuses still counts
toward it: wait, do not retry into it.

## Refusals

| the error starts with | what happened | terminal? |
|---|---|---|
| `no credential reached this run` | nothing reached the run: not connected, not granted, or the wrong `secrets_ref` | yes, until the owner connects or grants |
| `a refresh token reached this run with no OAuth client to use it with` | the owner's row carries a refresh token and no client, and the author stored none | yes — the owner stores their client or reconnects |
| `credential_expired:` | X refused the refresh token — revoked or expired | yes, the owner reconnects |
| `credential_rejected:` | X refused the access token or the OAuth client; probably revoked mid-flight | yes, the owner reconnects |
| `scope_missing:` | the credential was not granted the scope the operation needs (`tweet.write`, `users.read`) | yes, the owner consents again |
| `rate_limited:` | X is throttling; nothing was posted | no — wait, then retry |
| `policy_denied:` | the owner's rules: no policy, an unreadable policy, or their daily cap | not by retrying; change the request or ask the owner |
| `X refused /2/…: HTTP 4…` | anything else X refused, in its own words; nothing was posted | judge it by what X said |
| `… outcome is unknown` | the request went out, or may have, and its outcome is unknown: **the post MAY have gone out** | do not resend blind — check the profile, and say so to the owner |
| `operation_limit_reached` | the daily ceiling; `retry_after_seconds` names the wait | wait it out |

### About refresh-token rotation

X rotates the refresh token on every refresh: each refresh voids the token
it used and issues a new one. The connector keeps the newest one in its own
sealed project storage (keyed to the credential it was minted from), so the
owner's row never has to change. The access-token cache (X's tokens live
about two hours) is what keeps refreshes rare — a refresh that races another
can void a rotation, which is one reason not to hammer the connector.

## Tests

The connector is tested against a mocked X API (`cargo test`): the refresh
flow (rotation included), the policy matrix, both caps, every refusal
branch, the `awaiting_owner` confirm flow, the unknown-outcome semantics,
and the guard that no secret value is reachable from any output.
