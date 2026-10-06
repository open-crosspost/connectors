#!/usr/bin/env bash
#
# Link an X account to an OutLayer wallet — the agent-secret route.
#
# One human step (the OAuth consent click). The refresh token is exchanged
# against X and stored as the wallet's own secrets row; it is never printed,
# never leaves the machine, and never reaches the OutLayer dashboard.
#
# The row lands UNDER THE WALLET'S OWN ACCOUNT (accessor = the project, profile
# = the wallet's 64-hex account), so every later connector call is made with
# `X-Use-Owner-Secret: 1` and NO `secrets_ref` — the caller and the row's owner
# are the same account, and no whitelist exists to maintain. The wallet's own
# client (X_CLIENT_ID/X_CLIENT_SECRET in the row) wins over the author's: the
# token was minted by YOUR X app, and only that app can refresh it.
#
# Prerequisites:
#   * an X developer app with OAuth 2.0 enabled, User authentication settings
#     configured with X_REDIRECT_URI below as a registered Callback URI, and
#     the scopes (offline.access tweet.read tweet.write users.read) permitted
#   * OUTLAYER_WALLET_API_KEY (wk_...) in scripts/.env — the wallet that will
#     pay for calls, and under whose account the row is stored
#
# Usage:
#   X_CLIENT_ID=... X_CLIENT_SECRET=... X_REDIRECT_URI=https://... \
#     scripts/x-connect.sh
#
set -euo pipefail

cd "$(dirname "$0")/.."
[ -f scripts/.env ] && set -a && . scripts/.env && set +a

: "${X_CLIENT_ID:?set X_CLIENT_ID to your X app's OAuth 2.0 Client ID}"
: "${X_CLIENT_SECRET:?set X_CLIENT_SECRET to your X app's OAuth 2.0 Client Secret}"
: "${X_REDIRECT_URI:?set X_REDIRECT_URI to a Callback URI registered in the X app}"
OUTLAYER_API="${OUTLAYER_API:-https://api.outlayer.ai}"
PROJECT="${PROJECT:-connectors.outlayer.near/x}"
POLICY="${POLICY:-{\"max_per_day\":10}}"

command -v curl >/dev/null || { echo "ERROR: curl required"; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: python3 required"; exit 1; }

# ── PKCE pair ────────────────────────────────────────────────────────────────
VERIFIER=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
CHALLENGE=$(printf '%s' "$VERIFIER" | python3 -c 'import sys,hashlib,base64; print(base64.urlsafe_b64encode(hashlib.sha256(sys.stdin.buffer.read()).digest()).decode().rstrip("="))')
STATE=$(python3 -c 'import secrets; print(secrets.token_urlsafe(16))')

# ── the consent click — the one human step ──────────────────────────────────
AUTH_URL=$(python3 - "$X_CLIENT_ID" "$X_REDIRECT_URI" "$CHALLENGE" "$STATE" <<'PY'
import sys, json, urllib.parse
client_id, redirect, challenge, state = sys.argv[1:5]
params = {
    "response_type": "code",
    "client_id": client_id,
    "redirect_uri": redirect,
    "scope": "tweet.read users.read tweet.write offline.access",
    "state": state,
    "code_challenge": challenge,
    "code_challenge_method": "S256",
}
print("https://x.com/i/oauth2/authorize?" + urllib.parse.urlencode(params))
PY
)
echo "Opening X's consent page — approve it for the account you want to link."
echo "  $AUTH_URL"
( command -v open >/dev/null && open "$AUTH_URL" ) || ( command -v xdg-open >/dev/null && xdg-open "$AUTH_URL" ) || true
printf 'Paste the FULL redirect URL the browser landed on (it holds ?code=…&state=…): '
read -r REDIRECTED
case "$REDIRECTED" in
  *"state=$STATE"*) : ;;
  *) echo "ERROR: the state does not match — the redirect may not be this flow's. Aborting (nothing stored)."; exit 1 ;;
esac
CODE=$(printf '%s' "$REDIRECTED" | python3 -c 'import sys,urllib.parse; q=urllib.parse.urlparse(sys.stdin.read().strip()); print(dict(p.split("=",1) for p in q.query.split("&") if "=" in p).get("code",""))')
[ -n "$CODE" ] || { echo "ERROR: no code in the redirect."; exit 1; }

# ── exchange the code — Basic client auth, the confidential-client flow ─────
BASIC=$(python3 -c 'import sys,base64; print(base64.b64encode(f"{sys.argv[1]}:{sys.argv[2]}".encode()).decode())' "$X_CLIENT_ID" "$X_CLIENT_SECRET")
TOKEN_ANSWER=$(curl -s -X POST "https://api.twitter.com/2/oauth2/token" \
  -H "Authorization: Basic $BASIC" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=$X_REDIRECT_URI" \
  --data-urlencode "code_verifier=$VERIFIER")
REFRESH=$(printf '%s' "$TOKEN_ANSWER" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("refresh_token",""))')
GRANTED_SCOPE=$(printf '%s' "$TOKEN_ANSWER" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("scope",""))')
[ -n "$REFRESH" ] || {
  echo "ERROR: X granted no refresh token. The consent must carry offline.access,"
  echo "and the app must not be in a mode that withholds it. X's answer:"
  printf '%s\n' "$TOKEN_ANSWER" | python3 -c 'import sys,json; d=json.load(sys.stdin); print("  " + d.get("error","?") + (": " + d.get("error_description","") if d.get("error_description") else ""))'
  exit 1
}
echo "✓ exchanged — scope granted: $GRANTED_SCOPE"
case "$GRANTED_SCOPE" in
  *offline.access*|*tweet.write*) : ;;
  *) echo "WARN: the granted scope does not name offline.access/tweet.write — the row will store, but posting may be refused scope_missing." ;;
esac

# ── store the row under the wallet's own account (the agent-secret route) ────
BODY=$(python3 - "$PROJECT" "$REFRESH" "$X_CLIENT_ID" "$X_CLIENT_SECRET" "$POLICY" <<'PY'
import sys, json
project, refresh, client_id, client_secret, policy = sys.argv[1:6]
print(json.dumps({
    "project": project,
    "secrets": {
        "X_REFRESH_TOKEN": refresh,
        "X_CLIENT_ID": client_id,
        "X_CLIENT_SECRET": client_secret,
        "X_POLICY": json.dumps(json.loads(policy), separators=(",", ":")),
    },
}))
PY
)
ANSWER=$(curl -s -w '\n%{http_code}' -X POST "$OUTLAYER_API/wallet/v1/agent-secret" \
  -H "Authorization: Bearer ${OUTLAYER_WALLET_API_KEY:?set OUTLAYER_WALLET_API_KEY in scripts/.env}" \
  -H "Content-Type: application/json" \
  -d "$BODY")
STATUS=$(printf '%s' "$ANSWER" | tail -n1)
REPLY=$(printf '%s' "$ANSWER" | sed '$d')
if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
  echo "✓ stored: the row now sits under the wallet's own account for $PROJECT."
  echo "  Call the connector with X-Use-Owner-Secret: 1 and no secrets_ref."
else
  echo "The store did not land (HTTP $STATUS). The endpoint's answer names what it wants:"
  printf '%s\n' "$REPLY" | head -5
  echo "The refresh token is NOT lost — it is held in scripts/.env as X_REFRESH_TOKEN"
  echo "(chmod 600, gitignored) so you can store the row by hand or re-run once the"
  echo "body shape is right. Delete the line when the row is stored."
  umask 077
  printf '%s\n' "$TOKEN_ANSWER" | python3 -c 'import sys,json; print("X_REFRESH_TOKEN=" + json.load(sys.stdin)["refresh_token"])' >> scripts/.env
  exit 1
fi
