#!/usr/bin/env bash
#
# Call the x connector — either shape, one wrapper.
#
#   scripts/x-run.sh <project> '<operation-json>' [--payment-key KEY] [--account ACCOUNT] [--profile PROFILE]
#
#   <project>        connectors.outlayer.near/x (curated) — or <you>/x (preview)
#   <operation-json> e.g. '{"operation":"status"}'
#
# The credential shape follows the project:
#   * under the curated namespace  → `X-Use-Owner-Secret: 1`, no `secrets_ref`
#     (the row lives under the wallet's own account — the agent-secret route);
#   * anywhere else (the preview)  → `secrets_ref` naming the row instead: the
#     header does nothing on a project that is not a connector. The account is
#     auto-fetched from the wallet (GET /wallet/v1/address) unless --account
#     overrides it; the profile defaults to that account too — the shape the
#     agent-secret row is stored under. A row stored by hand has the label its
#     storer chose — pass --profile for that.
#
# Payment: X-Payment-Key (a key the wallet owns) is always sent — free
# operations reserve compute. The trial key reaches curated connectors only.
#
# env: OUTLAYER_PAYMENT_KEY (or --payment-key), OUTLAYER_WALLET_API_KEY
# (wk_ — used to auto-fetch the account), OUTLAYER_API (default mainnet).
#
set -euo pipefail

cd "$(dirname "$0")/.."
[ -f scripts/.env ] && set -a && . scripts/.env && set +a

die() { echo "ERROR: $*" >&2; exit 1; }
command -v curl >/dev/null || { echo "ERROR: curl required"; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: python3 required"; exit 1; }

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
[ $# -ge 2 ] || usage

PROJECT="$1"; shift
INPUT="$1"; shift

PAYMENT_KEY="${OUTLAYER_PAYMENT_KEY:-}"
ACCOUNT="${OUTLAYER_WALLET_ACCOUNT:-}"
PROFILE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --payment-key) PAYMENT_KEY="$2"; shift 2 ;;
    --account)     ACCOUNT="$2"; shift 2 ;;
    --profile)     PROFILE="$2"; shift 2 ;;
    *) usage ;;
  esac
done
PAYMENT_KEY="${PAYMENT_KEY:?set OUTLAYER_PAYMENT_KEY in scripts/.env or pass --payment-key (owner:nonce:key — outlayer keys show prints yours)}"

OUTLAYER_API="${OUTLAYER_API:-https://api.outlayer.ai}"

case "$PROJECT" in
  connectors.outlayer.*)
    MODE="curated"
    ;;
  *)
    MODE="preview"
    if [ -z "$ACCOUNT" ]; then
      echo "== Reading the wallet's account (GET /wallet/v1/address)"
      : "${OUTLAYER_WALLET_API_KEY:?set OUTLAYER_WALLET_API_KEY in scripts/.env (the wk_ that pays) or pass --account}"
      ACCOUNT=$(curl -s -H "Authorization: Bearer $OUTLAYER_WALLET_API_KEY" \
        "$OUTLAYER_API/wallet/v1/address?chain=near" \
        | python3 -c 'import sys,json; print(json.load(sys.stdin)["address"])')
      [ -n "$ACCOUNT" ] || die "could not read the wallet's account"
      echo "  account: $ACCOUNT"
    fi
    PROFILE="${PROFILE:-$ACCOUNT}"
    ;;
esac

BODY=$(python3 - "$INPUT" "$MODE" "$ACCOUNT" "$PROFILE" <<'PY'
import sys, json
input_json, mode, account, profile = sys.argv[1:5]
body = {"input": json.loads(input_json)}
if mode == "preview":
    body["secrets_ref"] = {"account_id": account, "profile": profile}
print(json.dumps(body))
PY
)

case "$MODE" in
  curated)
    echo "== Calling $PROJECT (X-Use-Owner-Secret: 1 — the agent-secret row)"
    HEADERS=(-H "X-Payment-Key: $PAYMENT_KEY" -H "X-Use-Owner-Secret: 1")
    ;;
  *)
    echo "== Calling $PROJECT (secrets_ref: $ACCOUNT/$PROFILE)"
    HEADERS=(-H "X-Payment-Key: $PAYMENT_KEY")
    ;;
esac

ANSWER=$(curl -s -w '\n%{http_code}' -X POST \
  "${HEADERS[@]}" -H "Content-Type: application/json" \
  -d "$BODY" "$OUTLAYER_API/call/$PROJECT")
HTTP=$(printf '%s' "$ANSWER" | tail -n1)
REPLY=$(printf '%s' "$ANSWER" | sed '$d')

echo "  HTTP $HTTP"
printf '%s\n' "$REPLY" | python3 -m json.tool 2>/dev/null || printf '%s\n' "$REPLY"

printf '%s' "$REPLY" | python3 -c '
import sys, json
try:
    answer = json.load(sys.stdin)
except Exception:
    sys.exit(0)
output = answer.get("output")
if isinstance(output, dict) and "success" in output:
    if output["success"]:
        print("✓ the connector answered success")
    else:
        error = output.get("error") or "(no error named)"
        print(f"✗ the connector refused: {error} — branch on its prefix (connector-core/src/refusal.rs)")
elif answer.get("status") == "failed":
    print(f"✗ the platform refused before the run: {answer.get(\"error\", \"\")}")' || true
