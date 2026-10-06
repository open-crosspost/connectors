#!/usr/bin/env bash
#
# Put the x connector's prices on chain and tell the coordinator to read
# them, in one run.
#
# Prices live on chain, not in the manifest: the contract is what the coordinator
# charges by, and the coordinator keeps a cached copy it refreshes on demand.
# Both halves are here so the two cannot be left disagreeing.
#
# Modeled on the platform's own connectors (gmail-connector/set-prices.sh in
# out-layer/outlayer). The priced operations must be exactly the manifest's:
# an operation priced but not implemented is money for nothing, and one
# implemented but unpriced is refused `unknown_operation` before it runs.
#
# Usage:
#   x/set-prices.sh [testnet|mainnet]
#
#   CONTRACT=outlayer.testnet \
#   OWNER=<the contract owner account that signs this call> \
#   ADMIN_TOKEN=<coordinator admin bearer> \
#   API=https://testnet-api.outlayer.ai \
#   x/set-prices.sh testnet
#
# Prerequisites, in order:
#   1. the contract is at the storage version with `project_pricing`;
#   2. `connectors.outlayer.<suffix>/x` is published — `set_project_pricing`
#      refuses a project nobody registered.
#
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cd "$(dirname "$0")"

NETWORK="${1:-testnet}"
case "$NETWORK" in
  testnet) NETWORK_ID=testnet; SUFFIX=testnet; DEFAULT_CONTRACT=outlayer.testnet;
     ADMIN_TOKEN_FROM_ENV="${ADMIN_BEARER_TOKEN_TESTNET:-}"; API_FROM_ENV="${COORDINATOR_URL_TESTNET:-}" ;;
  mainnet) NETWORK_ID=mainnet; SUFFIX=near; DEFAULT_CONTRACT=outlayer.near;
     ADMIN_TOKEN_FROM_ENV="${ADMIN_BEARER_TOKEN_MAINNET:-}"; API_FROM_ENV="${COORDINATOR_URL_MAINNET:-}" ;;
  *) echo "ERROR: network must be testnet or mainnet" >&2; exit 1 ;;
esac

CONTRACT="${CONTRACT:-$DEFAULT_CONTRACT}"
OWNER="${OWNER:?set OWNER to the contract owner account that signs this call}"
NAMESPACE="connectors.outlayer.$SUFFIX"
PROJECT="$NAMESPACE/x"
# Who is credited the author's share. Ours, so the share is zero and the whole
# fee stays with the project's owner — the shape of every connector we own.
AUTHOR="${AUTHOR:-$NAMESPACE}"
ADMIN_TOKEN="${ADMIN_TOKEN:-$ADMIN_TOKEN_FROM_ENV}"
API="${API:-$API_FROM_ENV}"

# The priced operations must be exactly the manifest's.
python3 - "$SELF" manifest.json <<'PYCHECK'
import json, re, sys
priced = set(re.findall(r'\{"operation": "([a-z_]+)"', open(sys.argv[1]).read()))
declared = set(json.load(open(sys.argv[2]))["operations"])
if priced != declared:
    print(f"ERROR: priced {sorted(priced)} vs manifest {sorted(declared)}"); sys.exit(1)
print(f"Manifest: {len(declared)} operations agree with the price list")
PYCHECK

# `status` and `me` are free, so an agent can see its own limits and the
# connected handle before spending anything. `post` is a cent, paid by whoever
# asks for it: the agent. The owner's `confirm` of a post already paid for is
# free, and so is asking where a task stands.
near call "$CONTRACT" set_project_pricing "$(cat <<JSON
{
  "project_id": "$PROJECT",
  "pricing": {
    "author_account_id": "$AUTHOR",
    "operations": [
      {"operation": "status",       "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "me",           "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "post",         "price_usd": "10000", "developer_share_bp": 0},
      {"operation": "confirm",      "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "task_status",  "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "task_cancel",  "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "task_delete",  "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "tasks",        "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "tasks_unlock", "price_usd": "0",     "developer_share_bp": 0}
    ]
  }
}
JSON
)" --accountId "$OWNER" --networkId "$NETWORK_ID"

echo
near view "$CONTRACT" get_project_pricing "{\"project_id\": \"$PROJECT\"}" --networkId "$NETWORK_ID"

# The coordinator charges from its cached copy, so a price nobody refreshed is a
# price nobody charges.
echo
if [ -n "$ADMIN_TOKEN" ] && [ -n "$API" ]; then
    echo "Refreshing $API/admin/connector-prices/refresh"
    curl -fsS -X POST "$API/admin/connector-prices/refresh" -H "Authorization: Bearer $ADMIN_TOKEN" && echo
    echo "Done: the on-chain row and the coordinator agree"
else
    echo "NOT refreshed: no admin token or API URL. Run it yourself, or the coordinator keeps charging the old prices:"
    echo "  curl -X POST \$API/admin/connector-prices/refresh -H \"Authorization: Bearer \$ADMIN_TOKEN\""
fi
