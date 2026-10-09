#!/usr/bin/env bash
#
# Deploy the x connector as an ORDINARY project under your own account —
# the pre-activation e2e preview (docs/PREVIEW.md).
#
# The curated connector (`connectors.outlayer.near/x`) cannot exist before the
# namespace account signs its version; this preview needs nobody's signature:
# `outlayer deploy` publishes `<you>/x`, an ordinary project that runs the same
# wasm in the same TEE. Calling it takes `secrets_ref` and a funded key — the
# trial key reaches curated connectors only (docs/PREVIEW.md, "What this does
# not prove").
#
#   scripts/preview-deploy.sh [build|deploy]
#
# build — x/build.sh (the fail-closed checks run inside it), then print the
#         SHA256. deploy — upload to FastFS and `outlayer deploy` under your
#         own account. Redeploy any time an update lands: this project is
#         yours; no round-trip with anyone.
#
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is not installed — the runbook names how"; }

DIR="x"
CRATE="x-connector"

cd "$(dirname "$0")/.."
STEP="${1:-all}"

need outlayer; need shasum
case "$STEP" in build|all) need cargo; need python3 ;; esac

WASM_FILE="target/wasm32-wasip2/release/$CRATE.wasm"
[ -f "$WASM_FILE" ] || WASM_FILE="$DIR/target/wasm32-wasip2/release/$CRATE.wasm"

if [ "$STEP" = "build" ] || [ "$STEP" = "all" ]; then
  echo "== Building x (the fail-closed checks run inside build.sh)"
  "$DIR/build.sh"
  grep -qa 'outlayer.manifest' "$WASM_FILE" || die "the built wasm carries no outlayer.manifest section"
fi

if [ "$STEP" = "deploy" ] || [ "$STEP" = "all" ]; then
  [ -f "$WASM_FILE" ] || die "no wasm at $WASM_FILE — run scripts/preview-deploy.sh build first"
  HASH=$(shasum -a 256 "$WASM_FILE" | cut -d' ' -f1)

  echo "== Deploying as an ordinary project under your own account"
  outlayer whoami >/dev/null 2>&1 || die "outlayer is not logged in — run: outlayer login"
  OWNER=$(outlayer whoami 2>/dev/null | head -n1)
  echo "  account: $OWNER"

  echo "== Uploading the wasm to FastFS"
  URL=$(outlayer upload "$WASM_FILE" | sed -n 's|.*/\(https://[^ ]*\).*|\1|p')
  [ -n "$URL" ] || die "could not read the FastFS url outlayer upload printed — copy it by hand"
  echo "  url: $URL"
  echo "  sha256: $HASH"

  echo "== Deploying <you>/x from those bytes"
  outlayer deploy x "$URL" --hash "$HASH"

  PROJECT="$OWNER/x"
  echo
  echo "✓ deployed: $PROJECT runs the same wasm the curated connector will."
  echo "  Next (docs/PREVIEW.md has the full walkthrough):"
  echo "    1. row:        PROJECT=$PROJECT scripts/x-connect.sh"
  echo "    2. funded key: outlayer keys create && outlayer keys topup"
  echo "                    (the trial key reaches curated connectors only)"
  echo "    3. first call: scripts/x-run.sh $PROJECT '{\"operation\":\"status\"}'"
fi
