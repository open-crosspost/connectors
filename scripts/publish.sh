#!/usr/bin/env bash
#
# Publish a connector of this family to OutLayer, the way the platform's own
# connectors are published (connector-probe/README.md in out-layer/outlayer).
#
#   scripts/publish.sh <connector-dir> [testnet|mainnet] [build|upload|version|activate|rollback|status]
#
# The one hard part of publishing a connector: the project id must be
# `connectors.outlayer.<suffix>/<connector_id>`, and `outlayer deploy` signs as
# the one identity the CLI has stored — so running it publishes
# `<you>/<connector_id>`, a project the registry does not recognise as a
# connector, with no price and no fee. The version has to be added BY the
# namespace account, which means near-cli:
#
#   upload    — anyone with a NEAR key may do it (FastFS; the uploader shows in
#               the URL only, the contract records url + hash, the worker
#               verifies the hash);
#   version   — signed by connectors.outlayer.<suffix>, with set_active: false
#               first: nothing any caller runs changes until the activation,
#               the previous version stays published, and a rollback is one
#               set_active_version;
#   activate  — signed by connectors.outlayer.<suffix>; `version_key` IS the
#               wasm hash;
#   rollback  — activate a prior version, one call.
#
# A new OPERATION also needs its price row (x/set-prices.sh, signed by the
# contract owner), or the coordinator refuses it with `unknown_operation`
# however good the wasm is; that table is cached for up to a minute.
#
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }

DIR="${1:?usage: scripts/publish.sh <connector-dir> [testnet|mainnet] [build|upload|version|activate|rollback|status]}"
NETWORK="${2:-testnet}"
STEP="${3:-all}"

case "$NETWORK" in
  testnet) SUFFIX=testnet; CONTRACT=outlayer.testnet ;;
  mainnet) SUFFIX=near; CONTRACT=outlayer.near ;;
  *) die "network must be testnet or mainnet" ;;
esac

cd "$(dirname "$0")/.."
DIR="${DIR%/}"
CONNECTOR_ID=$(python3 -c "import json,sys; print(json.load(open('$DIR/manifest.json'))['connector_id'])")
NAMESPACE="connectors.outlayer.$SUFFIX"
PROJECT="$NAMESPACE/$CONNECTOR_ID"

# The crate name inside the connector dir, for the wasm path.
case "$DIR" in
  x)          CRATE=x-connector ;;
  farcaster)  CRATE=farcaster-connector ;;
  *) die "no wasm path known for $DIR — add it to this script" ;;
esac
# publish.sh runs from the repo root; a workspace member builds into the
# ROOT's target/, a standalone crate into its own dir. Prefer the fresh one.
WASM_ROOT="target/wasm32-wasip2/release/$CRATE.wasm"
WASM_OWN="$DIR/target/wasm32-wasip2/release/$CRATE.wasm"
if [ -f "$WASM_ROOT" ] && [ -f "$WASM_OWN" ]; then
  WASM_FILE=$([ "$WASM_ROOT" -nt "$WASM_OWN" ] && echo "$WASM_ROOT" || echo "$WASM_OWN")
elif [ -f "$WASM_OWN" ]; then WASM_FILE="$WASM_OWN"; else WASM_FILE="$WASM_ROOT"; fi

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is not installed — the runbook names how"; }
need python3; need shasum
case "$STEP" in build|all) need cargo ;; esac
case "$STEP" in upload|all) need outlayer ;; esac
case "$STEP" in version|activate|rollback|all) need near ;; esac

manifest_section_present() { grep -qa 'outlayer.manifest' "$1"; }

build_step() {
  echo "== Building $CONNECTOR_ID (the fail-closed checks run inside build.sh)"
  "$DIR/build.sh"
  manifest_section_present "$WASM_FILE" || die "the built wasm carries no outlayer.manifest section"
  HASH=$(shasum -a 256 "$WASM_FILE" | cut -d' ' -f1)
  echo "SHA256: $HASH"
  echo "WASM:   $WASM_FILE"
}

case "$STEP" in
  build)
    build_step
    exit 0
    ;;

  upload)
    [ -f "$WASM_FILE" ] || build_step
    echo "== Uploading to FastFS (the uploader shows in the URL only)"
    outlayer upload "$WASM_FILE"
    echo "Record the URL + the SHA256 above for the version step."
    exit 0
    ;;
esac

case "$STEP" in
  version)
    URL="${URL:?set URL to the FastFS url outlayer upload printed}"
    HASH="${HASH:?set HASH to the wasm's SHA256}"
    manifest_section_present "$WASM_FILE" || die "the wasm to version carries no manifest section"
    echo "== Adding version of $PROJECT (set_active: false — nothing runs until the activation)"
    near contract call-function as-transaction "$CONTRACT" add_version \
      json-args "{\"project_name\":\"$CONNECTOR_ID\",
                  \"source\":{\"WasmUrl\":{\"url\":\"$URL\",\"hash\":\"$HASH\",\"build_target\":\"wasm32-wasip2\"}},
                  \"set_active\":false}" \
      prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \
      sign-as "$NAMESPACE" network-config "$NETWORK" sign-with-legacy-keychain send
    echo "Then check the URL really serves those bytes, then: scripts/publish.sh $DIR $NETWORK activate HASH=<hash>"
    ;;

  activate)
    HASH="${HASH:?set HASH to the version_key — the wasm's SHA256}"
    echo "== Activating $PROJECT at $HASH"
    near contract call-function as-transaction "$CONTRACT" set_active_version \
      json-args "{\"project_name\":\"$CONNECTOR_ID\",\"version_key\":\"$HASH\"}" \
      prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
      sign-as "$NAMESPACE" network-config "$NETWORK" sign-with-legacy-keychain send
    ;;

  rollback)
    HASH="${HASH:?set HASH to the PRIOR version_key — a rollback is one set_active_version}"
    echo "== Rolling $PROJECT back to $HASH"
    near contract call-function as-transaction "$CONTRACT" set_active_version \
      json-args "{\"project_name\":\"$CONNECTOR_ID\",\"version_key\":\"$HASH\"}" \
      prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
      sign-as "$NAMESPACE" network-config "$NETWORK" sign-with-legacy-keychain send
    ;;

  status)
    echo "== $PROJECT"
    near view "$CONTRACT" get_project_version "{\"project_id\": \"$PROJECT\"}" --networkId "$NETWORK" 2>/dev/null \
      || near view "$CONTRACT" get_version "{\"project_id\": \"$PROJECT\"}" --networkId "$NETWORK" 2>/dev/null \
      || echo "(no view call known for the active version — read it in the dashboard)"
    ;;

  all)
    die "publishing a connector has human steps in it (the namespace account signs, the price rows follow, the runbook checks each refusal): run build → upload → version → activate one at a time, with x/set-prices.sh between version and activate"
    ;;
esac
