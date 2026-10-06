#!/bin/bash
# Build the x connector's wasm and hold it to everything a connector must be.
#
# Fail-closed, modeled on the platform's own connectors (gmail-connector,
# connector-probe in out-layer/outlayer):
#
#   * the manifest must be INSIDE the wasm (`outlayer.manifest` custom
#     section) — a connector without it reaches nothing, and a build that
#     dropped it must never publish;
#   * the manifest, the code and the README must agree on the operations;
#   * the words the manifest uses must be words the platform knows;
#   * `describe` must describe what the code dispatches, with parameters
#     that are fields of an input struct;
#   * the artefact must import the host interfaces its code depends on;
#   * the SHA256 is what `add_version` records and the worker verifies.
set -e

cd "$(dirname "$0")"

# A workspace member builds into the workspace root's target/.
WASM_FILE="../target/wasm32-wasip2/release/x-connector.wasm"
MAX_SIZE=$((2 * 1024 * 1024))  # 2MB in bytes

echo "Building WASI module (wasm32-wasip2)..."
rustup target add wasm32-wasip2 2>/dev/null || true

# A post the owner confirms is a task: without the manifest's word the
# platform refuses every such ask.
if ! python3 -c 'import json,sys; sys.exit(0 if json.load(open("manifest.json")).get("tasks") is True else 1)'; then
    echo 'ERROR: the manifest does not say "tasks": true, and `post` may ask the owner through tasks'
    exit 1
fi

cargo build --target wasm32-wasip2 --release
echo ""

SIZE=$(stat -f%z "$WASM_FILE" 2>/dev/null || stat -c%s "$WASM_FILE" 2>/dev/null)
echo "WASM module: $WASM_FILE"
echo "Size: $((SIZE / 1024)) KB"

# The manifest must be in the artefact: it is the outbound allowlist the
# worker enforces, and it is covered by the SHA256 below.
if ! grep -qa 'outlayer.manifest' "$WASM_FILE"; then
    echo "ERROR: outlayer.manifest custom section is missing from $WASM_FILE"
    echo "The connector would publish with no allowlist and reach nothing."
    exit 1
fi
echo "Manifest section: present"

# A confirmed post is a task: without the import the owner's confirmation
# cannot be asked for.
if ! command -v wasm-tools >/dev/null 2>&1; then
    echo "ERROR: wasm-tools is not installed; it checks that $WASM_FILE imports outlayer:tasks"
    echo "  cargo install --locked cargo-binstall && cargo binstall wasm-tools"
    echo "  (or: cargo install wasm-tools)"
    exit 1
fi
if ! wasm-tools component wit "$WASM_FILE" 2>/dev/null | grep -q "outlayer:tasks"; then
    echo "ERROR: $WASM_FILE does not import outlayer:tasks"
    exit 1
fi
echo "OK: outlayer:tasks is imported"

# The manifest's operations must be exactly the ones the code dispatches on,
# and its limit words must be ones the platform knows.
python3 - manifest.json src/main.rs README.md <<'PY'
import json, re, sys
m = json.load(open(sys.argv[1]))
src = open(sys.argv[2]).read()
readme = open(sys.argv[3]).read()
declared = set(m["operations"])
advertised = set(re.findall(r'"([a-z_]+)"', re.search(r'const OPERATIONS.*?\];', src, re.S).group(0)))
# `answer` takes `confirm`, whose refusal names a notice; `run` takes the rest.
dispatched = set(n for f in ("answer", "run")
                 for n in re.findall(r'^\s*"([a-z_]+)" => ', re.search(r'fn ' + f + r'\(.*?\n\}\n', src, re.S).group(0), re.M))
WINDOWS = {"day", "week", "month"}; APPLIES = {"everyone", "unpaid", "covered"}
bad = []
if declared != advertised:
    bad.append(f"manifest {sorted(declared)} vs the OPERATIONS list {sorted(advertised)}")
if declared != dispatched:
    bad.append(f"manifest {sorted(declared)} vs dispatched {sorted(dispatched)}")
for limit in m.get("limits", []):
    if limit.get("window") not in WINDOWS:
        bad.append(f"window {limit.get('window')!r}")
    if limit.get("applies", "everyone") not in APPLIES:
        bad.append(f"applies {limit.get('applies')!r}")
    if limit.get("operation", "").split(":")[0] not in declared:
        bad.append(f"limit on unknown operation {limit.get('operation')!r}")
# An account connected through the connect page stores only a refresh token,
# and OUR OAuth client completes it at run time. That client reaches a run
# only as this connector's author secret.
profile = (m.get("author_secrets") or {}).get("profile")
if not isinstance(profile, str) or not profile.strip():
    bad.append("author_secrets.profile: a connected account brings only a refresh token, and the OAuth client that completes it arrives only as an author secret")
# Every dispatched operation must be documented in the README: one nobody
# documented is one nobody will ever call.
if declared - {op for op in declared if re.search(r"`" + re.escape(op) + r"`", readme)}:
    bad.append("operations missing from README.md: %s" % sorted(declared - {op for op in declared if re.search(r"`" + re.escape(op) + r"`", readme)}))
# `describe`: what the developer page shows. Held to the code here — every
# dispatched operation described and nothing else, every parameter a field
# some input struct declares.
import glob
desc = m.get("describe") or {}
described = set((desc.get("operations") or {}).keys())
if described != dispatched:
    bad.append(f"describe.operations {sorted(described)} vs dispatched {sorted(dispatched)}")
if not isinstance(desc.get("summary"), str) or not desc.get("summary", "").strip():
    bad.append("describe.summary is missing")
fields = set()
for f in glob.glob("src/**/*.rs", recursive=True):
    text = open(f).read()
    for body in re.findall(r'struct \w*Input(?:<[^>]*>)?\s*\{(.*?)\n\s*\}', text, re.S):
        fields |= set(re.findall(r'^\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([a-z]+\))? )?([a-z_][a-z0-9_]*)\s*:', body, re.M))
        fields |= set(re.findall(r'#\[serde\(rename = "([a-z_]+)"', body))
    fields |= set(re.findall(r'\binput\s*\.get\("([a-z_]+)"\)', text))
for name, o in (desc.get("operations") or {}).items():
    if o.get("class") not in {"read", "write"}:
        bad.append(f"describe.{name}.class {o.get('class')!r}")
    if not isinstance(o.get("doc"), str) or not o["doc"].strip():
        bad.append(f"describe.{name}.doc is missing")
    for prm in o.get("params", []):
        if prm.get("name") not in fields:
            bad.append(f"describe.{name}: parameter {prm.get('name')!r} is not a field of any input struct")
        if not isinstance(prm.get("type"), str):
            bad.append(f"describe.{name}.{prm.get('name')}: no type")
if bad:
    print("ERROR:"); [print("  -", b) for b in bad]; sys.exit(1)
print(f"Manifest: {len(declared)} operations agree with the code and the README; limits are well formed")
PY

HASH=$(shasum -a 256 "$WASM_FILE" | cut -d' ' -f1)
echo "SHA256: $HASH"

if [ "$SIZE" -gt "$MAX_SIZE" ]; then
    echo "ERROR: Size exceeds the 2MB FastFS limit"
    exit 1
fi
echo "OK: Size is within 2MB limit for FastFS"
