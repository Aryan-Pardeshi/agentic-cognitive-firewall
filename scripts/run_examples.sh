#!/usr/bin/env bash
# Run every example against a real sidecar. Exits non-zero if any example fails.
#
#   scripts/run_examples.sh            # builds the sidecar into bin/ first
#   ACF_SIDECAR_BIN=path scripts/run_examples.sh   # or uses a given binary
#
# The basics run against the shipped policy; the banking examples, the LangChain
# example (if langchain-core is installed) and the TypeScript example (if the
# TypeScript SDK is built) run against the banking application policy.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
command -v "$PYTHON" >/dev/null || PYTHON=python
EXE=""
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;; esac
LOG="$ROOT/bin/examples-sidecar.log"

# Always build from the checked-out source unless a binary is named: a stale
# binary left in bin/ would run the examples against old behaviour.
if [ -n "${ACF_SIDECAR_BIN:-}" ]; then
    BIN="$ACF_SIDECAR_BIN"
else
    BIN="$ROOT/bin/acf-sidecar$EXE"
    echo "building the sidecar into $BIN"
    (cd "$ROOT/sidecar" && go build -o "$BIN" ./cmd/sidecar)
fi
export ACF_HMAC_KEY="${ACF_HMAC_KEY:-$("$PYTHON" -c 'import secrets; print(secrets.token_hex(32))')}"
export PYTHONPATH="$ROOT/sdk/python${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONIOENCODING=utf-8

SIDECAR_PID=""
start_sidecar() {
    mkdir -p "$(dirname "$LOG")"
    (cd "$ROOT/sidecar" && ACF_CONFIG="$1" exec "$BIN") >"$LOG" 2>&1 &
    SIDECAR_PID=$!
    # Ready when a signed request gets a decision back.
    "$PYTHON" - <<'EOF' || { echo "sidecar did not start:"; tail -5 "$LOG"; exit 1; }
import time
from acf import Firewall
for _ in range(60):
    try:
        Firewall().on_prompt("ping")
        break
    except Exception:
        time.sleep(0.5)
else:
    raise SystemExit(1)
EOF
}
stop_sidecar() {
    if [ -n "$SIDECAR_PID" ]; then kill "$SIDECAR_PID" 2>/dev/null || true; wait "$SIDECAR_PID" 2>/dev/null || true; fi
    SIDECAR_PID=""
}
trap stop_sidecar EXIT

FAILED=()
run() {
    echo "── $*"
    if ! "$@"; then FAILED+=("$*"); fi
}

start_sidecar "$ROOT/config/sidecar.yaml"
for f in "$ROOT"/examples/basics/0*.py; do run "$PYTHON" "$f"; done
stop_sidecar

"$PYTHON" "$ROOT/examples/banking/run_sidecar.py" --build-only >/dev/null
start_sidecar "$ROOT/examples/banking/.policy/sidecar.yaml"
for f in "$ROOT"/examples/banking/0*.py; do (cd "$ROOT/examples/banking" && run "$PYTHON" "$(basename "$f")") || FAILED+=("$f"); done
if "$PYTHON" -c "import langchain_core" 2>/dev/null; then
    run "$PYTHON" "$ROOT/examples/adapters/langchain_guarded_tools.py"
else
    echo "── skipping the LangChain example: langchain-core is not installed"
fi
if command -v node >/dev/null && [ -f "$ROOT/sdk/typescript/dist/index.js" ]; then
    run node "$ROOT/examples/typescript/provenance.js"
else
    echo "── skipping the TypeScript example: node or sdk/typescript/dist is missing"
fi
stop_sidecar

if [ "${#FAILED[@]}" -gt 0 ]; then
    echo "FAILED: ${FAILED[*]}"
    exit 1
fi
echo "all examples passed"
