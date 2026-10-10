#!/usr/bin/env bash
# Full AgentDojo agent-mode run against a local model, safe to leave overnight.
#
#   benchmarkv2/agentdojo/run_overnight.sh setup    # venv, agentdojo, sidecar, preflight
#   benchmarkv2/agentdojo/run_overnight.sh pilot    # 24 cases, about a minute
#   benchmarkv2/agentdojo/run_overnight.sh full     # every suite; rerun to resume
#
# Settings, as environment variables:
#   MODEL     model id the server reports           (default gemma4)
#   BASE_URL  OpenAI-compatible endpoint            (default http://localhost:8000/v1)
#   ARMS      comma list of arms                    (default none,detect,gate-task,full-task,full-task-taint)
#   WORKERS   cases run at once                     (default 4)
#   PYTHON    interpreter used to create the venv   (default python3)
#   TOOL_CALLING  native, or prompt for a server with tool calling off (default native)
#
# `full` picks a results directory once and records it in .overnight-run, so
# running `full` again continues that run: finished cases are kept, and cases
# that errored are tried again. Delete .overnight-run to start a new run.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL="${MODEL:-gemma4}"
BASE_URL="${BASE_URL:-http://localhost:8000/v1}"
ARMS="${ARMS:-none,detect,gate-task,full-task,full-task-taint}"
WORKERS="${WORKERS:-4}"
PYTHON="${PYTHON:-python3}"
TOOL_CALLING="${TOOL_CALLING:-native}"
AGENTDOJO_VERSION="0.1.35"
MARKER="$HERE/.overnight-run"

if [ -x "$HERE/.venv/Scripts/python.exe" ]; then
    VENV_PY="$HERE/.venv/Scripts/python.exe"   # Windows
else
    VENV_PY="$HERE/.venv/bin/python"
fi
RUN=("$VENV_PY" "$HERE/run_agentdojo.py" --mode agent --model "$MODEL" --base-url "$BASE_URL" \n     --tool-calling "$TOOL_CALLING")

need_setup() {
    [ -x "$VENV_PY" ] || { echo "run '$0 setup' first" >&2; exit 1; }
}

case "${1:-}" in
setup)
    command -v go >/dev/null || { echo "Go is needed to build the sidecar: https://go.dev/dl/" >&2; exit 1; }
    if [ ! -x "$VENV_PY" ]; then
        "$PYTHON" -m venv "$HERE/.venv"
        [ -x "$HERE/.venv/bin/python" ] && VENV_PY="$HERE/.venv/bin/python"
    fi
    "$VENV_PY" -m pip install --quiet "agentdojo==$AGENTDOJO_VERSION" pytest
    "$VENV_PY" "$HERE/run_agentdojo.py" --dry-run --build-sidecar
    "$VENV_PY" -m pytest "$HERE" "$HERE/../common" -q -p no:cacheprovider
    echo "setup done. Next: $0 pilot"
    ;;
pilot)
    need_setup
    "${RUN[@]}" --suites banking --user-tasks user_task_0,user_task_1,user_task_2 \
        --injection-tasks injection_task_0,injection_task_4,injection_task_7 \
        --arms none,full-task-taint --workers "$WORKERS"
    echo "Open summary.md in the results directory above: Errors must be 0, and ASR in"
    echo "the 'none' row must be above 0 (the attacks reach the model). Then: $0 full"
    ;;
full)
    need_setup
    if [ -f "$MARKER" ]; then
        echo "continuing $(cat "$MARKER")"
    else
        echo "$HERE/results/$(date -u +%Y%m%dT%H%M%SZ)-agent-$MODEL" > "$MARKER"
    fi
    "${RUN[@]}" --arms "$ARMS" --workers "$WORKERS" --resume "$(cat "$MARKER")"
    ;;
*)
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
