#!/usr/bin/env bash
# Targeted Ghidra run: one import, only the requested functions, small artifact.
# usage: run_targeted.sh <ghidra-home> <project-dir> <project-name> <import-elf> <out-dir> <targets-file>
set -euo pipefail
if [[ $# -ne 6 ]]; then
  echo "usage: run_targeted.sh <ghidra-home> <project-dir> <project-name> <import-elf> <out-dir> <targets-file>" >&2
  exit 2
fi
GHIDRA_HOME="$1"; PROJECT_DIR="$2"; PROJECT_NAME="$3"; IMPORT="$4"; OUT="$5"; TARGETS="$6"
REPO_ROOT="${GITHUB_WORKSPACE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ANALYSIS_TIMEOUT="${MGL_ANALYSIS_TIMEOUT:-600}"
DECOMPILE_TIMEOUT="${MGL_DECOMPILE_TIMEOUT:-20}"
MAX_FUNCTIONS="${MGL_MAX_FUNCTIONS:-200}"
BUDGET_SEC="${MGL_BUDGET_SEC:-1800}"
export MAXMEM="${MGL_MAXMEM:-10G}"

mkdir -p "$PROJECT_DIR" "$OUT/targeted"
printf 'stage\tseconds\trc\n' > "$OUT/stage_times.tsv"
TIMINGS="$OUT/stage_times.tsv"

stage() {
  local name="$1"; shift
  local t0; t0=$(date +%s)
  local rc=0
  "$@" || rc=$?
  printf '%s\t%s\t%s\n' "$name" "$(( $(date +%s) - t0 ))" "$rc" >> "$TIMINGS"
  return $rc
}

echo "[targeted] import=$(basename "$IMPORT") analysisTimeout=${ANALYSIS_TIMEOUT}s maxFunctions=${MAX_FUNCTIONS} budget=${BUDGET_SEC}s MAXMEM=${MAXMEM}"
stage ghidra_import_and_targeted \
  "$GHIDRA_HOME/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" \
  -import "$IMPORT" \
  -analysisTimeoutPerFile "$ANALYSIS_TIMEOUT" \
  -scriptPath "$REPO_ROOT/ghidra_scripts" \
  -postScript ExportTargeted.java "$OUT" "$TARGETS" "$DECOMPILE_TIMEOUT" "$MAX_FUNCTIONS" "$BUDGET_SEC" \
  -deleteProject > "$OUT/ghidra_targeted.log" 2>&1

test -s "$OUT/targeted_index.csv"
echo "[targeted] stage timings:"
cat "$TIMINGS"
echo "[targeted] done"
