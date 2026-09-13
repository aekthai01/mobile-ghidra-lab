#!/usr/bin/env bash
set -euo pipefail
GHIDRA_HOME="$1"; PROJECT_DIR="$2"; PROJECT_NAME="$3"; IMPORT="$4"; OUT="$5"
"$GHIDRA_HOME/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" -import "$IMPORT" \
  -scriptPath "$GITHUB_WORKSPACE/ghidra_scripts" -analysisTimeoutPerFile 2400 \
  -postScript ExportAnalysis.java "$OUT" 0 90 1 \
  -postScript ExportV51Refs.java "$OUT" > "$OUT/ghidra_inventory.log" 2>&1
test -s "$OUT/functions.csv"
test -s "$OUT/v51_function_refs.csv"
