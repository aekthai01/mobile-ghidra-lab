#!/usr/bin/env bash
set -euo pipefail
GHIDRA_HOME="$1"; PROJECT_DIR="$2"; PROJECT_NAME="$3"; PROGRAM_NAME="$4"; OUT="$5"
"$GHIDRA_HOME/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" -process "$PROGRAM_NAME" -noanalysis \
  -scriptPath "$GITHUB_WORKSPACE/ghidra_scripts" \
  -postScript ExportV4Selected.java "$OUT" "$OUT/v52_selected_functions.csv" 1800 20 \
  -postScript ExportV51RawPcode.java "$OUT" "$OUT/v52_selected_functions.csv" 420 40000 120000 6000000 \
  -postScript ExportV51HighPcode.java "$OUT" "$OUT/v52_selected_functions.csv" 220 25 80000 2500000 \
  -postScript ExportV54ProtectedEvidence.java "$OUT" "$OUT/v52_protected_functions.csv" \
  -deleteProject > "$OUT/ghidra_selected.log" 2>&1
test -s "$OUT/v4_selected_export.csv"
test -s "$OUT/v51_raw_pcode.csv"
test -s "$OUT/v51_high_pcode_summary.csv"
test -s "$OUT/v54_protected_evidence_summary.csv"
