#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 5 ]]; then
  echo "usage: run_v55_pipeline.sh <ghidra-home> <project-dir> <project-name> <import-elf> <output-dir>" >&2
  exit 2
fi
GHIDRA_HOME="$1"; PROJECT_DIR="$2"; PROJECT_NAME="$3"; IMPORT="$4"; OUT="$5"
REPO_ROOT="${GITHUB_WORKSPACE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PROGRAM_NAME="$(basename "$IMPORT")"
mkdir -p "$PROJECT_DIR" "$OUT"

echo "[v5.6] inventory + login/network seed discovery"
"$GHIDRA_HOME/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" -import "$IMPORT" -scriptPath "$REPO_ROOT/ghidra_scripts" -analysisTimeoutPerFile 2400 \
  -postScript ExportAnalysis.java "$OUT" 0 90 1 -postScript ExportV51Refs.java "$OUT" -postScript ExportV56LoginSeeds.java "$OUT" > "$OUT/ghidra_inventory.log" 2>&1
test -s "$OUT/functions.csv"; test -s "$OUT/v51_function_refs.csv"; test -s "$OUT/v56_login_seeds.csv"

echo "[v5.6] selection/ranking + 0x2712 login bias"
python "$REPO_ROOT/tools/v4_select_targets.py" "$OUT" > "$OUT/v4_select.log"
python "$REPO_ROOT/tools/v51_rank_targets.py" "$OUT" > "$OUT/v51_rank.log"
python "$REPO_ROOT/tools/priority_bias.py" "$OUT" > "$OUT/v52_complexity.log"
python "$REPO_ROOT/tools/v56_login_bias.py" "$OUT" > "$OUT/v56_login_bias.log"
python "$REPO_ROOT/tools/v52_reselect.py" "$OUT" > "$OUT/v52_reselect.log"
test -s "$OUT/v52_selected_functions.csv"; test -s "$OUT/v52_protected_functions.csv"; test -s "$OUT/v56_login_priority.json"
cp "$OUT/v52_selected_functions.csv" "$OUT/v51_selected_functions.csv"; cp "$OUT/v52_selected_functions.csv" "$OUT/v5_selected_functions.csv"; cp "$OUT/v52_selected_functions.csv" "$OUT/v4_selected_functions.csv"

echo "[v5.6] selective deep export + protected preservation + selected region fallback"
"$GHIDRA_HOME/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" -process "$PROGRAM_NAME" -noanalysis -scriptPath "$REPO_ROOT/ghidra_scripts" \
  -postScript ExportV4Selected.java "$OUT" "$OUT/v52_selected_functions.csv" 1800 20 \
  -postScript ExportV51RawPcode.java "$OUT" "$OUT/v52_selected_functions.csv" 420 40000 120000 6000000 \
  -postScript ExportV51HighPcode.java "$OUT" "$OUT/v52_selected_functions.csv" 220 25 80000 2500000 \
  -postScript ExportV56RegionC.java "$OUT" "$OUT/v52_selected_functions.csv" 20 20000 > "$OUT/ghidra_selected.log" 2>&1
test -s "$OUT/v4_selected_export.csv"; test -s "$OUT/v51_raw_pcode.csv"; test -s "$OUT/v51_high_pcode_summary.csv"; test -s "$OUT/v54_protected_evidence_summary.csv"; test -s "$OUT/v55_region_high_pcode_summary.csv"; test -s "$OUT/v56_region_c_index.csv"

# Validate the legacy deep-priority fallback before the all-function fallback replaces the region index.
python "$REPO_ROOT/tools/v56_c_coverage_validate.py" "$OUT" > "$OUT/v56_c_coverage_validate.log"
test -s "$OUT/v56_c_coverage_acceptance.json"

echo "[v5.6] All-C pass: every internal function, then exhaustive fallback only for whole-C failures"
"$GHIDRA_HOME/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" -process "$PROGRAM_NAME" -noanalysis -scriptPath "$REPO_ROOT/ghidra_scripts" \
  -postScript ExportV56AllC.java "$OUT" 6 \
  -postScript ExportV56RegionC.java "$OUT" "$OUT/v56_all_c_fallback.csv" 20 20000 \
  -deleteProject > "$OUT/ghidra_all_c.log" 2>&1
test -s "$OUT/v56_all_c_index.csv"; test -s "$OUT/v56_all_c_fallback.csv"; test -s "$OUT/v56_region_c_index.csv"
python "$REPO_ROOT/tools/v56_all_c_validate.py" "$OUT" > "$OUT/v56_all_c_validate.log"
test -s "$OUT/v56_all_c_acceptance.json"; test -s "$OUT/v56_all_c_acceptance.md"

echo "[v5.6] control-flow, C merge, and evidence enrichment"
python "$REPO_ROOT/tools/v5_arm64_flow.py" "$OUT" "$IMPORT" > "$OUT/v5_flow.log"
python "$REPO_ROOT/tools/v5_validate_tables.py" "$OUT" > "$OUT/v5_tables.log"
python "$REPO_ROOT/tools/v51_high_pcode_slices.py" "$OUT" > "$OUT/v51_high_slices.log"
python "$REPO_ROOT/tools/v52_selector_labels.py" "$OUT" > "$OUT/v52_selector_labels.log"
python "$REPO_ROOT/tools/v51_runtime_tables.py" "$OUT" > "$OUT/v51_runtime_tables.log"
python "$REPO_ROOT/tools/v52_protected_regions.py" "$OUT" > "$OUT/v52_protected_regions.log"
python "$REPO_ROOT/tools/v55_cfg_metrics.py" "$OUT" > "$OUT/v55_cfg.log"
python "$REPO_ROOT/tools/v55_native_data.py" "$IMPORT" "$OUT" > "$OUT/v55_native_data.log"
python "$REPO_ROOT/tools/v52_coverage.py" "$OUT" > "$OUT/v52_coverage.log"
python "$REPO_ROOT/tools/v51_quality.py" "$OUT" > "$OUT/v51_quality.log"
python "$REPO_ROOT/tools/v4_callgraph.py" "$OUT" > "$OUT/v52_callgraph.log" || true
python "$REPO_ROOT/tools/v51_ai_context.py" "$OUT" > "$OUT/v52_ai_context.log"
python "$REPO_ROOT/tools/v53_enrich_asm.py" "$OUT" > "$OUT/v53_enrich_asm.log"
python "$REPO_ROOT/tools/v53_human_pack.py" "$OUT" > "$OUT/v53_human_pack.log"
python "$REPO_ROOT/tools/v56_merge_region_c.py" "$OUT" > "$OUT/v56_merge_region_c.log"

echo "[v5.6] lossless validation + region SSA + ARM64-grounded semantic C + IDA interop"
python "$REPO_ROOT/tools/v54_protected_pack.py" "$OUT" > "$OUT/v54_protected_pack.log"
python "$REPO_ROOT/tools/v55_region_high_pcode_validate.py" "$OUT" > "$OUT/v55_region_high_pcode_validate.log"
python "$REPO_ROOT/tools/v55_merge_region_high_pcode.py" "$OUT" > "$OUT/v55_merge_region_high_pcode.log"
python "$REPO_ROOT/tools/v55_region_reconstruct.py" "$OUT" > "$OUT/v55_region_reconstruct.log"
python "$REPO_ROOT/tools/v55_ida_pack.py" "$OUT" > "$OUT/v55_ida_pack.log"
python "$REPO_ROOT/tools/v55_complete_views.py" "$OUT" > "$OUT/v55_complete_views.log"
python "$REPO_ROOT/tools/v55_semantic_c.py" "$OUT" "$IMPORT" > "$OUT/v55_semantic_c.log"
python "$REPO_ROOT/tools/v55_semantic_quality_v2.py" "$OUT" > "$OUT/v55_semantic_quality_v2.log"
python "$REPO_ROOT/tools/v55_semantic_validate.py" "$OUT" > "$OUT/v55_semantic_validate.log"
python "$REPO_ROOT/tools/v55_human_finalize.py" "$OUT" > "$OUT/v55_human_finalize.log"
python "$REPO_ROOT/tools/v55_validate.py" "$OUT" > "$OUT/v55_validate.log"

for f in v54_protected_manifest.json v55_region_high_pcode_acceptance.md v55_region_high_pcode_merge.json v55_region_map.csv v55_reconstruction_summary.csv v55_cfg_report.md v55_native_data_report.md v55_complete_views_report.md v55_complete_views_stats.json v55_semantic_c_report.md v55_semantic_c_stats.json v55_semantic_string_recovery.csv v55_semantic_quality_v2.json v55_semantic_quality_v2.md v55_semantic_acceptance.md v55_acceptance.md v56_c_coverage_acceptance.json v56_c_coverage_acceptance.md v56_all_c_acceptance.json v56_all_c_acceptance.md; do test -s "$OUT/$f"; done
for f in START_HERE.html V55_RECONSTRUCTION.html V55_SEMANTIC_C.html SEMANTIC_C_INDEX.csv V55_CFG.html V55_NATIVE_DATA.html OFFSET_LOOKUP.html OFFSET_MAP.txt FUNCTIONS_C.html FUNCTION_C_INDEX.csv ida/import_mobile_ghidra.py reconstructed_c_v56/V56_C_RECONSTRUCTION.md; do test -s "$OUT/human/$f"; done

echo "[v5.6] pipeline complete"
