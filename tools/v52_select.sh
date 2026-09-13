#!/usr/bin/env bash
set -euo pipefail
OUT="$1"
python tools/v4_select_targets.py "$OUT" > "$OUT/v4_select.log"
python tools/v51_rank_targets.py "$OUT" > "$OUT/v51_rank.log"
python tools/priority_bias.py "$OUT" > "$OUT/v52_complexity.log"
python tools/v52_reselect.py "$OUT" > "$OUT/v52_reselect.log"
test -s "$OUT/v52_selected_functions.csv"
test -s "$OUT/v52_protected_functions.csv"
cp "$OUT/v52_selected_functions.csv" "$OUT/v51_selected_functions.csv"
cp "$OUT/v52_selected_functions.csv" "$OUT/v5_selected_functions.csv"
cp "$OUT/v52_selected_functions.csv" "$OUT/v4_selected_functions.csv"
