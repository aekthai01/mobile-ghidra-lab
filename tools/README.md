# Tools used by V5.5

Do not infer whether a file is active from the version number in its filename. V5.5 deliberately reuses proven V4/V5.1/V5.2 analysis stages.

## Entry point

`run_v55_pipeline.sh` is the only shell orchestrator used by the active GitHub Actions workflow.

## Active stages

Selection/ranking: `v4_select_targets.py`, `v51_rank_targets.py`, `priority_bias.py`, `v52_reselect.py`.

ARM64/CFG/protected flow: `v5_arm64_flow.py`, `v5_validate_tables.py`, `v52_selector_labels.py`, `v51_runtime_tables.py`, `v52_protected_regions.py`, `v52_coverage.py`.

P-code/quality/context: `v51_high_pcode_slices.py`, `v51_quality.py`, `v51_ai_context.py`, `v4_callgraph.py`.

Human/preservation: `v53_enrich_asm.py`, `v53_human_pack.py`, `v54_protected_pack.py`.

V5.5: `v55_region_reconstruct.py`, `v55_ida_pack.py`.

ELF/preflight: `preflight_obfuscation.py`, `elf_report.py`.

## Retained research utilities

`arm64_deflatten_report.py`, `arm64_obfuscation_report.py`, `deep_report.py`, and `third_party_filter.py` are not required by the active workflow, but are retained because they provide distinct manual research capability rather than duplicating the pipeline.
