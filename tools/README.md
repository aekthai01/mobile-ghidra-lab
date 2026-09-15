# Tools used by V5.5

Do not infer whether a file is active from the version number in its filename. V5.5 deliberately reuses proven V4/V5.1/V5.2 analysis stages.

## Entry point

`run_v55_pipeline.sh` is the only shell orchestrator used by the active GitHub Actions workflow.

## Active stages

Selection/ranking: `v4_select_targets.py`, `v51_rank_targets.py`, `priority_bias.py`, `v52_reselect.py`.

ARM64/CFG/protected flow: `v5_arm64_flow.py`, `v5_validate_tables.py`, `v52_selector_labels.py`, `v51_runtime_tables.py`, `v52_protected_regions.py`, `v52_coverage.py`.

P-code/quality/context: `v51_high_pcode_slices.py`, `v51_quality.py`, `v51_ai_context.py`, `v4_callgraph.py`.

Human/preservation: `v53_enrich_asm.py`, `v53_human_pack.py`, `v54_protected_pack.py`.

V5.5 reconstruction/intelligence: `v55_cfg_metrics.py`, `v55_native_data.py`, `v55_region_reconstruct.py`, `v55_ida_pack.py`, `v55_complete_views.py`, `v55_semantic_c.py`, `v55_semantic_validate.py`, `v55_human_finalize.py`, `v55_validate.py`.

`v55_complete_views.py` closes the human-view coverage gap: every selected function receives one evidence-oriented C/C-like file and one full ARM64 file, while all disassembled instructions receive dual ELF/IDA-RVA and Ghidra-VA address aliases. The human artifact includes `OFFSET_LOOKUP.html`, `OFFSET_MAP.txt`, `offset_pages/`, `FUNCTIONS_C.html`, `functions_c/`, and `asm_full/`.

`v55_semantic_c.py` is the preferred analysis layer. It treats full ARM64 + CFG as authoritative, reconstructs code block-by-block, folds only evidence-backed ARM64 idioms, tracks observed AArch64 ABI arguments, handles common integer/SIMD/FP operations, recovers exact and interior strings, and optionally scans the analyzed ELF directly for printable strings missed by Ghidra. Instructions not safely lowered remain explicit `ARM64_*` statements instead of guessed C.

`v55_semantic_validate.py` prevents green-but-useless regressions: it requires semantic-C coverage for every selected function, exact CFG-block coverage for functions with CFG, rejects raw P-code-noise tokens from semantic output, and checks known stress semantics including the `0x19C094` path.

ELF/preflight: `preflight_obfuscation.py`, `elf_report.py`.

## Retained research utilities

`arm64_deflatten_report.py`, `arm64_obfuscation_report.py`, `deep_report.py`, and `third_party_filter.py` are not required by the active workflow, but are retained because they provide distinct manual research capability rather than duplicating the pipeline.
