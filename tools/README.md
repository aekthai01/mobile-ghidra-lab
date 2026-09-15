# Tools used by V5.5

Do not infer whether a file is active from the version number in its filename. V5.5 deliberately reuses proven V4/V5.1/V5.2 analysis stages.

## Entry point

`run_v55_pipeline.sh` is the only shell orchestrator used by the active GitHub Actions workflow.

## Active stages

Selection/ranking: `v4_select_targets.py`, `v51_rank_targets.py`, `priority_bias.py`, `v52_reselect.py`.

ARM64/CFG/protected flow: `v5_arm64_flow.py`, `v5_validate_tables.py`, `v52_selector_labels.py`, `v51_runtime_tables.py`, `v52_protected_regions.py`, `v52_coverage.py`.

P-code/quality/context: `v51_high_pcode_slices.py`, `v51_quality.py`, `v51_ai_context.py`, `v4_callgraph.py`.

Human/preservation: `v53_enrich_asm.py`, `v53_human_pack.py`, `v54_protected_pack.py`.

V5.5 reconstruction/intelligence: `v55_cfg_metrics.py`, `v55_native_data.py`, `v55_region_reconstruct.py`, `v55_ida_pack.py`, `v55_complete_views.py`, `v55_semantic_c.py`, `v55_semantic_ai_upgrade.py`, `v55_semantic_quality_v2.py`, `v55_ai_quality_v3.py`, `v55_semantic_validate.py`, `v55_human_finalize.py`, `v55_validate.py`.

The semantic order is intentional and fatal on failure: `v55_semantic_c.py` generates the ARM64-grounded views, `v55_semantic_ai_upgrade.py` performs V3 bit-exact/evidence-safe enrichment, then V2/V3 quality gates and semantic validation run before human finalization. `v55_ai_quality_v3.py` is not advisory and must never be weakened with `|| true`.

## Four analysis layers

1. `asm_full/` is immutable ARM64 ground truth.
2. `semantic_c/` is the ARM64-grounded semantic core and preferred analysis view.
3. `semantic_c_compact/` is the high-signal AI prompt view.
4. `raw_ir` in the forensic output is the Raw P-code/SSA evidence vault.

`functions_c/` is legacy evidence-oriented raw P-code C-like material. It is useful forensic context, but it is not the preferred analysis view.

Semantic provenance uses EXACT / STRONG / HEURISTIC. EXACT is direct ARM64/address/CFG evidence; STRONG is deterministic lowering backed by ARM64/data flow; HEURISTIC is inference only. Real symbols are never replaced by heuristic names.

V3 treats ARM64 SIMD/NEON modified immediates as bit patterns after their architectural shift. For example `MOVI v1.2S,#0x41,LSL#24` produces raw lane bits `0x41000000`, therefore `8.0f`; interpreting the pre-shift byte as `9.10844001811131e-44f` is forbidden. Raw bits remain visible. The V3 gate also rejects suspicious denormal splats globally, covers no-byte assembly listings and DUP/vector propagation evidence, and requires evidence strings containing `*/` to survive through a safe literal representation.

`v55_complete_views.py` closes the human-view coverage gap: every selected function receives one evidence-oriented C/C-like file and one full ARM64 file, while all disassembled instructions receive dual ELF/IDA-RVA and Ghidra-VA address aliases.

`v55_semantic_validate.py` prevents green-but-useless regressions: it requires semantic-C coverage for every selected function, exact CFG-block coverage for functions with CFG, rejects raw P-code-noise tokens from semantic output, and checks known stress semantics including the `0x19C094` path.

ELF/preflight: `preflight_obfuscation.py`, `elf_report.py`.

## Retained research utilities

`arm64_deflatten_report.py`, `arm64_obfuscation_report.py`, `deep_report.py`, and `third_party_filter.py` are retained because they provide distinct manual research capability rather than duplicating the pipeline.
