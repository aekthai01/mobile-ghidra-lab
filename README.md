# Mobile Ghidra Lab V5.5

Phone-first Android native reverse-engineering lab. Upload a `.so`; GitHub Actions runs Ghidra Headless plus ARM64/P-code analysis and produces a phone-friendly human artifact and a full forensic artifact.

The primary engine is **Ghidra Headless**. **ARM64 is the ground truth** for control flow and instruction semantics. High/Raw P-code are supporting data-flow evidence. **IDA Pro is optional** and is used only as an annotation/navigation surface through the generated IDAPython bridge.

## V5.5 AI-native semantic-C V3

The analysis contract has four layers, deliberately separated so convenient output never quietly outranks machine-code evidence:

1. `asm_full/` is immutable ARM64 ground truth.
2. `semantic_c/` is the ARM64-grounded semantic core and preferred analysis view.
3. `semantic_c_compact/` is the high-signal AI prompt view.
4. `raw_ir` in the forensic artifact is the Raw P-code/SSA evidence vault.

`functions_c/` is retained as legacy evidence-oriented raw P-code C-like context. It is **not** the preferred analysis view.

Semantic provenance is explicit: **EXACT** for direct instruction/address/CFG facts, **STRONG** for deterministic ARM64/data-flow-backed lowering, and **HEURISTIC** for inference. A real symbol is never replaced by a heuristic name.

V3 interprets SIMD/NEON modified immediates only after the architectural shift has produced the final lane bits. The regression `MOVI v1.2S,#0x41,LSL#24` therefore preserves raw bits `0x41000000` and yields `8.0f`, never the pre-shift denormal `9.10844001811131e-44f`. Raw bits remain visible, suspicious denormal splats are rejected globally, no-byte assembly listings remain parseable, DUP/vector evidence is retained, and strings containing `*/` are represented through a safe evidence literal.

## V5.5 goal

V5.5 removes the old "huge protected function = decompiler dead end" assumption and avoids pretending that a raw P-code dump is good C.

```text
ARM64 / protected giant function
        ↓
CFG + SCC + dominators + indirect/state evidence
        ↓
full dual-address ARM64 evidence
        ↓
High P-code / SSA when available + preserved Raw P-code fallback
        ↓
ARM64-grounded basic-block reconstruction
        ↓
V3 bit-exact semantic AI upgrade
        ↓
semantic C (preferred human/AI analysis view)
        ↓
fatal V3 quality gate + semantic validation
```

Generated semantic C is **reconstruction, not original source code**. Unsupported instructions stay explicit as `ARM64_*` instead of being guessed.

## Use from a phone

1. Upload the target library under `input/`.
2. Open **Actions → Analyze native library v5.5 reconstructed C**.
3. Run the workflow, or let an upload trigger it.
4. Download `ghidra-v55-human-...`.
5. Open `START_HERE.html`.
6. Prefer **ARM64-grounded semantic C** for analysis, and use full ARM64 to verify any critical conclusion.

## Main outputs

- `V55_SEMANTIC_C.html` + `semantic_c/`: detailed ARM64-grounded semantic C.
- `semantic_c_compact/`: high-signal AI prompt view.
- `SEMANTIC_C_INDEX.csv`: semantic-C coverage and CFG/call statistics.
- `asm_full/`: full dual-address immutable ARM64 evidence for every selected function.
- `FUNCTIONS_C.html` + `functions_c/`: legacy evidence-oriented C-like context only.
- `OFFSET_LOOKUP.html`, `OFFSET_MAP.txt`, `offset_pages/`: exact dual-address navigation.
- `V55_RECONSTRUCTION.html`, `V55_CFG.html`, `V55_NATIVE_DATA.html`, and optional `ida/import_mobile_ghidra.py`.

Forensic output keeps full inventory/disassembly, call graph, exact string xrefs, ARM64 flow recovery, jump tables, Raw/High P-code and SSA, protected evidence, region maps, semantic-string recovery, and protected-evidence hashes.

For high-protection functions, V5.4 preservation remains mandatory. Missing/truncated required evidence fails the workflow. V3 quality and semantic validation are fatal.

## IDA Pro interop

Open the same ELF in IDA Pro and run `human/ida/import_mobile_ghidra.py`. It imports confidence-tagged comments/regions and handles image-base differences. It does not patch bytes, create functions, or change function boundaries. Suggested renames are disabled by default.

## Active entrypoints

There is one workflow and one shell orchestrator:

- `.github/workflows/analyze-native-v55.yml`
- `tools/run_v55_pipeline.sh`

The semantic chain is `v55_semantic_c.py` → `v55_semantic_ai_upgrade.py` → quality gates → `v55_semantic_validate.py` → `v55_human_finalize.py` → `v55_validate.py`. See `tools/README.md` for the complete active-stage map.

## Stress targets

`input/libcstatic.so` remains the main stress test. The known `FUN_0029C094` path checks signed divide-by-two folding, visible branch structure, license/UI strings, interior Telegram recovery, `Exit`, bit-exact modified FP immediates and vector propagation.

## Runtime-encrypted libraries

If real code exists only after runtime decryption, static analysis cannot invent it. Use the tooling under `runtime/` to dump/recover the decrypted module, upload the repaired `.so`, then run V5.5 again.

## Cleanup policy

Legacy duplicate workflows, obsolete wrapper scripts, the unused standalone IDA-like exporter, and superseded P-code/AI helper implementations were removed in V5.5. A file is deleted only when the active pipeline no longer depends on it.
