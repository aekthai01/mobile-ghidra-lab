# Mobile Ghidra Lab V5.5

Phone-first Android native reverse-engineering lab. Upload a `.so`; GitHub Actions runs Ghidra Headless plus ARM64/P-code analysis and produces a phone-friendly human artifact and a full forensic artifact.

The primary engine is **Ghidra Headless**. **ARM64 is the ground truth** for control flow and instruction semantics. High/Raw P-code are supporting data-flow evidence. **IDA Pro is optional** and is used only as an annotation/navigation surface through the generated IDAPython bridge.

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
evidence-backed idiom folding + call/string recovery
        ↓
semantic C (preferred human/AI analysis view)
        ↓
legacy evidence C-like views + IDA annotations
```

Generated semantic C is **reconstruction, not original source code**. Unsupported instructions stay explicit as `ARM64_*` instead of being guessed. A tidy-looking heuristic is never promoted to fact merely because it compiles in somebody's imagination.

## Use from a phone

1. Upload the target library under `input/`.
2. Open **Actions → Analyze native library v5.5 reconstructed C**.
3. Run the workflow, or let an upload trigger it.
4. Download `ghidra-v55-human-...`.
5. Open `START_HERE.html`.
6. Prefer **ARM64-grounded semantic C** for analysis, and use full ARM64 to verify any critical conclusion.

## Main outputs

The human artifact guarantees complete selected-function coverage:

- `V55_SEMANTIC_C.html` + `semantic_c/`: detailed ARM64-grounded semantic C with exact basic-block/CFG provenance.
- `semantic_c_compact/`: high-signal semantic view designed for human/AI analysis without raw P-code flag noise.
- `SEMANTIC_C_INDEX.csv`: per-function semantic-C coverage, CFG block coverage, calls and folded idioms.
- `OFFSET_LOOKUP.html`: paste an IDA/RVA offset such as `19C56C` or a Ghidra VA such as `g:29C56C`.
- `OFFSET_MAP.txt` + `offset_pages/`: exact searchable mapping for every disassembled instruction using both address forms.
- `asm_full/`: one full dual-address ARM64 listing for every selected function.
- `FUNCTIONS_C.html` + `functions_c/`: legacy evidence-oriented C/C-like coverage. This remains useful forensic context but is no longer the preferred semantic view.
- `V55_RECONSTRUCTION.html` + `reconstructed_c/`: protected/giant region reconstruction.
- `V55_CFG.html`, `V55_NATIVE_DATA.html`, and optional `ida/import_mobile_ghidra.py`.

The semantic-C stage uses ARM64 branch instructions and CFG as authoritative structure, folds only recognized instruction idioms, preserves unsupported instructions explicitly, tracks observed AArch64 ABI arguments, and recovers exact/interior strings. It also scans the analyzed ELF directly for printable strings that Ghidra may not materialize as String objects.

Ghidra and IDA can show different virtual addresses when Ghidra imports the ELF at a non-zero image base. Human views therefore display both **ELF/IDA RVA** and **Ghidra VA**. Users should not need to manually add or subtract the image base.

Forensic artifact keeps full inventory/disassembly, call graph, exact string xrefs, ARM64 flow recovery, jump tables, Raw P-code, High P-code/SSA, protected-function evidence, region maps, semantic-string recovery, and protected-evidence hashes.

For high-protection functions, V5.4 preservation remains mandatory. Missing/truncated required evidence fails the workflow. Semantic-C validation also fails if selected-function coverage or CFG-block coverage regresses, if known stress semantics disappear, or if raw P-code-noise tokens leak back into the semantic view.

## IDA Pro interop

Open the same ELF in IDA Pro and run `human/ida/import_mobile_ghidra.py`. It imports confidence-tagged comments/regions and handles image-base differences. It does not patch bytes, create functions, or change function boundaries. Suggested renames are disabled by default.

## Active entrypoints

There is one workflow and one shell orchestrator:

- `.github/workflows/analyze-native-v55.yml`
- `tools/run_v55_pipeline.sh`

Important stages include `ExportAnalysis.java`, `ExportV4Selected.java`, `ExportV51Refs.java`, `ExportV51RawPcode.java`, `ExportV51HighPcode.java`, `ExportV54ProtectedEvidence.java`, `v5_arm64_flow.py`, `v54_protected_pack.py`, `v55_region_reconstruct.py`, `v55_complete_views.py`, `v55_semantic_c.py`, `v55_semantic_validate.py`, and `v55_ida_pack.py`.

See `tools/README.md` for the active-stage map. Older version numbers in filenames do not automatically mean obsolete; V5.5 reuses proven stage algorithms intentionally.

## Stress targets

`input/libcstatic.so` remains the main stress test. When present, V5.5 validates reconstructed regions for known giant/protected targets including `FUN_00267564`, `FUN_001D3CA4`, and `_INIT_2`. It also validates that every selected function has full ARM64, complete evidence C/C-like views, and ARM64-grounded semantic C.

The known `FUN_0029C094` stress path additionally checks semantic reconstruction around IDA/RVA `0x19C4E0`: signed divide-by-two idiom folding, visible branch structure, license/UI strings, interior Telegram string recovery, and direct ELF recovery of `"Exit"` when the ELF scanner is active.

## Runtime-encrypted libraries

If real code exists only after runtime decryption, static analysis cannot invent it. Use the tooling under `runtime/` to dump/recover the decrypted module, upload the repaired `.so`, then run V5.5 again.

## Cleanup policy

Legacy duplicate workflows, obsolete wrapper scripts, the unused standalone IDA-like exporter, and superseded P-code/AI helper implementations were removed in V5.5. A file is deleted only when the active pipeline no longer depends on it.
