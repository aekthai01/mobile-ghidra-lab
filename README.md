# Mobile Ghidra Lab V5.5

Phone-first Android native reverse-engineering lab. Upload a `.so`; GitHub Actions runs Ghidra Headless plus ARM64/P-code analysis and produces a phone-friendly human artifact and a full forensic artifact.

The primary engine is **Ghidra Headless**. **IDA Pro is optional** and is used only as an annotation/navigation surface through the generated IDAPython bridge.

## V5.5 goal

V5.5 removes the old "huge protected function = decompiler dead end" assumption.

```text
ARM64 / protected giant function
        ↓
CFG + indirect-flow + state evidence
        ↓
semantic region windows
        ↓
High P-code / SSA when available
        ↓
full preserved Raw P-code fallback
        ↓
confidence-tagged C-like region reconstruction
        ↓
overview.c + per-region C + IDA annotations
```

Generated C-like output is **reconstruction, not original source code**. A heuristic never becomes a fact merely because it looks tidy.

## Use from a phone

1. Upload the target library under `input/`.
2. Open **Actions → Analyze native library v5.5 reconstructed C**.
3. Run the workflow, or let an upload trigger it.
4. Download `ghidra-v55-human-...`.
5. Open `START_HERE.html`.

## Main outputs

Human artifact: `START_HERE.html`, `V55_RECONSTRUCTION.html`, `reconstructed_c/<function>/overview.c`, per-region C files, and optional `ida/import_mobile_ghidra.py`.

Forensic artifact keeps full inventory/disassembly, call graph, exact string xrefs, ARM64 flow recovery, jump tables, Raw P-code, High P-code/SSA, protected-function evidence, region maps, and protected-evidence hashes.

For high-protection functions, V5.4 preservation remains mandatory. Missing/truncated required evidence fails the workflow.

## IDA Pro interop

Open the same ELF in IDA Pro and run `human/ida/import_mobile_ghidra.py`. It imports confidence-tagged comments/regions and handles image-base differences. It does not patch bytes, create functions, or change function boundaries. Suggested renames are disabled by default.

## Active entrypoints

There is one workflow and one shell orchestrator:

- `.github/workflows/analyze-native-v55.yml`
- `tools/run_v55_pipeline.sh`

Important stages include `ExportAnalysis.java`, `ExportV4Selected.java`, `ExportV51Refs.java`, `ExportV51RawPcode.java`, `ExportV51HighPcode.java`, `ExportV54ProtectedEvidence.java`, `v5_arm64_flow.py`, `v54_protected_pack.py`, `v55_region_reconstruct.py`, and `v55_ida_pack.py`.

See `tools/README.md` for the active-stage map. Older version numbers in filenames do not automatically mean obsolete; V5.5 reuses proven stage algorithms intentionally.

## Stress targets

`input/libcstatic.so` remains the main stress test. When present, V5.5 validates reconstructed regions for known giant/protected targets including `FUN_00267564`, `FUN_001D3CA4`, and `_INIT_2`.

## Runtime-encrypted libraries

If real code exists only after runtime decryption, static analysis cannot invent it. Use the tooling under `runtime/` to dump/recover the decrypted module, upload the repaired `.so`, then run V5.5 again.

## Cleanup policy

Legacy duplicate workflows, obsolete wrapper scripts, the unused standalone IDA-like exporter, and superseded P-code/AI helper implementations were removed in V5.5. A file is deleted only when the active pipeline no longer depends on it.
