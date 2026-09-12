# Mobile Ghidra Lab

Phone-first native Android reverse-engineering lab. Upload a `.so` from your phone; GitHub Actions performs the heavy analysis with Ghidra Headless and supporting ELF/ARM64 tooling.

## Use from a phone

1. Open this repository on GitHub.
2. Open `input/`.
3. Tap **Add file → Upload files**.
4. Upload a library such as `libcstatic.so` or `libgvraudio.so`.
5. Commit to `main`.
6. Open **Actions → Analyze native library v5 flow recovery**.
7. Wait for the run to finish.
8. Download the `ghidra-v5-...` artifact for that target.

The repository is private. Keep non-public binaries private and analyze only software you own or are authorized to inspect.

## V5 architecture

V5 keeps V4's selective analysis and adds control-flow recovery instead of merely reporting that a function is horrible.

1. **Packing/encryption preflight** validates ELF structure, measures entropy, and conservatively attempts simple whole-file XOR recovery.
2. **Independent ELF evidence** exports headers, segments, sections, symbols, imports, exports, relocations, strings, and pyelftools metadata.
3. **One full Ghidra inventory pass** discovers functions, symbols, strings/xrefs, call graph, and disassembly without mass-decompiling every function.
4. **Selective ranking** reuses the proven V4 ranker to prioritize JNI/app paths while suppressing obvious bundled OpenSSL/libc++/zlib/xhook noise.
5. **Selective assembly/decompile** keeps normal high-value functions readable while giant/flattened functions stay in bounded region mode.
6. **Raw Ghidra P-code** exports architecture-normalized operations for top functions so ARM64 register/value flow can be correlated without trusting text disassembly alone.
7. **ARM64 indirect-branch recovery** recognizes common `ADRP + ADD + LDRSW + ADD + BR` relative jump-table dispatch and reads table entries directly from the ELF when the evidence is valid.
8. **State/dispatcher analysis** records state-register comparisons, high-fan-in dispatcher candidates, resolved computed edges, and conservative trampoline collapse.
9. **Semantic slices** create bounded ARM64 windows around computed branches and dispatcher-like blocks instead of throwing a 100 KB function at a decompiler and hoping for spiritual intervention.
10. **AI context pack** produces small per-function cards for Agora/MT MCP/ChatGPT so a phone client can start with the important evidence rather than ingesting the entire artifact.

When pipeline code changes without a new `.so`, V5 stress-tests the largest current library. When a `.so` is uploaded, only the changed library is selected. A manual run with a blank target analyzes every library under `input/`.

## Start with these V5 files

Do not begin by opening the full disassembly unless scrolling is the actual research objective.

- `ai_context/overview.md` — best phone/AI starting point
- `v5_selected_functions.csv` — ranked targets and `full` vs `region` mode
- `v5_flow_report.md` — control-flow recovery summary
- `v5_indirect_branches.csv` — every recovered ARM64 computed branch and its evidence
- `v5_jump_tables.csv` — decoded table entries for conservatively recognized relative jump tables
- `v5_state_values.csv` — state-register/constant comparisons and nearby conditional targets
- `v5_clean_edges.csv` — CFG edges after only safe trivial-branch collapse
- `v5_slices/` — semantic ARM64 slices around indirect flow and dispatcher candidates
- `v5_pcode.csv` / `v5_pcode_summary.csv` — bounded raw Ghidra P-code evidence
- `v4_selected_ida/` and `v4_decompiled_selected/` — V4 selective exporter retained as a compatibility layer inside the V5 artifact
- `functions.csv`, `callgraph.csv`, `strings.csv`, `string_xrefs.csv` — complete inventory evidence

## What V5 can and cannot claim

A decoded jump-table entry is only emitted after the table address can be derived from the ARM64 sequence and the table bytes can be mapped back into the ELF. Resolved targets are additionally checked against executable load segments. Other indirect branches remain explicitly marked unresolved.

`v5_clean_edges.csv` collapses only trivial unconditional branch trampolines. V5 does not rewrite the binary, invent missing branches, or claim that a heuristic dispatcher is proven obfuscation. Generated parsers, crypto/state machines, and compiler output can be ugly without deliberate protection.

Raw P-code is Ghidra's instruction-level intermediate representation. It is useful for architecture-normalized data-flow evidence, but it is not SSA/high P-code and it is not the original C/C++ source.

## Packed / runtime-encrypted libraries

Static analysis still has limits. If real code is decrypted only after launch, use the prepared Android runtime path under `runtime/`. Dump the already-decrypted memory ranges, reconstruct/repair the ELF as needed, upload the repaired `.so` to `input/`, then run V5 again.

## Manual run

Open **Actions → Analyze native library v5 flow recovery → Run workflow**. Leave the target blank to analyze every `.so` under `input/`, or enter a path such as:

`input/libcstatic.so`

## Limits

Decompiler output is reconstructed pseudocode, not original source. Stripped names, types, comments, runtime-only keys, VM bytecode semantics, and dynamically generated code may require additional runtime evidence. Ranking, dispatcher scoring, and state-register hints are triage signals, not proof by themselves.
