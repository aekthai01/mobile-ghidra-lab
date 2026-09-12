# Mobile Ghidra Lab

Phone-first native Android reverse-engineering lab. Upload a `.so` from your phone; GitHub Actions performs the heavy analysis with Ghidra Headless and supporting ELF/ARM64 tooling.

## Use from a phone

1. Open this repository on GitHub.
2. Open `input/`.
3. Tap **Add file → Upload files**.
4. Upload a library such as `libcstatic.so` or `libgvraudio.so`.
5. Commit to `main`.
6. Open **Actions → Analyze native library v4 selective**.
7. Wait for the run to finish.
8. Download the `ghidra-v4-...` artifact for that target.

The repository is private. Keep non-public binaries private and analyze only software you own or are authorized to inspect.

## Why V4 exists

V3 proved that “analyze everything deeply” is a bad strategy for hostile native libraries. A 100 KB ARM64 function with thousands of blocks can make decompilers time out, and feeding a multi-thousand-node CFG to Graphviz can waste most of a runner session after Ghidra itself already finished.

V4 changes the pipeline to **inventory → rank → selectively deepen**:

1. **Packing/encryption preflight** — validates ELF structure, measures entropy and conservatively attempts simple whole-file XOR recovery.
2. **Independent ELF evidence** — `readelf`, `nm`, strings and pyelftools metadata.
3. **One full Ghidra auto-analysis** — discovers functions, symbols, strings/xrefs, call graph and one-file disassembly, but mass pseudocode export is disabled.
4. **Whole-binary triage** — `v4_select_targets.py` ranks functions using JNI/app proximity, strings, indirect flow, compare/state patterns, size and conservative third-party signatures.
5. **Two analysis modes**:
   - `full` for manageable high-value functions: selective IDA-like assembly + Ghidra pseudocode.
   - `region` for giant/flattened functions: no whole-function decompile; bounded windows are extracted around entry, indirect jumps/calls, high-indegree blocks, state-compare samples and periodic coverage points.
6. **Bounded visualization** — only a capped selected-function call graph is rendered. Graphviz is also wrapped in a hard timeout so visualization cannot hold the workflow hostage.
7. **Per-library matrix jobs** — multiple uploaded `.so` files can be analyzed in parallel instead of one enormous sequential job.

When pipeline code changes without a new `.so`, V4 automatically stress-tests the largest current library. When a `.so` is uploaded, only the changed library is selected. A manual run with a blank target analyzes every library under `input/`.

## Start with these V4 files

Do not begin with a 70 MB disassembly unless your thumb has offended you personally.

- `v4_triage.md` — short explanation of what V4 selected and why
- `v4_selected_functions.csv` — authoritative target list with `full` vs `region` mode
- `v4_function_metrics.csv` — whole-binary ARM64 metrics and ranking evidence
- `v4_selected_export.csv` — what the second Ghidra pass actually exported/decompiled
- `v4_selected_ida/` — readable IDA-like ARM64 listings for manageable selected functions
- `v4_decompiled_selected/` — focused Ghidra pseudocode, one file per selected function
- `v4_giant_regions/` — bounded evidence windows for giant/flattened functions
- `v4_giant_region_index.csv` — region center, reason, range and file path
- `v4_selected_callgraph.svg` — capped phone-friendly selected call graph
- `callgraph.csv`, `functions.csv`, `strings.csv`, `string_xrefs.csv` — complete inventory evidence

## Giant / flattened ARM64 functions

V4 deliberately does **not** treat a 20–100 KB flattened function like an ordinary function. Whole-function decompilation can spend seconds or minutes building an expression tree that is mostly dispatcher noise and still return nothing useful.

Region mode instead keeps the original runtime addresses and extracts small windows around high-value control-flow evidence. This makes it practical to follow `BR Xn`, jump tables, dispatcher candidates, JNI paths and suspicious state comparisons without exporting thousands of per-function files.

This is triage/deobfuscation assistance, not proof that a function is obfuscated. Large generated parsers, crypto code and state machines can look hostile without deliberate protection.

## Packed / encrypted libraries

Static analysis has limits. The preflight can detect suspicious structure/entropy and recover conservative simple whole-file XOR wrappers, but custom ciphers or code decrypted only after launch may require a runtime dump.

See `runtime/README.md` and `runtime/frida_dump_module.js`. A cloud runner cannot attach directly to an Android process on your phone. Once a decrypted/repaired `.so` is obtained, upload it to `input/` and run V4 again.

## Manual run

Open **Actions → Analyze native library v4 selective → Run workflow**. Leave the target blank to analyze every `.so` under `input/`, or enter a path such as:

`input/libcstatic.so`

## Limits

Decompiler output is reconstructed pseudocode, not original C/C++ source. Stripped symbols, types and comments may be permanently absent. Function ranking, third-party classification, state-register hints and region selection are heuristics. They prioritize evidence; they do not magically recover original source or defeat every VM/packer.
