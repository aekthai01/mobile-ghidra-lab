# Mobile Ghidra Lab

Private, phone-first reverse-engineering lab for native Android `.so` libraries. The phone only uploads the file; GitHub Actions performs the heavy analysis with Ghidra Headless and ELF tools.

## Use from a phone

1. Open this repository on GitHub.
2. Open the `input` folder.
3. Tap **Add file → Upload files**.
4. Upload the library, for example `libgvraudio.so`.
5. Commit directly to `main`.
6. Open **Actions → Analyze native library**. A run should start automatically because a `.so` under `input/` changed.
7. Wait for the run to finish.
8. Open the finished run and download the artifact named `ghidra-analysis-...`.

The first run can take longer because the runner downloads the official Ghidra release. The release ZIP is cached for later runs.

## What the artifact contains

Each analyzed library gets its own result folder. It includes:

- `analysis_summary.md` — compact Ghidra summary
- `elf_metadata.json` — structured ELF metadata produced with pyelftools
- `file.txt`, `sha256.txt` — file identity and hash
- `readelf_*.txt` — ELF headers, sections, segments, dynamic table, relocations, symbols, notes and versions
- `imports.txt`, `exports.txt`, `nm_dynamic_all.txt` — dynamic/native symbols
- `raw_strings.txt`, `interesting_strings.txt` — extracted strings and a useful filtered subset
- `objdump_disassembly.txt` — GNU objdump disassembly
- `functions.csv` — functions Ghidra discovered
- `symbols.csv` — Ghidra symbol inventory
- `strings.csv`, `string_xrefs.csv` — strings and references discovered by Ghidra
- `callgraph.csv` — caller/callee/callsite edges
- `disassembly.txt` — Ghidra listing disassembly
- `jni_candidates.txt` — JNI/native-registration related names
- `decompiled.c` — reconstructed C-like pseudocode from Ghidra
- `decompiled_index.csv` — which functions decompiled successfully or failed/timed out
- `ghidra_headless.log` — full Ghidra log for troubleshooting
- `status.txt`, `ghidra_exit_code.txt` — whether the result is complete or partial

The artifact is retained for **5 days** by the workflow.

## Analysis limits

The workflow exports the full function inventory, symbols, strings, call graph and disassembly independently of pseudocode generation. Pseudocode is prioritized and bounded so one pathological function cannot consume the entire cloud job. Current defaults are up to 2,500 candidate functions, a 20-minute total decompiler budget, and 8 seconds per function.

Ghidra pseudocode is reconstructed output. It is **not** the original C/C++ source code, and stripped/obfuscated binaries may lose names and type information permanently.

## Manual run

You can also open **Actions → Analyze native library → Run workflow**. Leave the target blank to analyze all `.so` files under `input/`, or enter a path such as:

`input/libgvraudio.so`

## Safety / privacy

Keep this repository private for non-public binaries. Analyze only software you own or are authorized to inspect. The workflow performs static analysis and does not execute the uploaded `.so` library.
