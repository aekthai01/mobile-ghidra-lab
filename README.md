# Mobile Ghidra Lab

Phone-first native Android reverse-engineering lab. Upload a `.so` from your phone; GitHub Actions performs the heavy analysis with Ghidra Headless and supporting ELF/ARM64 tooling.

## Use from a phone

1. Open this repository on GitHub.
2. Open `input/`.
3. Tap **Add file → Upload files**.
4. Upload a library such as `libgvraudio.so`.
5. Commit to `main`.
6. Open **Actions → Analyze native library v3**.
7. Wait for the run to finish.
8. Download the artifact named `ghidra-v3-analysis-...`.

The repository is private. Keep non-public binaries private and analyze only software you own or are authorized to inspect.

## What v3 does

The v3 pipeline is layered so one tool does not get to invent reality by itself:

1. **Packing/encryption preflight** — validates ELF structure, measures entropy, flags suspicious executable regions, and conservatively attempts simple whole-file XOR recovery.
2. **Independent ELF analysis** — `readelf`, `nm`, `objdump`, strings and pyelftools metadata.
3. **Ghidra Headless** — functions, symbols, strings/xrefs, call graph, pseudocode and detailed disassembly.
4. **IDA-like ARM64 export** — raw bytes, `sub_...` / `loc_...` labels, CODE XREF-style information, symbolic direct calls/jumps and per-function assembly files.
5. **ARM64 obstruction triage** — huge-function metrics, basic-block counts, cyclomatic complexity, indirect jumps, repetitive instruction patterns and possible flattening clues.
6. **Third-party filter** — deprioritizes likely OpenSSL/libc++/zlib/xhook/etc. noise without deleting anything, while protecting code close to JNI/app seeds.
7. **De-flatten / indirect-flow triage** — collapses trivial branch trampolines, ranks dispatcher-like blocks, finds likely state registers, records indirect branch context and emits simplified CFGs.
8. **Graphviz SVGs** — simplified CFGs rendered for easier viewing on a phone.

## Start with these files

Do not begin by opening the giant full disassembly unless you enjoy scrolling until retirement.

- `analysis_priority.csv` — best overall starting point after app/JNI proximity, ARM64 complexity and third-party filtering
- `third_party_report.md` — likely bundled-library noise and detected families
- `arm64_obfuscation_report.md` — suspicious/huge ARM64 functions
- `arm64_deflatten_report.md` — dispatcher/state/indirect-flow overview
- `arm64_deflatten/` — per-function reconstruction notes
- `arm64_deflatten_svg/` — simplified CFG diagrams for top candidates
- `arm64_indirect_branches.csv` — indirect `BR` contexts and nearby target clues
- `ida_like_functions/` — one IDA-style ARM64 listing per recovered function
- `decompiled_focus/` — focused Ghidra pseudocode snippets

The artifact also includes the complete evidence set: `functions.csv`, `symbols.csv`, `strings.csv`, `string_xrefs.csv`, `callgraph.csv`, `decompiled.c`, `ida_like_full.asm`, ELF reports, raw strings, logs and manifests.

## Packed / encrypted libraries

Static analysis has limits. v3 can detect suspicious entropy/permissions and recover conservative simple whole-file XOR wrappers, but custom ciphers or code decrypted only after launch may require a runtime dump.

See `runtime/README.md` and `runtime/frida_dump_module.js` for the prepared runtime-unpack path. A cloud GitHub runner cannot attach to an Android process on your phone, so runtime dumping remains a separate stage. Once a decrypted/repaired `.so` is obtained, upload it back to `input/` and run v3 again.

## Manual run

Open **Actions → Analyze native library v3 → Run workflow**. Leave the target blank to analyze every `.so` under `input/`, or enter a path such as:

`input/libgvraudio.so`

## Limits

Decompiler output is reconstructed pseudocode, not original C/C++ source. Stripped symbols, types and comments may be permanently absent. De-flattening and third-party classification are heuristics: use them to prioritize evidence, not as proof.
