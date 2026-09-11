# Mobile Ghidra Lab

Private, mobile-first reverse-engineering lab for native Android libraries.

## How to use

1. Upload a `.so` file into `input/` from GitHub on your phone.
2. GitHub Actions starts automatically when a `.so` under `input/` changes, or you can run **Analyze native library** manually from the Actions tab.
3. Wait for the workflow to finish.
4. Download the `ghidra-analysis-*` artifact from the workflow run.

The artifact contains ELF metadata, symbols, imports/exports, strings, Ghidra function inventory, call graph, xrefs, JNI-related findings, disassembly, and decompiled pseudocode where Ghidra can recover it.

> Keep this repository private if the binaries are private or proprietary. Only analyze software you own or are authorized to inspect.
