# Runtime-unpack path (Android)

Use this only for software you own or are authorized to inspect.

Static analysis cannot fully recover code that is decrypted only after the process starts. This folder provides the next stage for that case.

## When to use it

Use runtime dumping when the static artifact shows one or more of these:

- input is not a valid ELF and simple XOR recovery failed
- executable sections have unusually high entropy
- loader code writes to executable memory
- large regions look encrypted/compressed until runtime
- Ghidra sees a tiny loader but the app clearly contains much more behavior

## What `frida_dump_module.js` does

It does **not** patch the app. It asks Frida for one loaded module, enumerates readable ranges that belong to that module, and writes:

- one `.bin` file per readable memory range
- one JSON manifest containing module base, size, range addresses, offsets and protections

Default output folder on Android:

`/sdcard/Download/mobile-ghidra-runtime`

The script exposes two RPC functions:

- `listmodules()` — list currently loaded modules
- `dumpmodule(moduleName, outputDir)` — dump readable ranges for one module

## Why ranges instead of one fake `.so`

Packed libraries often contain unreadable gaps, relocated pointers, anonymous executable pages, or code that no longer matches the on-disk ELF layout. Writing a single blob and pretending it is a clean ELF can destroy evidence. The range manifest preserves the real runtime addresses so a later reconstruction stage can rebuild the image correctly.

## Phone-first plan

The practical phone-only route is:

1. Load the target app with Frida available (rooted Frida server or Frida Gadget).
2. Run `frida_dump_module.js` after the target library has been loaded/decrypted.
3. Copy the generated manifest and range files into a private analysis workspace.
4. Reconstruct/repair the memory image (for example with a dedicated ELF fixer when appropriate).
5. Upload the repaired `.so` to `input/` and run the normal deep workflow again.

This runtime stage is intentionally separate from GitHub Actions because a cloud runner cannot attach to an Android process on your phone.

## Important limitation

If the decryption key is derived from a server response, device hardware, TEE/KeyStore, or ephemeral runtime state, static Ghidra cannot magically recover it. In that situation the useful target is usually the **already-decrypted memory** rather than the encrypted file itself.
