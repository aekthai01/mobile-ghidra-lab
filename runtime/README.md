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

## `frida_dump_module.js`

It does **not** patch the app. It asks Frida for one loaded module, enumerates readable ranges belonging to that module, and writes:

- one `.bin` file per readable memory range
- one JSON manifest containing module base, size, range addresses, offsets and protections

Default output folder on Android:

`/sdcard/Download/mobile-ghidra-runtime`

RPC functions:

- `listmodules()` — list loaded modules
- `dumpmodule(moduleName, outputDir)` — dump readable ranges for one module

## `stitch_ranges.py`

After copying the manifest and its range files into one folder, the stitcher can rebuild a **contiguous memory image** using the module-relative addresses recorded by Frida. It also writes a coverage report so missing/unreadable ranges remain visible instead of being silently mistaken for valid code.

The stitched output is still a memory image, **not automatically a repaired ELF**. Relocations, headers, anonymous executable mappings and loader-created pages may still need dedicated reconstruction before the file is suitable for Ghidra as a normal `.so`.

## Why ranges instead of one fake `.so`

Packed libraries can contain unreadable gaps, relocated pointers, anonymous executable pages, or code that no longer matches the on-disk ELF layout. Writing one blob and pretending it is clean can destroy evidence. The range manifest preserves actual runtime addresses so reconstruction can remain explicit.

## Phone-first plan

1. Load the target app with Frida available (rooted Frida server or Frida Gadget).
2. Run `frida_dump_module.js` after the target library has been loaded/decrypted.
3. Keep the generated manifest and range files together.
4. Stitch/reconstruct the runtime image, then repair ELF metadata if necessary.
5. Upload the repaired `.so` to `input/` and run **Analyze native library v3** again.

This runtime stage is separate from GitHub Actions because a cloud runner cannot attach directly to an Android process on your phone.

## Important limitation

If the decryption key is derived from a server response, device hardware, TEE/KeyStore, or ephemeral runtime state, static Ghidra cannot magically recover it. In that case the useful target is usually the **already-decrypted memory** rather than the encrypted file itself.
