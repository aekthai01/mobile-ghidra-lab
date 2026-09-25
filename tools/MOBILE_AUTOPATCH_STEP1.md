# Mobile AutoPatch - Step 1

This step proves address translation and safe byte writing on the phone before any cross-version signature logic is added.

## Termux setup

```sh
pkg update
pkg install python git
python -m pip install pyelftools
```

Clone the repository/branch on the phone and enter it:

```sh
git clone -b autopatch-step1 https://github.com/aekthai01/mobile-ghidra-lab.git
cd mobile-ghidra-lab
```

## First validation: dry-run only

For the current Ghidra analysis convention, the default Ghidra image base is `0x100000`.

```sh
python tools/mobile_autopatch.py input/librudp.so \
  byte_36AE84=1 \
  dword_36AF34=3 \
  --dry-run
```

The tool prints, for every target:

- Ghidra VA
- ELF RVA after subtracting the Ghidra image base
- PT_LOAD segment
- section when available
- physical file offset when one exists
- original bytes/value
- replacement bytes/value

If a target is in `.bss` / `SHT_NOBITS` or another zero-filled PT_LOAD tail, the command exits with code `4` and writes nothing. That is intentional: there is no physical byte in the ELF to edit at such an address.

## Patch only after dry-run succeeds

```sh
python tools/mobile_autopatch.py input/librudp.so \
  byte_36AE84=1 \
  dword_36AF34=3
```

The original file is never modified. The default output is:

```text
input/librudp.patched.so
```

The output is re-read and the replacement bytes are verified before success is reported.

## patches.txt mode

`patches.txt`:

```text
byte_36AE84=1
dword_36AF34=3
```

Run:

```sh
python tools/mobile_autopatch.py input/librudp.so --patch-file patches.txt --dry-run
```

## Run the Step 1 tests on the phone

```sh
python -m unittest tests.test_mobile_autopatch -v
```

No GitHub Action is added for this patcher. Execution is intentionally local to the phone.
