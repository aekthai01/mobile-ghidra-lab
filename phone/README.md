# Mobile AutoPatch - Step 1

This step proves address translation and safe byte writing on the phone before any cross-version signature logic is added.

Everything under `phone/` is intentionally outside the repository's existing GitHub Actions path triggers, so editing or using this patcher does not make the cloud analysis workflow part of the patching path.

## Termux setup

```sh
pkg update
pkg install python git
python -m pip install pyelftools
```

Clone the Step 1 branch on the phone:

```sh
git clone -b autopatch-step1 https://github.com/aekthai01/mobile-ghidra-lab.git
cd mobile-ghidra-lab
```

## First validation: dry-run only

For the current Mobile Ghidra Lab address convention, the default Ghidra image base is `0x100000`.

```sh
python phone/mobile_autopatch.py input/librudp.so \
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

If the names came from a Ghidra project with a different image base, pass it explicitly, for example:

```sh
python phone/mobile_autopatch.py lib.so byte_123456=1 --ghidra-image-base 0x0 --dry-run
```

## Patch only after dry-run succeeds

```sh
python phone/mobile_autopatch.py input/librudp.so \
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
python phone/mobile_autopatch.py input/librudp.so --patch-file patches.txt --dry-run
```

## Run the Step 1 tests on the phone

```sh
python -m unittest discover -s phone/tests -p 'test_mobile_autopatch.py' -v
```

No workflow file is added or changed for this patcher. Runtime validation belongs on the phone.
