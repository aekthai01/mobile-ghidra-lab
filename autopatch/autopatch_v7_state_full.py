#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path

EXPECTED_SHA256 = '5a14855bfdab54000a7724b6935a1191ed654a6b43c2ed514ba54fcc6ae2bb48'
NOP = 0xD503201F
RET = 0xD65F03C0

# Exact original words for this build. Fail closed on any mismatch.
SITES = {
    # byte_36AE84 reads
    0x20BEDC: 0x08DFFD08,
    0x21649C: 0x08DFFFA9,
    0x217B28: 0x08DFFFA9,
    0x218B14: 0x08DFFFA8,
    0x218EA8: 0x08DFFFA9,
    0x21A088: 0x08DFFFA8,
    0x240C50: 0x08DFFD08,
    # byte writers / producer
    0x23BDEC: 0x089FFD1F,
    0x23C6B8: 0x5280002A,
    0x23C6CC: 0x089FFD0A,
    0x244B54: 0x089FFD1F,
    # dword_36AF34 reads
    0x217BE0: 0xB94F3708,
    0x217C78: 0xB94F3708,
    0x218974: 0xB94F3708,
    # dword writers / producers
    0x217B4C: 0xB90F371F,
    0x217BF8: 0x52800028,
    0x217BFC: 0xB90F3708,
    0x217DD4: 0x52800048,
    0x217DDC: 0xB90F3708,
    0x217E14: 0x5280006A,
    0x217E20: 0xB90F370A,
    # only two validated NOP islands in .text
    0x237ADC: NOP, 0x237AE0: NOP, 0x237AE4: NOP,
    0x237AE8: NOP, 0x237AEC: NOP, 0x237AF0: NOP,
    0x23E8DC: NOP, 0x23E8E0: NOP, 0x23E8E4: NOP,
    0x23E8E8: NOP, 0x23E8EC: NOP, 0x23E8F0: NOP,
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def word(data: bytes, rva: int) -> int:
    if rva < 0 or rva + 4 > len(data):
        raise SystemExit(f'RVA outside ELF file-backed range: 0x{rva:X}')
    return int.from_bytes(data[rva:rva+4], 'little')


def enc_b(pc: int, dest: int, link: bool = False) -> int:
    delta = dest - pc
    if delta & 3:
        raise ValueError('unaligned branch target')
    imm26 = delta >> 2
    if not -(1 << 25) <= imm26 < (1 << 25):
        raise ValueError('branch out of range')
    return (0x94000000 if link else 0x14000000) | (imm26 & 0x03FFFFFF)


def enc_adrp(pc: int, target: int, rd: int) -> int:
    pc_page = pc & ~0xFFF
    target_page = target & ~0xFFF
    imm = (target_page - pc_page) >> 12
    if not -(1 << 20) <= imm < (1 << 20):
        raise ValueError('ADRP target out of range')
    u = imm & ((1 << 21) - 1)
    immlo = u & 3
    immhi = (u >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | (rd & 31)


def enc_add_x(rd: int, rn: int, imm12: int) -> int:
    if not 0 <= imm12 <= 0xFFF:
        raise ValueError('ADD immediate out of range')
    return 0x91000000 | (imm12 << 10) | ((rn & 31) << 5) | (rd & 31)


def enc_mov_w(rd: int, value: int) -> int:
    if not 0 <= value <= 0xFFFF:
        raise ValueError('MOV immediate requires one MOVZ')
    return 0x52800000 | (value << 5) | (rd & 31)


def enc_stlrb(rt: int, rn: int) -> int:
    return 0x089FFC00 | ((rn & 31) << 5) | (rt & 31)


def enc_str_w(rt: int, rn: int, byte_off: int = 0) -> int:
    if byte_off & 3 or not 0 <= byte_off <= 0x3FFC:
        raise ValueError('STR W unsigned offset out of range')
    imm12 = byte_off >> 2
    return 0xB9000000 | (imm12 << 10) | ((rn & 31) << 5) | (rt & 31)


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f'.{path.name}.', suffix='.tmp', dir=str(path.parent))
    tp = Path(tmp)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tp, stat.S_IMODE(mode))
        os.replace(tp, path)
    except Exception:
        tp.unlink(missing_ok=True)
        raise


def build_plan() -> list[dict]:
    plan: list[dict] = []
    def add(rva: int, new: int, reason: str) -> None:
        plan.append({'rva': rva, 'old': SITES[rva], 'new': new, 'reason': reason})

    # Cave A: universal byte_36AE84 setter. It computes the BSS address itself,
    # writes 1 with release semantics, returns W9=1, and uses X16 as call scratch.
    add(0x237ADC, enc_b(0x237ADC, 0x237AF4), 'preserve normal fallthrough around byte setter cave')
    add(0x237AE0, enc_adrp(0x237AE0, 0x36AE84, 16), 'byte stub: ADRP X16, byte_36AE84 page')
    add(0x237AE4, enc_add_x(16, 16, 0xE84), 'byte stub: ADD X16,X16,#0xE84')
    add(0x237AE8, enc_mov_w(9, 1), 'byte stub: MOV W9,#1')
    add(0x237AEC, enc_stlrb(9, 16), 'byte stub: STLRB W9,[X16] => real byte=1')
    add(0x237AF0, RET, 'byte stub: RET')

    # Main hidden read becomes a real setter/read. Both reset-to-zero stores also
    # call the same setter instead of writing zero.
    add(0x217B28, enc_b(0x217B28, 0x237AE0, link=True), 'hidden auth read -> byte setter; returns W9=1')
    add(0x23BDEC, enc_b(0x23BDEC, 0x237AE0, link=True), 'reset writer -> byte setter; writes 1 instead of 0')
    add(0x244B54, enc_b(0x244B54, 0x237AE0, link=True), 'reset writer -> byte setter; writes 1 instead of 0')

    # Other decoded auth reads are forced locally. The critical 0x217B28 path above
    # additionally materializes the real BSS byte, so debugger state is no longer 0.
    add(0x20BEDC, enc_mov_w(8, 1), 'force byte read W8=1')
    add(0x21649C, enc_mov_w(9, 1), 'force byte read W9=1')
    add(0x218B14, enc_mov_w(8, 1), 'force byte read W8=1')
    add(0x218EA8, enc_mov_w(9, 1), 'force byte read W9=1')
    add(0x21A088, enc_mov_w(8, 1), 'force byte read W8=1')
    add(0x240C50, enc_mov_w(8, 1), 'force byte read W8=1')

    # Keep the legitimate success writer as an invariant guard: W10=1 + STLRB.
    # It is intentionally not modified.

    # Cave B: universal dword_36AF34 setter/read. Returns W8=3 and materializes 3.
    add(0x23E8DC, enc_b(0x23E8DC, 0x23E8F4), 'preserve normal fallthrough around dword setter cave')
    add(0x23E8E0, enc_adrp(0x23E8E0, 0x36AF34, 16), 'dword stub: ADRP X16, dword_36AF34 page')
    add(0x23E8E4, enc_add_x(16, 16, 0xF34), 'dword stub: ADD X16,X16,#0xF34')
    add(0x23E8E8, enc_mov_w(8, 3), 'dword stub: MOV W8,#3')
    add(0x23E8EC, enc_str_w(8, 16, 0), 'dword stub: STR W8,[X16] => real dword=3')
    add(0x23E8F0, RET, 'dword stub: RET')

    # First central state read materializes 3 and returns W8=3. Other reads are
    # constant-forced. The zero reset is removed, and transition producers 1/2 -> 3.
    add(0x217BE0, enc_b(0x217BE0, 0x23E8E0, link=True), 'central dword read -> setter; returns W8=3')
    add(0x217C78, enc_mov_w(8, 3), 'force dword read W8=3')
    add(0x218974, enc_mov_w(8, 3), 'force dword read W8=3')
    add(0x217B4C, NOP, 'remove dword reset-to-zero store')
    add(0x217BF8, enc_mov_w(8, 3), 'transition producer 1 -> 3')
    add(0x217DD4, enc_mov_w(8, 3), 'transition producer 2 -> 3')

    return plan


def main() -> int:
    ap = argparse.ArgumentParser(description='Exact-build v7 full real-memory state-force patch')
    ap.add_argument('elf', type=Path)
    ap.add_argument('-o', '--output', type=Path)
    ap.add_argument('--manifest', type=Path, default=Path('patch_manifest_v7.json'))
    ap.add_argument('--dry-run', action='store_true')
    a = ap.parse_args()

    src = a.elf.read_bytes()
    got = sha256(src)
    if got != EXPECTED_SHA256:
        raise SystemExit(f'SHA256 mismatch; exact-build patch refused\nexpected {EXPECTED_SHA256}\nfound    {got}')
    for rva, expected in SITES.items():
        actual = word(src, rva)
        if actual != expected:
            raise SystemExit(f'guard mismatch at RVA 0x{rva:X}: expected 0x{expected:08X}, got 0x{actual:08X}')

    plan = build_plan()
    outb = bytearray(src)
    seen: set[int] = set()
    for item in plan:
        rva = item['rva']
        if rva in seen:
            raise SystemExit(f'duplicate plan RVA 0x{rva:X}')
        seen.add(rva)
        if word(src, rva) != item['old']:
            raise SystemExit(f'pre-write guard changed at RVA 0x{rva:X}')
        outb[rva:rva+4] = int(item['new']).to_bytes(4, 'little')

    # Preserve known already-correct writer sequences.
    invariants = {
        0x23C6B8: 0x5280002A,  # MOV W10,#1
        0x23C6CC: 0x089FFD0A,  # STLRB W10,[X8]
        0x217BFC: 0xB90F3708,  # store transition W8 (producer forced to 3)
        0x217DDC: 0xB90F3708,  # store transition W8 (producer forced to 3)
        0x217E14: 0x5280006A,  # MOV W10,#3
        0x217E20: 0xB90F370A,  # final STR W10 => 3
    }
    for rva, expected in invariants.items():
        if word(outb, rva) != expected:
            raise SystemExit(f'invariant changed at 0x{rva:X}')

    after = sha256(bytes(outb))
    manifest = {
        'version': 7,
        'mode': 'exact-build-full-real-memory-state-force',
        'input': str(a.elf),
        'sha256_before': got,
        'sha256_after': after,
        'targets': {'byte_36AE84': 1, 'dword_36AF34': 3},
        'patched_instruction_count': len(plan),
        'plan': [
            {**x, 'old': f"0x{x['old']:08X}", 'new': f"0x{x['new']:08X}",
             'new_bytes_le': int(x['new']).to_bytes(4, 'little').hex()}
            for x in plan
        ],
    }
    a.manifest.write_text(json.dumps(manifest, indent=2), encoding='utf-8')

    print(f'[*] SHA256 before: {got}')
    for x in manifest['plan']:
        print(f"0x{x['rva']:X}: {x['old']} -> {x['new']}  {x['reason']}")
    print(f'[*] SHA256 after : {after}')
    print(f'[+] manifest     : {a.manifest}')
    if a.dry_run:
        print('[+] dry-run: exact guards and full state-force plan verified; no ELF written')
        return 0

    out = a.output or a.elf.with_name(a.elf.stem + '.v7-state' + a.elf.suffix)
    if out.resolve() == a.elf.resolve():
        raise SystemExit('refusing to overwrite source ELF')
    if out.exists():
        raise SystemExit(f'output exists: {out}')
    atomic_write(out, bytes(outb), a.elf.stat().st_mode)
    verify = out.read_bytes()
    if sha256(verify) != after:
        raise SystemExit('post-write SHA256 verification failed')
    for x in plan:
        if word(verify, x['rva']) != x['new']:
            raise SystemExit(f'post-write instruction verification failed at 0x{x["rva"]:X}')
    print(f'[+] output       : {out}')
    print(f'[+] verified     : {len(plan)} patched instructions')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
