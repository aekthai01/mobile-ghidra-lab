#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, stat, tempfile
from pathlib import Path

EXPECTED_SHA256 = '5a14855bfdab54000a7724b6935a1191ed654a6b43c2ed514ba54fcc6ae2bb48'
NOP = 0xD503201F

SITES = {
    0x217B28: 0x08DFFFA9,
    0x217B4C: 0xB90F371F,
    0x217BE0: 0xB94F3708,
    0x217BF8: 0x52800028,
    0x217DD4: 0x52800048,
    0x217E14: 0x5280006A,
    0x23BDEC: 0x089FFD1F,
    0x23C6B8: 0x5280002A,
    0x23C6CC: 0x089FFD0A,
    0x244B54: 0x089FFD1F,
    0x237ADC: NOP, 0x237AE0: NOP, 0x237AE4: NOP, 0x237AE8: NOP, 0x237AEC: NOP, 0x237AF0: NOP,
    0x23E8DC: NOP, 0x23E8E0: NOP, 0x23E8E4: NOP, 0x23E8E8: NOP, 0x23E8EC: NOP, 0x23E8F0: NOP,
}

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def enc_b(pc: int, dest: int) -> int:
    delta = dest - pc
    if delta & 3:
        raise ValueError('unaligned branch target')
    imm26 = delta >> 2
    if not -(1 << 25) <= imm26 < (1 << 25):
        raise ValueError('branch out of range')
    return 0x14000000 | (imm26 & 0x03FFFFFF)

def word(data: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(data):
        raise SystemExit(f'offset outside ELF: 0x{off:X}')
    return int.from_bytes(data[off:off+4], 'little')

def atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f'.{path.name}.', suffix='.tmp', dir=str(path.parent))
    tp = Path(tmp)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.chmod(tp, stat.S_IMODE(mode))
        os.replace(tp, path)
    except Exception:
        tp.unlink(missing_ok=True)
        raise

def build_plan() -> list[dict]:
    p = []
    def add(rva: int, new: int, reason: str):
        p.append({'rva': rva, 'old': SITES[rva], 'new': new, 'reason': reason})

    add(0x237ADC, enc_b(0x237ADC, 0x237AF4), 'normal-flow skip over byte force stub')
    add(0x237AE0, 0x52800029, 'stub: MOV W9,#1')
    add(0x237AE4, 0x089FFFA9, 'stub: STLRB W9,[X29] => byte_36AE84=1')
    add(0x237AE8, enc_b(0x237AE8, 0x217B2C), 'stub: return after replaced LDARB')
    add(0x217B28, enc_b(0x217B28, 0x237AE0), 'replace hidden LDARB with real-memory byte force stub')

    add(0x23BDEC, NOP, 'block byte_36AE84 reset-to-zero')
    add(0x244B54, NOP, 'block byte_36AE84 reset-to-zero')

    add(0x23E8DC, enc_b(0x23E8DC, 0x23E8F4), 'normal-flow skip over dword force stub')
    add(0x23E8E0, 0x52800068, 'stub: MOV W8,#3')
    add(0x23E8E4, 0xB90F3708, 'stub: STR W8,[X24,#0xF34] => dword_36AF34=3')
    add(0x23E8E8, enc_b(0x23E8E8, 0x217BE4), 'stub: return after replaced LDR')
    add(0x217BE0, enc_b(0x217BE0, 0x23E8E0), 'replace central state LDR with real-memory dword force stub')

    add(0x217B4C, NOP, 'block dword_36AF34 reset-to-zero')
    add(0x217BF8, 0x52800068, 'transition writer: MOV W8,#1 -> MOV W8,#3')
    add(0x217DD4, 0x52800068, 'transition writer: MOV W8,#2 -> MOV W8,#3')
    return p

def main() -> int:
    ap = argparse.ArgumentParser(description='Exact-build v6 real-memory state force patch')
    ap.add_argument('elf', type=Path)
    ap.add_argument('-o', '--output', type=Path)
    ap.add_argument('--manifest', type=Path, default=Path('patch_manifest_v6.json'))
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
    seen = set()
    for x in plan:
        rva = x['rva']
        if rva in seen:
            raise SystemExit(f'duplicate plan RVA 0x{rva:X}')
        seen.add(rva)
        if word(src, rva) != x['old']:
            raise SystemExit(f'pre-write guard changed at 0x{rva:X}')
        outb[rva:rva+4] = int(x['new']).to_bytes(4, 'little')

    assert word(outb, 0x23C6B8) == 0x5280002A
    assert word(outb, 0x23C6CC) == 0x089FFD0A
    assert word(outb, 0x217E14) == 0x5280006A
    assert word(outb, 0x217E20) == 0xB90F370A

    after = sha256(bytes(outb))
    manifest = {
        'version': 6,
        'mode': 'exact-build-real-memory-state-force',
        'input': str(a.elf),
        'sha256_before': got,
        'sha256_after': after,
        'targets': {'byte_36AE84': 1, 'dword_36AF34': 3},
        'plan': [
            {**x, 'old': f"0x{x['old']:08X}", 'new': f"0x{x['new']:08X}",
             'new_bytes_le': int(x['new']).to_bytes(4,'little').hex()}
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
        print('[+] dry-run: guards and plan verified; no ELF written')
        return 0
    out = a.output or a.elf.with_name(a.elf.stem + '.v6-state' + a.elf.suffix)
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
            raise SystemExit(f'post-write word verification failed at 0x{x["rva"]:X}')
    print(f'[+] output       : {out}')
    print(f'[+] verified     : {len(plan)} patched instructions')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
