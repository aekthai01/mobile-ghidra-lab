#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

NOP = b'\x1f\x20\x03\xd5'


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--near', type=lambda x: int(x, 0), default=0x244B54)
    ap.add_argument('--min-insns', type=int, default=4)
    ap.add_argument('--limit', type=int, default=30)
    a = ap.parse_args()

    with a.elf.open('rb') as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name('.text')
        if text is None:
            raise SystemExit('.text not found')
        text_rva = int(text['sh_addr'])
        text_off = int(text['sh_offset'])
        data = text.data()

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    branch_targets: set[int] = set()
    for ins in md.disasm(data, text_rva):
        if ins.mnemonic in {'b','bl','b.eq','b.ne','b.hs','b.lo','b.mi','b.pl','b.vs','b.vc','b.hi','b.ls','b.ge','b.lt','b.gt','b.le','cbz','cbnz','tbz','tbnz'}:
            for op in ins.operands:
                if op.type == ARM64_OP_IMM:
                    branch_targets.add(int(op.imm))

    runs = []
    i = 0
    while i + 4 <= len(data):
        if data[i:i+4] != NOP:
            i += 4
            continue
        j = i
        while j + 4 <= len(data) and data[j:j+4] == NOP:
            j += 4
        count = (j - i) // 4
        if count >= a.min_insns:
            start = text_rva + i
            end = text_rva + j
            inbound = sorted(t for t in branch_targets if start <= t < end)
            runs.append((abs(start-a.near), start, end, count, inbound, text_off+i))
        i = j

    runs.sort()
    print(f'.text RVA=0x{text_rva:X} size=0x{len(data):X}')
    print(f'direct branch targets decoded={len(branch_targets)}')
    print(f'NOP runs >= {a.min_insns} insns={len(runs)}')
    for _, start, end, count, inbound, off in runs[:a.limit]:
        verdict = 'SAFE-DIRECT' if not inbound else 'HAS-INBOUND'
        inbound_s = ','.join(f'0x{x:X}' for x in inbound[:8]) or '-'
        print(f'0x{start:X}-0x{end-4:X} count={count} file=0x{off:X} dist=0x{abs(start-a.near):X} {verdict} inbound={inbound_s}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
