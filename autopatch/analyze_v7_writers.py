#!/usr/bin/env python3
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

SITES = [
    0x23BDEC, 0x23C6CC, 0x244B54,
    0x217B4C, 0x217BFC, 0x217DDC, 0x217E20,
]


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--radius', type=int, default=10)
    a = ap.parse_args()
    data = a.elf.read_bytes()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    for site in SITES:
        print(f'\n=== 0x{site:X} ===')
        start = max(0, site - a.radius * 4)
        end = min(len(data), site + (a.radius + 1) * 4)
        for ins in md.disasm(data[start:end], start):
            mark = '=>' if ins.address == site else '  '
            raw = data[ins.address:ins.address+4].hex()
            print(f'{mark} 0x{ins.address:08X} {raw}  {ins.mnemonic:8s} {ins.op_str}')

if __name__ == '__main__':
    main()
