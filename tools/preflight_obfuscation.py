#!/usr/bin/env python3
import csv
import json
import math
import sys
from collections import Counter
from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
except Exception:
    ELFFile = None

if len(sys.argv) != 3:
    raise SystemExit('usage: preflight_obfuscation.py <input.so> <output-dir>')

src = Path(sys.argv[1])
out = Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
MAGIC = b'\x7fELF'


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if b in (9, 10, 13) or 32 <= b <= 126)
    return printable / len(data)


def valid_elf_header(data: bytes) -> bool:
    if len(data) < 64 or data[:4] != MAGIC:
        return False
    elf_class = data[4]
    endian = data[5]
    version = data[6]
    if elf_class not in (1, 2) or endian not in (1, 2) or version != 1:
        return False
    order = 'little' if endian == 1 else 'big'
    e_type = int.from_bytes(data[16:18], order)
    e_machine = int.from_bytes(data[18:20], order)
    return e_type in (1, 2, 3, 4) and 0 < e_machine < 0x10000


def xor_bytes(data: bytes, key: bytes) -> bytes:
    n = len(key)
    return bytes(b ^ key[i % n] for i, b in enumerate(data))


def try_simple_xor(data: bytes):
    # Common wrapper: one-byte XOR over the entire file.
    for key in range(256):
        head = bytes(b ^ key for b in data[:64])
        if valid_elf_header(head):
            return bytes([key]), 'single-byte-xor'

    # Common lightweight wrapper: repeating 4-byte XOR. The ELF magic reveals the key.
    if len(data) >= 64:
        key = bytes(data[i] ^ MAGIC[i] for i in range(4))
        head = xor_bytes(data[:64], key)
        if valid_elf_header(head):
            return key, 'repeating-4-byte-xor'
    return None, None


raw = src.read_bytes()
report = {
    'source': str(src),
    'size_bytes': len(raw),
    'first_16_hex': raw[:16].hex(),
    'whole_file_entropy': round(entropy(raw), 4),
    'printable_ratio': round(printable_ratio(raw), 4),
    'is_elf': valid_elf_header(raw[:64]),
    'analysis_target': None,
    'recovery': None,
    'warnings': [],
    'sections': [],
    'segments': [],
}

analysis_target = src
if not report['is_elf']:
    key, method = try_simple_xor(raw)
    if key:
        recovered = xor_bytes(raw, key)
        recovered_path = out / 'recovered_simple_xor.so'
        recovered_path.write_bytes(recovered)
        analysis_target = recovered_path
        report['analysis_target'] = str(recovered_path)
        report['recovery'] = {
            'method': method,
            'key_hex': key.hex(),
            'validated_elf_header': True,
        }
        report['warnings'].append(
            'Input was not ELF but a simple XOR wrapper was recovered automatically.'
        )
    else:
        analysis_target = None
        report['warnings'].append(
            'Input is not a valid ELF and simple single-byte/repeating-4-byte XOR recovery did not succeed.'
        )
        if report['whole_file_entropy'] >= 7.5:
            report['warnings'].append(
                'High whole-file entropy suggests encryption/compression/packing; runtime unpacking may be required.'
            )
else:
    report['analysis_target'] = str(src)

# 64 KiB entropy windows help locate packed/encrypted regions even when the ELF itself remains valid.
with (out / 'entropy_windows.csv').open('w', encoding='utf-8', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['offset', 'size', 'entropy', 'printable_ratio'])
    step = 65536
    for offset in range(0, len(raw), step):
        chunk = raw[offset:offset + step]
        writer.writerow([
            f'0x{offset:X}',
            len(chunk),
            f'{entropy(chunk):.4f}',
            f'{printable_ratio(chunk):.4f}',
        ])

if analysis_target and ELFFile is not None:
    try:
        with analysis_target.open('rb') as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                try:
                    data = section.data()
                except Exception:
                    data = b''
                flags = int(section['sh_flags'])
                item = {
                    'name': section.name,
                    'type': str(section['sh_type']),
                    'address': int(section['sh_addr']),
                    'offset': int(section['sh_offset']),
                    'size': int(section['sh_size']),
                    'flags': flags,
                    'entropy': round(entropy(data), 4),
                    'printable_ratio': round(printable_ratio(data), 4),
                    'executable': bool(flags & 0x4),
                    'writable': bool(flags & 0x1),
                }
                report['sections'].append(item)
                if item['executable'] and item['size'] >= 4096 and item['entropy'] >= 7.5:
                    report['warnings'].append(
                        f"Executable section {section.name or '<unnamed>'} has very high entropy ({item['entropy']}); packed/encrypted code is possible."
                    )

            for segment in elf.iter_segments():
                flags = int(segment['p_flags'])
                item = {
                    'type': str(segment['p_type']),
                    'flags': flags,
                    'offset': int(segment['p_offset']),
                    'virtual_address': int(segment['p_vaddr']),
                    'file_size': int(segment['p_filesz']),
                    'memory_size': int(segment['p_memsz']),
                    'executable': bool(flags & 1),
                    'writable': bool(flags & 2),
                    'readable': bool(flags & 4),
                }
                report['segments'].append(item)
                if item['executable'] and item['writable']:
                    report['warnings'].append(
                        f"Segment at 0x{item['virtual_address']:X} is writable+executable (W+X); self-modifying/unpacking behavior is possible."
                    )
    except Exception as exc:
        report['warnings'].append('ELF structural parse failed: ' + repr(exc))

(out / 'preflight_obfuscation.json').write_text(
    json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8'
)
with (out / 'preflight_obfuscation.md').open('w', encoding='utf-8') as w:
    w.write('# Packing / encryption preflight\n\n')
    w.write(f"- Source: `{src}`\n")
    w.write(f"- Size: **{len(raw)}** bytes\n")
    w.write(f"- ELF: **{report['is_elf']}**\n")
    w.write(f"- Whole-file entropy: **{report['whole_file_entropy']} / 8.0**\n")
    w.write(f"- Printable ratio: **{report['printable_ratio']}**\n")
    if report['recovery']:
        w.write(
            f"- Auto-recovery: **{report['recovery']['method']}**, key `{report['recovery']['key_hex']}`\n"
        )
    w.write('\n## Warnings / clues\n\n')
    warnings = list(dict.fromkeys(report['warnings']))
    if warnings:
        for warning in warnings:
            w.write(f'- {warning}\n')
    else:
        w.write('- No obvious whole-file/section-level packing signal from these static heuristics.\n')
    w.write('\n`entropy_windows.csv` contains 64 KiB window entropy for locating suspicious regions.\n')
    w.write(
        '\nSimple XOR auto-recovery is intentionally conservative. Custom ciphers, runtime-derived keys, encrypted code pages, or loader-based unpacking require analysis of the decryptor or a runtime memory dump.\n'
    )

(out / 'analysis_target.txt').write_text(
    (str(analysis_target) if analysis_target else '') + '\n', encoding='utf-8'
)
print(json.dumps({
    'analysis_target': str(analysis_target) if analysis_target else None,
    'is_elf': report['is_elf'],
    'recovery': report['recovery'],
    'warnings': report['warnings'][:5],
}))
