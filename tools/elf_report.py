#!/usr/bin/env python3
import hashlib
import json
import os
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    if len(sys.argv) != 3:
        print('usage: elf_report.py <input.so> <output.json>', file=sys.stderr)
        return 2

    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    dst.parent.mkdir(parents=True, exist_ok=True)

    report = {
        'file': str(src),
        'size_bytes': src.stat().st_size,
        'sha256': sha256_file(src),
        'elf': {},
        'sections': [],
        'segments': [],
        'needed_libraries': [],
        'dynamic_tags': [],
        'symbol_tables': {},
        'notes': [],
    }

    with src.open('rb') as f:
        elf = ELFFile(f)
        hdr = elf.header
        report['elf'] = {
            'class': elf.elfclass,
            'little_endian': elf.little_endian,
            'machine': str(hdr['e_machine']),
            'type': str(hdr['e_type']),
            'entry': int(hdr['e_entry']),
            'osabi': str(hdr['e_ident']['EI_OSABI']),
            'abi_version': int(hdr['e_ident']['EI_ABIVERSION']),
            'num_sections': elf.num_sections(),
            'num_segments': elf.num_segments(),
        }

        for sec in elf.iter_sections():
            item = {
                'name': sec.name,
                'type': str(sec['sh_type']),
                'address': int(sec['sh_addr']),
                'offset': int(sec['sh_offset']),
                'size': int(sec['sh_size']),
                'flags': int(sec['sh_flags']),
                'alignment': int(sec['sh_addralign']),
            }
            report['sections'].append(item)

            if sec.name in ('.dynsym', '.symtab') and hasattr(sec, 'iter_symbols'):
                total = 0
                defined = 0
                undefined = 0
                globals_ = 0
                functions = 0
                objects = 0
                for sym in sec.iter_symbols():
                    total += 1
                    shndx = sym['st_shndx']
                    if shndx == 'SHN_UNDEF':
                        undefined += 1
                    else:
                        defined += 1
                    bind = str(sym['st_info']['bind'])
                    typ = str(sym['st_info']['type'])
                    if bind in ('STB_GLOBAL', 'STB_WEAK'):
                        globals_ += 1
                    if typ == 'STT_FUNC':
                        functions += 1
                    elif typ == 'STT_OBJECT':
                        objects += 1
                report['symbol_tables'][sec.name] = {
                    'total': total,
                    'defined': defined,
                    'undefined': undefined,
                    'global_or_weak': globals_,
                    'functions': functions,
                    'objects': objects,
                }

            if sec.name == '.dynamic' and hasattr(sec, 'iter_tags'):
                for tag in sec.iter_tags():
                    tag_name = str(tag.entry.d_tag)
                    value = None
                    if hasattr(tag, 'needed'):
                        value = tag.needed
                        report['needed_libraries'].append(value)
                    elif hasattr(tag, 'soname'):
                        value = tag.soname
                    elif hasattr(tag, 'rpath'):
                        value = tag.rpath
                    elif hasattr(tag, 'runpath'):
                        value = tag.runpath
                    elif hasattr(tag.entry, 'd_val'):
                        try:
                            value = int(tag.entry.d_val)
                        except Exception:
                            value = str(tag.entry.d_val)
                    report['dynamic_tags'].append({'tag': tag_name, 'value': value})

        for seg in elf.iter_segments():
            report['segments'].append({
                'type': str(seg['p_type']),
                'offset': int(seg['p_offset']),
                'virtual_address': int(seg['p_vaddr']),
                'physical_address': int(seg['p_paddr']),
                'file_size': int(seg['p_filesz']),
                'memory_size': int(seg['p_memsz']),
                'flags': int(seg['p_flags']),
                'alignment': int(seg['p_align']),
            })

        for sec in elf.iter_sections():
            if sec['sh_type'] == 'SHT_NOTE' and hasattr(sec, 'iter_notes'):
                for note in sec.iter_notes():
                    desc = note.get('n_desc')
                    if isinstance(desc, bytes):
                        desc = desc.hex()
                    elif not isinstance(desc, (str, int, float, bool, type(None), list, dict)):
                        desc = str(desc)
                    report['notes'].append({
                        'name': str(note.get('n_name')),
                        'type': str(note.get('n_type')),
                        'description': desc,
                    })

    # Stable order and no duplicates while preserving first appearance.
    report['needed_libraries'] = list(dict.fromkeys(report['needed_libraries']))
    dst.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    print(dst)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
