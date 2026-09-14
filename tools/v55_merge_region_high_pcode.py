#!/usr/bin/env python3
"""Merge successful V5.5 region High-P-code rows into the late-stage SSA stream.

The original region file remains intact as forensic evidence. This only enriches the
combined v51_high_pcode.csv consumed by V5.5 reconstruction after earlier V5.1 tools ran.
"""
import csv, json, sys
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: v55_merge_region_high_pcode.py <analysis-output-dir>')
root = Path(sys.argv[1])
base = root / 'v51_high_pcode.csv'
region = root / 'v55_region_high_pcode.csv'
if not base.exists() or not region.exists():
    raise SystemExit('missing base or region High-P-code CSV')

fields = ['rank','function_entry','function_name','mode','tier','sequence_address','sequence_time','opcode','mnemonic','output','inputs']
existing = set()
with base.open(encoding='utf-8', errors='replace', newline='') as f:
    for r in csv.DictReader(f):
        existing.add((r.get('function_entry','').upper(), r.get('sequence_address','').upper(), r.get('sequence_time',''), r.get('mnemonic',''), r.get('output',''), r.get('inputs','')))

added = 0
with region.open(encoding='utf-8', errors='replace', newline='') as src, base.open('a', encoding='utf-8', newline='') as dst:
    rd = csv.DictReader(src)
    wr = csv.DictWriter(dst, fieldnames=fields)
    for r in rd:
        key = (r.get('function_entry','').upper(), r.get('sequence_address','').upper(), r.get('sequence_time',''), r.get('mnemonic',''), r.get('output',''), r.get('inputs',''))
        if key in existing:
            continue
        existing.add(key)
        wr.writerow({
            'rank': '0',
            'function_entry': r.get('function_entry',''),
            'function_name': r.get('function_name',''),
            'mode': 'region',
            'tier': 'A-protected-region',
            'sequence_address': r.get('sequence_address',''),
            'sequence_time': r.get('sequence_time',''),
            'opcode': r.get('opcode',''),
            'mnemonic': r.get('mnemonic',''),
            'output': r.get('output',''),
            'inputs': r.get('inputs',''),
        })
        added += 1
report = {'region_high_pcode_rows_added': added, 'combined_unique_rows': len(existing)}
(root / 'v55_region_high_pcode_merge.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps(report))
