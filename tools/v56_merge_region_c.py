#!/usr/bin/env python3
import csv, re, shutil, sys
from collections import defaultdict
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: v56_merge_region_c.py <analysis-output-dir>')
root = Path(sys.argv[1])
human = root / 'human' / 'reconstructed_c_v56'
human.mkdir(parents=True, exist_ok=True)
full_dir = human / 'full'
full_dir.mkdir(exist_ok=True)

# Preserve every successful whole-function Ghidra decompile. These are the closest output to IDA/Ghidra pseudocode.
whole = []
for src in sorted((root / 'v4_decompiled_selected').glob('*.c')) if (root / 'v4_decompiled_selected').exists() else []:
    dst = full_dir / src.name
    shutil.copyfile(src, dst)
    whole.append(dst)

idx = root / 'v56_region_c_index.csv'
rows = []
if idx.exists() and idx.stat().st_size:
    with idx.open(encoding='utf-8', errors='replace', newline='') as f:
        rows = list(csv.DictReader(f))

def canon(v):
    v=(v or '').strip(); v=v[2:] if v.lower().startswith('0x') else v
    try:return f'{int(v,16):08X}'
    except:return v.upper()

def safe(v):
    return (re.sub(r'[^A-Za-z0-9._-]+','_',v or 'function').strip('_') or 'function')[:96]

def body_of(text):
    a=text.find('{'); b=text.rfind('}')
    if a < 0 or b <= a:
        return text.strip()
    return text[a+1:b].strip('\n')

groups=defaultdict(list)
for r in rows:
    if (r.get('status') or '').startswith('ok') and r.get('c_file'):
        groups[canon(r.get('function_entry'))].append(r)

merged=[]
for entry, rs in sorted(groups.items(), key=lambda kv:int(kv[0],16) if re.fullmatch(r'[0-9A-F]+',kv[0]) else 0):
    rs.sort(key=lambda r:int(canon(r.get('start_address')),16) if canon(r.get('start_address')).isalnum() else 0)
    name=(rs[0].get('function_name') or f'sub_{entry}')
    out=human/f'{entry}_{safe(name)}_regions.c'
    with out.open('w',encoding='utf-8') as w:
        w.write('/* V5.6 ordered region reconstruction.\n')
        w.write(' * Each block is real Ghidra decompiler C for an address-bounded temporary function.\n')
        w.write(' * Blocks are ordered by address; cross-region data/control flow is evidence-guided and not claimed as original source.\n */\n\n')
        w.write(f'void sub_{entry}_reconstructed(void)\n{{\n')
        for i,r in enumerate(rs,1):
            p=root/(r.get('c_file') or '')
            if not p.exists(): continue
            text=p.read_text(encoding='utf-8',errors='replace')
            w.write(f'\n  /* REGION {i:03d}: 0x{canon(r.get("start_address"))}..0x{canon(r.get("end_address"))} | {r.get("reason","")} */\n')
            w.write(f'REGION_{i:03d}:\n  {{\n')
            body=body_of(text)
            for line in body.splitlines():
                w.write('    '+line+'\n')
            w.write('  }\n')
        w.write('}\n')
    merged.append(out)

report=human/'V56_C_RECONSTRUCTION.md'
with report.open('w',encoding='utf-8') as w:
    w.write('# V5.6 C reconstruction\n\n')
    w.write('Whole-function files are native Ghidra decompiler output. Region files are used when whole-function decompilation is impractical or fails.\n\n')
    w.write(f'- Whole-function C files: **{len(whole)}**\n')
    w.write(f'- Region C rows: **{sum(len(v) for v in groups.values())}**\n')
    w.write(f'- Region-merged functions: **{len(merged)}**\n\n')
    if merged:
        w.write('## Region-merged functions\n\n')
        for p in merged:
            w.write(f'- `{p.name}`\n')
print(f'v5.6 C: whole={len(whole)} merged_region_functions={len(merged)} region_rows={sum(len(v) for v in groups.values())}')
