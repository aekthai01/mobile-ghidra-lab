#!/usr/bin/env python3
"""Acceptance checks for V5.5 ARM64-grounded semantic C.

Fails if selected functions lose semantic-C coverage, CFG block provenance, or regress
back into raw P-code-noise tokens. Stress checks make the known 0x19C094 UI/license
function prove that branch structure, string recovery, and signed-divide idiom folding
survive the pipeline.
"""
import csv, json, re, sys
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: v55_semantic_validate.py <analysis-output-dir>')
root=Path(sys.argv[1]); human=root/'human'

def rows(path):
    p=root/path
    if not p.exists() or not p.stat().st_size:return []
    with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))
def canon(v):
    v=(v or '').strip();v=v[2:] if v.lower().startswith('0x') else v
    try:return f'{int(v,16):08X}'
    except:return v.upper()

def load_json(path):
    p=root/path
    if not p.exists():return None
    try:return json.loads(p.read_text(encoding='utf-8'))
    except Exception:return None

selected={canon(r.get('entry')):r for r in rows('v52_selected_functions.csv') if canon(r.get('entry'))}
idx=rows('human/SEMANTIC_C_INDEX.csv')
stats=load_json('v55_semantic_c_stats.json') or {}
errors=[]; warnings=[]

if not selected:errors.append('selected function list missing/empty')
if not idx:errors.append('semantic C index missing/empty')
if not stats:errors.append('semantic C stats missing/invalid')
if len(idx)!=len(selected):errors.append(f'semantic index coverage {len(idx)}/{len(selected)}')
if int(stats.get('semantic_c_files') or -1)!=len(selected):errors.append('semantic_c_files is not 100% of selected functions')
if stats.get('missing_functions'):errors.append('semantic C reports missing selected functions')
if int(stats.get('cfg_blocks_total') or 0)<=0:errors.append('semantic C CFG block total is empty')
if int(stats.get('semantic_blocks_total') or 0)<=0:errors.append('semantic block total is empty')
if int(stats.get('calls') or 0)<=0:errors.append('semantic C contains no recovered calls')
if int(stats.get('recovered_string_refs') or 0)<=0:errors.append('semantic C contains no recovered string refs')

for r in idx:
    try:cfg=int(r.get('cfg_blocks') or 0); sem=int(r.get('semantic_blocks') or 0)
    except:cfg=sem=-1
    if cfg>0 and sem!=cfg:errors.append(f"{r.get('ghidra_va')}: CFG block coverage {sem}/{cfg}")
    cp=human/(r.get('compact_c_path') or '')
    dp=human/(r.get('semantic_c_path') or '')
    if not cp.exists() or not cp.stat().st_size:errors.append(f"{r.get('ghidra_va')}: compact semantic C missing")
    if not dp.exists() or not dp.stat().st_size:errors.append(f"{r.get('ghidra_va')}: detailed semantic C missing")

forbidden=[r'int_carry\s*\(',r'int_scarry\s*\(',r'bool_negate\s*\(',r'\btmp_23500_8\b',r'\breg_105_1\b']
for r in idx:
    for key in ('semantic_c_path','compact_c_path'):
        p=human/(r.get(key) or '')
        if not p.exists():continue
        txt=p.read_text(encoding='utf-8',errors='replace')
        for pat in forbidden:
            if re.search(pat,txt):errors.append(f"{r.get('ghidra_va')}: forbidden raw-P-code token {pat} in {key}")

# Known stress function from the user's exact sample. Only enforce if selected.
stress='0029C094'
stress_row=next((r for r in idx if canon(r.get('ghidra_va'))==stress),None)
if stress in selected:
    if not stress_row:errors.append(f'{stress}: semantic index row missing')
    else:
        p=human/(stress_row.get('compact_c_path') or '')
        txt=p.read_text(encoding='utf-8',errors='replace') if p.exists() else ''
        must=[
            'CINC + ASR => trunc toward zero',
            'Your access has been expired!',
            'Please renew your license.',
            't.me/VVIPMODS_OFFICIAL',
            'if (',
            'loc_0019C4E0:',
        ]
        for token in must:
            if token not in txt:errors.append(f'{stress}: compact semantic C missing {token!r}')
        if stats.get('elf_string_scan_enabled') and '"Exit"' not in txt:
            errors.append(f'{stress}: ELF scan enabled but Exit string was not recovered')
        if 'now_ret_x0_0019C328 >= from_time_t_ret_x0_0019C2F8' not in txt:
            warnings.append(f'{stress}: expected distinct call-return comparison not found')

report={
    'selected_functions':len(selected),
    'semantic_index_rows':len(idx),
    'semantic_c_files':int(stats.get('semantic_c_files') or 0),
    'cfg_blocks_total':int(stats.get('cfg_blocks_total') or 0),
    'semantic_blocks_total':int(stats.get('semantic_blocks_total') or 0),
    'idiom_folds':int(stats.get('idiom_folds') or 0),
    'calls':int(stats.get('calls') or 0),
    'recovered_string_refs':int(stats.get('recovered_string_refs') or 0),
    'elf_string_scan_enabled':bool(stats.get('elf_string_scan_enabled')),
    'warnings':warnings,
    'errors':errors,
    'status':'pass' if not errors else 'fail',
}
(root/'v55_semantic_acceptance.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
(root/'v55_semantic_acceptance.md').write_text(
    '# V5.5 ARM64-grounded semantic C acceptance\n\n'+
    ''.join(f'- {k.replace("_"," ").title()}: **{v}**\n' for k,v in report.items() if k not in ('errors','warnings'))+
    ('\n## Warnings\n'+''.join(f'- {x}\n' for x in warnings) if warnings else '')+
    ('\n## Errors\n'+''.join(f'- {x}\n' for x in errors) if errors else ''),
    encoding='utf-8')
if errors:
    raise SystemExit('V5.5 semantic C acceptance failed: '+'; '.join(errors[:10]))
print(json.dumps(report))
