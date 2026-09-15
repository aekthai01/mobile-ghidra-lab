#!/usr/bin/env python3
"""V5.5 semantic-C quality gate V2.

Measures reconstruction against ARM64 ground truth, tags inference confidence, rejects
raw P-code leakage, and enforces the known 0x29C094 regression target.
"""
import csv, hashlib, json, re, sys
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: v55_semantic_quality_v2.py <analysis-output-dir>')
root=Path(sys.argv[1]); human=root/'human'; compact=human/'semantic_c_compact'; detailed=human/'semantic_c'
BASE=0x100000

def csvrows(p):
    p=root/p
    if not p.exists(): return []
    with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))

def add_confidence_header(p):
    txt=p.read_text(encoding='utf-8',errors='replace')
    if ' * Confidence policy:' in txt:return txt
    needle=' * This is reconstruction, NOT original source code.\n'
    policy=(
        ' * Confidence policy: EXACT = instruction/address/CFG facts copied from ARM64 evidence;\n'
        ' * STRONG = deterministic lowering or ABI/data-flow reconstruction backed by ARM64/CFG;\n'
        ' * HEURISTIC = inferred labels/strings or incomplete semantics; never treated as original source.\n')
    if needle in txt:
        txt=txt.replace(needle,needle+policy,1);p.write_text(txt,encoding='utf-8')
    return txt

idx=csvrows('human/SEMANTIC_C_INDEX.csv'); errors=[]
for r in idx:
    for key in ('semantic_c_path','compact_c_path'):
        p=human/(r.get(key) or '')
        if p.exists(): add_confidence_header(p)

# Build exact IDA/RVA-address maps from compact semantic C.
addr_lines={}
all_text=[]
for p in compact.glob('*.c'):
    txt=p.read_text(encoding='utf-8',errors='replace');all_text.append(txt)
    for line in txt.splitlines():
        m=re.search(r'IDA/RVA 0x([0-9A-Fa-f]+)',line)
        if m:addr_lines.setdefault(int(m.group(1),16),[]).append(line)
joined='\n'.join(all_text)

# Generic P-code implementation noise is forbidden, not merely five sample names.
noise={
 'int_carry':len(re.findall(r'\bint_carry\s*\(',joined)),
 'int_scarry':len(re.findall(r'\bint_scarry\s*\(',joined)),
 'bool_negate':len(re.findall(r'\bbool_negate\s*\(',joined)),
 'tmp_vars':len(re.findall(r'\btmp_[A-Za-z0-9_]+\b',joined)),
 'reg_pcode_vars':len(re.findall(r'\breg_[0-9]+_[0-9]+\b',joined)),
 'raw_call_mem':len(re.findall(r'call\s*\(\s*mem_',joined)),
 'raw_goto_mem':len(re.findall(r'goto\s+mem_',joined)),
}
if any(noise.values()):errors.append('raw P-code implementation noise remains: '+json.dumps(noise,sort_keys=True))
if idx and not all(x in joined for x in ('Confidence policy: EXACT','STRONG =','HEURISTIC =')):
    errors.append('confidence policy tags missing from semantic C')

# ARM64 direct branch/call preservation: match each instruction by its exact IDA/RVA.
branch_total=branch_ok=call_total=call_ok=0
asm_re=re.compile(r'^\.text:[0-9A-Fa-f]{16}\s+(?:[0-9A-Fa-f]{2}\s+){4}\s*([A-Za-z0-9.]+)\s*(.*?)\s*;.*IDA_RVA=0x([0-9A-Fa-f]+)',re.I)
for p in (human/'asm_full').glob('*.asm'):
    for line in p.read_text(encoding='utf-8',errors='replace').splitlines():
        m=asm_re.match(line)
        if not m:continue
        mn,op,addr=m.group(1).upper(),m.group(2),int(m.group(3),16); lines=addr_lines.get(addr,[])
        if mn=='B' or mn.startswith('B.') or mn in ('CBZ','CBNZ','TBZ','TBNZ'):
            mt=re.search(r'loc_([0-9A-Fa-f]+)',op,re.I)
            if mt:
                branch_total+=1;x=int(mt.group(1),16);target=x-BASE if x>=BASE else x
                if any(f'loc_{target:08X}' in q for q in lines):branch_ok+=1
        elif mn=='BL':
            tgt=op.split(',',1)[0].strip();call_total+=1
            if any((tgt+'(').lower() in q.lower() for q in lines):call_ok+=1
branch_pct=100.0*branch_ok/branch_total if branch_total else 100.0
call_pct=100.0*call_ok/call_total if call_total else 100.0
if branch_pct<95:errors.append(f'direct branch target reconstruction {branch_pct:.2f}% < 95%')
if call_pct<95:errors.append(f'direct call preservation {call_pct:.2f}% < 95%')

# Known Ghidra string xrefs whose instruction is selected must survive as literals.
string_total=string_ok=0
for r in csvrows('string_xrefs.csv'):
    try:
        a=int((r.get('from_address') or '0').replace('0x',''),16);addr=a-BASE if a>=BASE else a
    except:continue
    lines=addr_lines.get(addr)
    if not lines:continue
    value=(r.get('value') or '').strip().strip('"')
    if not value:continue
    string_total+=1
    if any(value in q for q in lines):string_ok+=1
string_pct=100.0*string_ok/string_total if string_total else 100.0
if string_pct<95:errors.append(f'known string-xref lifting {string_pct:.2f}% < 95%')

# V5.4 protected manifest must remain byte-for-byte intact.
manifest_path=root/'v54_protected_manifest.json'; manifest=[]
try:manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
except Exception:errors.append('V5.4 protected manifest missing/invalid')
manifest_ok=0
for e in manifest if isinstance(manifest,list) else []:
    p=root/e.get('path','')
    if p.is_file() and p.stat().st_size==int(e.get('bytes',-1)) and hashlib.sha256(p.read_bytes()).hexdigest()==e.get('sha256'):
        manifest_ok+=1
if len(manifest)!=115 or manifest_ok!=115:errors.append(f'V5.4 protected manifest integrity {manifest_ok}/{len(manifest)}; expected 115/115')

# Exact stress target from the user's sample.
stress=next(compact.glob('0019C094_0029C094_*.c'),None)
stress_txt=stress.read_text(encoding='utf-8',errors='replace') if stress else ''
for token in ('loc_0019C56C:','Your access has been expired!','Please renew your license.','Telegram:','t.me/VVIPMODS_OFFICIAL','"Exit"','CINC + ASR => trunc toward zero',' - 175',' - 85'):
    if token not in stress_txt:errors.append(f'0029C094 missing stress token {token!r}')

report={
 'semantic_c_files':len(idx),'pcode_noise':noise,
 'direct_branches_total':branch_total,'direct_branches_preserved':branch_ok,'direct_branch_target_pct':round(branch_pct,4),
 'direct_calls_total':call_total,'direct_calls_preserved':call_ok,'direct_call_preservation_pct':round(call_pct,4),
 'known_string_xrefs_total':string_total,'known_string_xrefs_lifted':string_ok,'known_string_xref_lifting_pct':round(string_pct,4),
 'confidence_tags':['EXACT','STRONG','HEURISTIC'],'protected_manifest_total':len(manifest),'protected_manifest_verified':manifest_ok,
 'stress_0029C094':'pass' if not any(x.startswith('0029C094') for x in errors) else 'fail',
 'errors':errors,'status':'pass' if not errors else 'fail'}
(root/'v55_semantic_quality_v2.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
(root/'v55_semantic_quality_v2.md').write_text('# V5.5 Semantic C Quality Gate V2\n\n'+''.join(f'- {k.replace("_"," ").title()}: **{v}**\n' for k,v in report.items() if k!='errors')+('\n## Errors\n'+''.join(f'- {e}\n' for e in errors) if errors else ''),encoding='utf-8')
print(json.dumps(report))
if errors:raise SystemExit('semantic quality gate V2 failed: '+'; '.join(errors[:10]))
