#!/usr/bin/env python3
import csv, json, re, sys
from collections import defaultdict
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: v51_high_pcode_slices.py <analysis-output-dir>')
root = Path(sys.argv[1])

def rows(name):
    p=root/name
    if not p.exists() or p.stat().st_size==0: return []
    with p.open(encoding='utf-8',errors='replace',newline='') as f: return list(csv.DictReader(f))

def canon(x):
    try:return f'{int((x or "").strip(),16):08X}'
    except Exception:return (x or '').strip().upper()

def split_inputs(s): return [x.strip() for x in (s or '').split(' | ') if x.strip()]

def pretty(v):
    v=(v or '').strip()
    m=re.fullmatch(r'\(const, 0x([0-9a-fA-F]+), (\d+)\)',v)
    if m:return f'0x{int(m.group(1),16):X}'
    m=re.fullmatch(r'\(unique, 0x([0-9a-fA-F]+), (\d+)\)',v)
    if m:return f'u_{m.group(1).upper()}:{m.group(2)}'
    m=re.fullmatch(r'\(register, 0x([0-9a-fA-F]+), (\d+)\)',v)
    if m:return f'REG[0x{int(m.group(1),16):X}:{m.group(2)}]'
    m=re.fullmatch(r'\(ram, 0x([0-9a-fA-F]+), (\d+)\)',v)
    if m:return f'RAM[0x{int(m.group(1),16):X}]'
    return v

high=rows('v51_high_pcode.csv')
indirect=rows('v5_indirect_branches.csv')
validation=rows('v5_jump_table_validation.csv')
valid={(canon(r.get('function_entry')),canon(r.get('branch_address'))):r for r in validation}
by_func=defaultdict(list)
for r in high:
    e=canon(r.get('function_entry'))
    if e: by_func[e].append(r)

def build_defs(xs):
    defs={}
    for r in xs:
        o=(r.get('output') or '').strip()
        if o: defs[o]=r
    return defs

def expr(var,defs,depth=0,seen=None):
    if seen is None: seen=set()
    pv=pretty(var)
    if not var or depth>=14 or var in seen:return pv
    r=defs.get(var)
    if not r:return pv
    seen=set(seen);seen.add(var)
    op=(r.get('mnemonic') or '').upper()
    ins=split_inputs(r.get('inputs'))
    es=[expr(x,defs,depth+1,seen) for x in ins]
    if op in ('COPY','CAST','INT_ZEXT','INT_SEXT','SUBPIECE') and es:
        if op=='INT_ZEXT':return f'zext({es[0]})'
        if op=='INT_SEXT':return f'sext({es[0]})'
        if op=='SUBPIECE':return f'subpiece({", ".join(es)})'
        return es[0]
    if op=='MULTIEQUAL':return 'phi(' + ', '.join(es[:8]) + (', ...' if len(es)>8 else '') + ')'
    if op=='INT_ADD' and len(es)>=2:return f'({es[0]} + {es[1]})'
    if op=='INT_SUB' and len(es)>=2:return f'({es[0]} - {es[1]})'
    if op=='INT_MULT' and len(es)>=2:return f'({es[0]} * {es[1]})'
    if op=='INT_LEFT' and len(es)>=2:return f'({es[0]} << {es[1]})'
    if op in ('INT_RIGHT','INT_SRIGHT') and len(es)>=2:return f'({es[0]} >> {es[1]})'
    if op=='LOAD' and es:return f'LOAD[{es[-1]}]'
    if op=='PTRADD' and len(es)>=3:return f'({es[0]} + {es[1]}*{es[2]})'
    if op=='PTRSUB' and len(es)>=2:return f'({es[0]} + {es[1]})'
    if op in ('INT_AND','INT_OR','INT_XOR') and len(es)>=2:
        sym={'INT_AND':'&','INT_OR':'|','INT_XOR':'^'}[op];return f'({es[0]} {sym} {es[1]})'
    if op=='INDIRECT' and es:return f'indirect({es[0]})'
    return op+'('+', '.join(es)+')'

records=[]
outdir=root/'v51_high_pcode_slices';outdir.mkdir(exist_ok=True)
for r in indirect:
    e,addr=canon(r.get('function_entry')),canon(r.get('branch_address'))
    xs=by_func.get(e,[])
    if not xs:continue
    branch=None
    for q in xs:
        if canon(q.get('sequence_address'))==addr and (q.get('mnemonic') or '').upper()=='BRANCHIND':
            branch=q;break
    if not branch:continue
    ins=split_inputs(branch.get('inputs')); target=ins[0] if ins else ''
    defs=build_defs(xs); expression=expr(target,defs)
    vr=valid.get((e,addr),{})
    path=outdir/f'{e}_{addr}.md'
    with path.open('w',encoding='utf-8') as w:
        w.write(f'# V5.1 high-P-code slice `{e}` / `0x{addr}`\n\n')
        w.write(f'- Function: `{r.get("function_name","")}`\n- Static validation: `{vr.get("classification", "not-applicable")}`\n- Target varnode: `{target}`\n\n')
        w.write('## SSA target expression\n\n```text\n'+expression+'\n```\n\n')
        w.write('This expression is reconstructed from Ghidra high P-code definition/use relationships. `phi(...)` represents merged control-flow definitions and should not be mistaken for a single runtime value.\n')
    records.append({'function_entry':e,'function_name':r.get('function_name',''),'branch_address':addr,'static_validation':vr.get('classification',''),'target_high_varnode':target,'target_expression':expression,'slice_path':str(path.relative_to(root))})

fields=['function_entry','function_name','branch_address','static_validation','target_high_varnode','target_expression','slice_path']
with (root/'v51_high_pcode_indirect_slices.csv').open('w',encoding='utf-8',newline='') as f:
    w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(records)
with (root/'v51_high_pcode_slices_report.md').open('w',encoding='utf-8') as w:
    w.write('# V5.1 SSA/high-P-code indirect-flow slices\n\n')
    w.write(f'- Indirect branches with high-P-code slices: **{len(records)}**\n')
    w.write('- High P-code is preferred over the older linear raw-P-code `last definition` heuristic because it preserves decompiler definition/use structure and phi/MULTIEQUAL nodes.\n\n')
    w.write('| Function | Branch | Validation | Expression |\n|---|---|---|---|\n')
    for r in records[:120]:w.write(f"| `{r['function_entry']}` | `{r['branch_address']}` | {r['static_validation']} | `{r['target_expression'].replace('|','\\|')[:240]}` |\n")
print(json.dumps({'high_pcode_indirect_slices':len(records)}))
