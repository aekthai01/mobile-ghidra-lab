#!/usr/bin/env python3
import csv, json, re, sys
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: v51_runtime_tables.py <analysis-output-dir>')
root=Path(sys.argv[1])

def rows(name):
    p=root/name
    if not p.exists() or p.stat().st_size==0:return []
    with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))

def canon(x):
    try:return f'{int((x or "").strip(),16):08X}'
    except Exception:return (x or '').strip().upper()

def split_ops(s):
    out=[];cur=[];depth=0
    for ch in s or '':
        if ch in '[{(':depth+=1
        elif ch in ']})':depth=max(0,depth-1)
        if ch==',' and depth==0:out.append(''.join(cur).strip());cur=[]
        else:cur.append(ch)
    if cur:out.append(''.join(cur).strip())
    return out

def reg_norm(s):
    s=(s or '').strip().upper()
    m=re.fullmatch(r'([WX])(\d{1,2})',s)
    return 'X'+m.group(2) if m else s

def memory_base(ops):
    m=re.search(r'\[\s*(X\d{1,2}|W\d{1,2}|SP)\b',ops or '',re.I)
    return reg_norm(m.group(1)) if m else ''

def first_reg_operand(ops):
    xs=split_ops(ops)
    if not xs:return ''
    t=xs[0].strip().upper()
    return reg_norm(t) if re.fullmatch(r'[XW]\d{1,2}',t) else t

STORE_PREFIX=('STR','STP','STUR','STXR','STLXR','STLR')
LOAD_PREFIX=('LDR','LDP','LDUR','LDXR','LDAXR','LDAR')

def is_store(m):return m.startswith(STORE_PREFIX)
def is_load(m):return m.startswith(LOAD_PREFIX)

def writes_first_operand(m):
    # Stores/branches/compares do not define their first register operand. Most other AArch64
    # data-processing and loads do. This conservative rule lets us stop following a table base
    # once its register has clearly been repurposed.
    if is_store(m):return False
    if m in {'CMP','CMN','TST','CCMP','CCMN','B','BL','BR','BLR','RET','CBZ','CBNZ','TBZ','TBNZ'} or m.startswith('B.'):
        return False
    return True

cands=rows('v5_runtime_table_candidates.csv')
ins=[]
p=root/'disassembly.txt'
if p.exists():
    with p.open(encoding='utf-8',errors='replace') as f:
        for line in f:
            parts=line.rstrip('\n').split('\t',2)
            if len(parts)<3:continue
            try:addr=int(parts[0].strip(),16)
            except ValueError:continue
            fn=parts[1].strip();text=parts[2].strip();xs=text.split(None,1)
            if not xs:continue
            ins.append({'addr':addr,'fn':fn,'mnem':xs[0].upper(),'ops':xs[1].strip() if len(xs)>1 else '','text':text})

refs=[];writers=[]
seen_ref=set();seen_writer=set()
for c in cands:
    try:table=int(c.get('table_address') or '0',16)
    except ValueError:continue
    if table<=0:continue
    page=table & ~0xfff; off=table & 0xfff
    for i,x in enumerate(ins):
        if x['mnem']!='ADRP':continue
        op=split_ops(x['ops'])
        if len(op)<2:continue
        m=re.search(r'0x([0-9a-fA-F]+)',op[1])
        if not m or int(m.group(1),16)!=page:continue
        reg=reg_norm(op[0])
        exact=(off==0);build_end=i
        if off!=0:
            for j in range(i+1,min(len(ins),i+14)):
                y=ins[j]
                if y['fn']!=x['fn']:break
                yop=split_ops(y['ops'])
                if y['mnem']=='ADD' and len(yop)>=3 and reg_norm(yop[0])==reg and reg_norm(yop[1])==reg:
                    mm=re.search(r'#?(0x[0-9a-fA-F]+|\d+)',yop[2])
                    if mm and int(mm.group(1),0)==off:
                        exact=True;build_end=j;break
                # If the base register is overwritten before the expected ADD, this ADRP cannot
                # be the table-base construction we are looking for.
                if writes_first_operand(y['mnem']) and first_reg_operand(y['ops'])==reg:
                    break
        if not exact:continue

        key=(table,x['addr'],'base-construction')
        if key not in seen_ref:
            refs.append({'table_address':f'{table:08X}','function_name':x['fn'],'address':f'{x["addr"]:08X}','kind':'base-construction','register':reg,'memory_base':'','evidence':x['text']})
            seen_ref.add(key)

        for j in range(build_end+1,min(len(ins),build_end+40)):
            y=ins[j]
            if y['fn']!=x['fn']:break
            mb=memory_base(y['ops'])
            if is_store(y['mnem']) or is_load(y['mnem']):
                # Crucial correctness rule: the table-base register must be the memory base inside
                # [...] rather than merely the value being stored. `str x9,[sp]` is NOT a table write.
                if mb==reg:
                    kind='store' if is_store(y['mnem']) else 'load'
                    rk=(table,y['addr'],kind)
                    if rk not in seen_ref:
                        refs.append({'table_address':f'{table:08X}','function_name':y['fn'],'address':f'{y["addr"]:08X}','kind':kind,'register':reg,'memory_base':mb,'evidence':y['text']})
                        seen_ref.add(rk)
                    if kind=='store':
                        wk=(table,y['addr'])
                        if wk not in seen_writer:
                            writers.append({'table_address':f'{table:08X}','function_name':y['fn'],'store_address':f'{y["addr"]:08X}','register':reg,'memory_base':mb,'evidence':y['text'],'confidence':'medium-static-base-relative'})
                            seen_writer.add(wk)
                # A load can simultaneously use the old base and redefine that register.
                if writes_first_operand(y['mnem']) and first_reg_operand(y['ops'])==reg:
                    break
                continue
            if reg in y['ops'].upper():
                rk=(table,y['addr'],'use')
                if rk not in seen_ref:
                    refs.append({'table_address':f'{table:08X}','function_name':y['fn'],'address':f'{y["addr"]:08X}','kind':'use','register':reg,'memory_base':'','evidence':y['text']})
                    seen_ref.add(rk)
            if writes_first_operand(y['mnem']) and first_reg_operand(y['ops'])==reg:
                break

fields=['table_address','function_name','address','kind','register','memory_base','evidence']
with (root/'v51_table_static_refs.csv').open('w',encoding='utf-8',newline='') as f:
    w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(refs)
fields2=['table_address','function_name','store_address','register','memory_base','evidence','confidence']
with (root/'v51_table_writer_candidates.csv').open('w',encoding='utf-8',newline='') as f:
    w=csv.DictWriter(f,fieldnames=fields2);w.writeheader();w.writerows(writers)

source=(root/'source_path.txt').read_text(errors='ignore').strip() if (root/'source_path.txt').exists() else ''
module=Path(source).name or 'target.so'
probe=[]
seen_probe=set()
for c in cands[:240]:
    try:va=int(c.get('table_address') or '0',16)
    except ValueError:continue
    if va<=0:continue
    branch=canon(c.get('branch_address'));key=(va,branch)
    if key in seen_probe:continue
    seen_probe.add(key)
    try:n=min(max(int(float(c.get('max_index') or 0))+1,1),256)
    except Exception:n=24
    probe.append({'function_entry':canon(c.get('function_entry')),'branch_address':branch,'va':va,'count':n,'pattern':c.get('pattern','')})
js=f'''// Generated by Mobile Ghidra Lab V5.1. Read-only runtime table probe.\n'use strict';\nconst MODULE_NAME = {json.dumps(module)};\nconst CANDIDATES = {json.dumps(probe)};\nfunction insideModule(m,p) {{ const x=ptr(p); return x.compare(m.base)>=0 && x.compare(m.base.add(m.size))<0; }}\nrpc.exports = {{\n  probe() {{\n    const m=Process.findModuleByName(MODULE_NAME); if(!m) throw new Error('module not loaded: '+MODULE_NAME);\n    const out=[];\n    for(const c of CANDIDATES) {{\n      const table=m.base.add(c.va); const entries=[];\n      for(let i=0;i<c.count;i++) {{\n        try {{ const rel=table.add(i*4).readS32(); const target=table.add(rel); entries.push({{i,rel,target:target.toString(),inModule:insideModule(m,target)}}); }}\n        catch(e) {{ entries.push({{i,error:String(e)}}); break; }}\n      }}\n      out.push({{...c,table:table.toString(),entries}});\n    }}\n    return {{module:MODULE_NAME,base:m.base.toString(),size:m.size,candidates:out}};\n  }},\n  watchmprotect() {{\n    const m=Process.findModuleByName(MODULE_NAME); if(!m) throw new Error('module not loaded: '+MODULE_NAME);\n    const p=Module.findGlobalExportByName('mprotect'); if(!p) return false;\n    Interceptor.attach(p,{{onEnter(args){{this.a=args[0];this.n=args[1].toUInt32();this.prot=args[2].toInt32();}},onLeave(ret){{if(insideModule(m,this.a)) send({{kind:'mprotect',address:this.a.toString(),length:this.n,prot:this.prot,result:ret.toInt32()}});}}}});\n    return true;\n  }}\n}};\n'''
(root/'v51_runtime_table_probe.js').write_text(js,encoding='utf-8')
with (root/'v51_runtime_table_report.md').open('w',encoding='utf-8') as w:
    w.write('# V5.1 runtime-table follow-up\n\n')
    w.write(f'- Runtime/transformed table candidates: **{len(cands)}**\n- Static table-base references recovered: **{len(refs)}**\n- Base-relative store candidates: **{len(writers)}**\n- Generated read-only Frida table probes: **{len(probe)}**\n\n')
    w.write('Writer candidates now require the reconstructed table-base register to be the actual memory base inside `[...]`; stores such as `str x9,[sp,...]` are explicitly excluded. Register tracking stops when the base register is overwritten. These remain evidence candidates, not proof that a store initializes the dispatcher table.\n')
print(json.dumps({'tables':len(cands),'static_refs':len(refs),'writer_candidates':len(writers),'probe_tables':len(probe)}))
