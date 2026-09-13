#!/usr/bin/env python3
import csv,sys
from pathlib import Path
root=Path(sys.argv[1])
def rows(n):
 p=root/n
 if not p.exists() or not p.stat().st_size:return []
 with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))
def c(x):
 try:return f'{int((x or "").strip(),16):08X}'
 except:return (x or '').strip().upper()
prot=[r for r in rows('v52_protected_functions.csv') if r.get('complexity_priority')=='high']
raw={c(r.get('function_entry')):r for r in rows('v51_raw_pcode_summary.csv')}
high={c(r.get('function_entry')):r for r in rows('v51_high_pcode_summary.csv')}
dec={c(r.get('entry')):r for r in rows('v4_selected_export.csv')}
out=[]
for r in prot:
 e=c(r.get('entry'));a=raw.get(e,{});h=high.get(e,{});d=dec.get(e,{})
 out.append({'entry':e,'name':r.get('name',''),'complexity_score':r.get('complexity_priority_score',''),'size_bytes':r.get('size_bytes',''),'raw_pcode_ops':a.get('pcode_ops',''),'raw_truncated':a.get('truncated','missing'),'raw_reason':a.get('truncate_reason',''),'high_status':h.get('status','missing'),'high_ops':h.get('high_pcode_ops',''),'high_truncated':h.get('truncated',''),'decompile_status':d.get('decompile_status',''),'mode':r.get('recommended_mode','')})
fields=list(out[0].keys()) if out else ['entry']
with (root/'v52_protected_coverage.csv').open('w',encoding='utf-8',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(out)
with (root/'v52_protected_coverage.md').open('w',encoding='utf-8') as w:
 w.write('# V5.2 protected-function coverage\n\n')
 w.write(f'- High-complexity protected targets: **{len(out)}**\n- Raw P-code present: **{sum(bool(x["raw_pcode_ops"]) for x in out)}**\n- Raw P-code truncated: **{sum(str(x["raw_truncated"]).lower()=="true" for x in out)}**\n- High P-code available: **{sum(str(x["high_status"]).lower()=="ok" for x in out)}**\n\n')
 w.write('| Entry | Function | Complexity | Raw ops | Raw cut | High status | High ops | Decompile |\n|---|---|---:|---:|---|---|---:|---|\n')
 for x in out:w.write(f"| `0x{x['entry']}` | `{x['name']}` | {x['complexity_score']} | {x['raw_pcode_ops']} | {x['raw_truncated']} | {x['high_status']} | {x['high_ops']} | {x['decompile_status']} |\n")
print('protected coverage',len(out))
