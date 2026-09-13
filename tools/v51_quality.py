#!/usr/bin/env python3
import bisect,csv,json,sys
from pathlib import Path

if len(sys.argv)!=2:raise SystemExit('usage: v51_quality.py <analysis-output-dir>')
root=Path(sys.argv[1])

def rows(name):
 p=root/name
 if not p.exists() or p.stat().st_size==0:return []
 with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))

def canon(x):
 try:return f'{int((x or "").strip(),16):08X}'
 except:return (x or '').strip().upper()

metrics={canon(r.get('entry')):r for r in rows('v51_function_metrics.csv') or rows('v4_function_metrics.csv')}
exports=rows('v4_selected_export.csv')
flow=rows('v5_function_flow.csv')
funcs=rows('functions.csv')
starts=[];by_start={}
for r in funcs:
 try:s=int((r.get('entry') or '').strip(),16);size=int(float(r.get('size_bytes') or 0))
 except:continue
 starts.append(s);by_start[s]=(canon(r.get('entry')),size,r.get('name',''))
starts.sort()

def containing(a):
 i=bisect.bisect_right(starts,a)-1
 if i<0:return None
 s=starts[i];e,size,n=by_start[s]
 return (e,s,size,n) if size<=0 or a<s+size else None

ins_by={}
p=root/'disassembly.txt'
if p.exists():
 with p.open(encoding='utf-8',errors='replace') as f:
  for line in f:
   parts=line.rstrip('\n').split('\t',2)
   if len(parts)<3:continue
   try:a=int(parts[0].strip(),16)
   except:continue
   c=containing(a)
   if not c:continue
   e=c[0];ins_by.setdefault(e,[]).append((a,parts[1].strip(),parts[2].strip()))

fallback=[];fbdir=root/'v51_decompile_fallback';fbdir.mkdir(exist_ok=True)
for r in exports:
 status=(r.get('decompile_status') or '').strip()
 if (r.get('mode') or '')!='full' or status.lower() in ('ok','success','decompiled','') or not any(k in status.lower() for k in ('fail','timeout','error','exception')):continue
 e=canon(r.get('entry'));xs=ins_by.get(e,[])
 path=fbdir/f'{e}_{(r.get("name") or "function").replace("/","_")}.asm'
 with path.open('w',encoding='utf-8') as w:
  w.write(f'; V5.1 automatic fallback for failed whole-function decompile\n; entry=0x{e} name={r.get("name","")}\n; original_status={status}\n; instruction_count={len(xs)}\n\n')
  for a,fn,text in xs[:6000]:w.write(f'.text:{a:016X}  {text}\n')
 fallback.append({'entry':e,'name':r.get('name',''),'decompile_status':status,'instructions_exported':min(len(xs),6000),'fallback_path':str(path.relative_to(root))})
with (root/'v51_decompile_fallback.csv').open('w',encoding='utf-8',newline='') as f:
 fields=['entry','name','decompile_status','instructions_exported','fallback_path'];w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(fallback)

app=[];third=[]
for r in flow:
 e=canon(r.get('entry'));m=metrics.get(e,{})
 rr=dict(r);rr['third_party_family']=m.get('third_party_family','');rr['v51_priority_tier']=m.get('v51_priority_tier','')
 try:score=int(float(r.get('top_dispatcher_score') or 0))
 except:score=0
 if score<=0:continue
 if (m.get('third_party') or '').lower()=='true' or m.get('third_party_family'):third.append(rr)
 else:app.append(rr)
app.sort(key=lambda r:-int(float(r.get('top_dispatcher_score') or 0)));third.sort(key=lambda r:-int(float(r.get('top_dispatcher_score') or 0)))
fields=list((app or third or [{'entry':''}])[0].keys())
for name,data in [('v51_dispatcher_app.csv',app),('v51_dispatcher_third_party.csv',third)]:
 with (root/name).open('w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(data)

val=rows('v5_jump_table_validation.csv')
runtime=rows('v5_runtime_table_candidates.csv')
strong=sum(int(float(r.get('strong_static_targets') or 0)) for r in val)
plausible=sum(int(float(r.get('plausible_static_targets') or 0)) for r in val)
with (root/'v51_quality_report.md').open('w',encoding='utf-8') as w:
 w.write('# V5.1 quality/limitations report\n\n')
 w.write(f'- Whole-function decompile failures with automatic ASM fallback: **{len(fallback)}**\n')
 w.write(f'- App/unknown dispatcher candidates: **{len(app)}**\n- Third-party dispatcher candidates separated: **{len(third)}**\n')
 w.write(f'- Validated strong static jump-table targets: **{strong}**\n- Plausible static jump-table targets: **{plausible}**\n- Runtime/transformed table candidates: **{len(runtime)}**\n\n')
 w.write('Terminology rule: heuristic executable-looking targets are not reported as resolved static control flow unless post-validation confirms alignment and a known Ghidra instruction target.\n')
print(json.dumps({'decompile_fallbacks':len(fallback),'app_dispatchers':len(app),'third_party_dispatchers':len(third),'strong_static_targets':strong,'runtime_table_candidates':len(runtime)}))
