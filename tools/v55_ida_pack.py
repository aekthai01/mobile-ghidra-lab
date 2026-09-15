#!/usr/bin/env python3
import csv,html,json,re,shutil,sys
from collections import Counter,defaultdict
from pathlib import Path
if len(sys.argv)!=2:raise SystemExit('usage: v55_ida_pack.py <analysis-output-dir>')
root=Path(sys.argv[1]);ida=root/'human'/'ida';ida.mkdir(parents=True,exist_ok=True)
def rows(n):
 p=root/n
 if not p.exists() or not p.stat().st_size:return []
 with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))
def canon(v):
 v=(v or '').strip();v=v[2:] if v.lower().startswith('0x') else v
 try:return f'{int(v,16):08X}'
 except:return v.upper()
def clean(v):return re.sub(r'[^A-Za-z0-9_]+','_',v or '').strip('_')[:120]
def out(n,data,fields):
 with (ida/n).open('w',encoding='utf-8',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(data)
regions=rows('v55_region_map.csv');summary=rows('v55_reconstruction_summary.csv');indirect=rows('v5_indirect_branches.csv');strings=rows('string_xrefs.csv');program={};gp=root/'ghidra_program.json'
if gp.exists():
 try:program=json.loads(gp.read_text(encoding='utf-8',errors='replace'))
 except:pass
functions=[];regions_out=[];comments=[];names=[];important=[];byfn=defaultdict(list)
for r in regions:byfn[canon(r.get('function_entry'))].append(r)
rank={'CANDIDATE':1,'PROBABLE':2,'STRONG':3,'PROVEN':4}
for s in summary:
 e=canon(s.get('entry'));fn=s.get('name') or f'sub_{e}';functions.append({'address':e,'current_name':fn,'size_bytes':s.get('size_bytes',''),'protection':s.get('protection',''),'protection_score':s.get('protection_score',''),'region_count':s.get('region_count',''),'state_register':s.get('state_register',''),'overview_path':s.get('overview_path','')});comments.append({'address':e,'repeatable':'true','confidence':'PROVEN','comment':f"V5.5 reconstructed overview: {s.get('overview_path','')} | protection={s.get('protection','')} score={s.get('protection_score','')} | regions={s.get('region_count','')}"});sem=Counter();conf={}
 for r in byfn.get(e,[]):
  n=r.get('semantic_name') or ''
  if n and n not in {'unknown_region','entry','state_logic','indirect_flow'}:sem[n]+=1;conf[n]=max(conf.get(n,'CANDIDATE'),r.get('confidence') or 'CANDIDATE',key=lambda x:rank.get(x,0))
 if sem:
  dom,_=sem.most_common(1)[0];names.append({'address':e,'kind':'function','current_name':fn,'suggested_name':f'mg_{clean(dom)}_{e.lower()}','confidence':conf.get(dom,'PROBABLE'),'apply_policy':'strong-only-disabled-by-default'})
for r in regions:
 e=canon(r.get('function_entry'));st=canon(r.get('start_address'));rid=r.get('region_id') or '';sem=r.get('semantic_name') or 'region';cf=r.get('confidence') or 'CANDIDATE';cl=r.get('classification') or 'UNKNOWN';regions_out.append({'function_entry':e,'function_name':r.get('function_name',''),'region_id':rid,'start_address':st,'end_address':canon(r.get('end_address')),'center_address':canon(r.get('center_address')),'classification':cl,'semantic_name':sem,'confidence':cf,'reasons':r.get('reasons',''),'c_path':r.get('c_path',''),'evidence_path':r.get('evidence_path','')});comments.append({'address':st,'repeatable':'false','confidence':cf,'comment':f"Region {rid}: {cl} / {sem} | {r.get('reasons','')} | C: {r.get('c_path','')}"});names.append({'address':st,'kind':'region','current_name':'','suggested_name':f'mg_r{rid}_{clean(sem)}_{st.lower()}','confidence':cf,'apply_policy':'strong-only-disabled-by-default'})
 if cl in {'STATE_DISPATCHER','INDIRECT_FLOW','REAL_LOGIC'}:important.append({'address':st,'category':cl,'label':sem,'confidence':cf,'note':f"Region {rid} in 0x{e}; {r.get('reasons','')}"})
for r in indirect:
 a=canon(r.get('branch_address'))
 if not a:continue
 n=int(r.get('resolved_targets') or 0);cf='STRONG' if n else 'PROBABLE';note=f"Indirect branch {r.get('branch_register','')}; pattern={r.get('pattern','')}; resolved_targets={n}; table={r.get('table_address','')}";comments.append({'address':a,'repeatable':'false','confidence':cf,'comment':note});important.append({'address':a,'category':'INDIRECT_BRANCH','label':'resolved_indirect' if n else 'unresolved_indirect','confidence':cf,'note':note})
smap=defaultdict(list)
for r in strings:
 a=canon(r.get('from_address'));v=(r.get('value') or '').strip()
 if a and v and v not in smap[a]:smap[a].append(v)
for a,vs in smap.items():comments.append({'address':a,'repeatable':'false','confidence':'PROVEN','comment':'Exact string xref: '+' | '.join(v.replace('\n','\\n')[:160] for v in vs[:4])})
def uniq(data,keys):
 seen=set();z=[]
 for r in data:
  k=tuple(r.get(x,'') for x in keys)
  if k in seen:continue
  seen.add(k);z.append(r)
 return z
comments=uniq(comments,['address','comment']);names=uniq(names,['address','suggested_name']);important=uniq(important,['address','category','note'])
out('functions.csv',functions,['address','current_name','size_bytes','protection','protection_score','region_count','state_register','overview_path']);out('regions.csv',regions_out,['function_entry','function_name','region_id','start_address','end_address','center_address','classification','semantic_name','confidence','reasons','c_path','evidence_path']);out('comments.csv',comments,['address','repeatable','confidence','comment']);out('suggested_names.csv',names,['address','kind','current_name','suggested_name','confidence','apply_policy']);out('important_addresses.csv',important,['address','category','label','confidence','note'])
meta={'format':'mobile-ghidra-lab.ida-interop','version':'5.5','program':program.get('name',''),'sha256':program.get('sha256',''),'ghidra_image_base':program.get('image_base','0'),'policy':{'patch_binary':False,'create_functions':False,'change_function_boundaries':False,'rename_default':False,'comments_default':True,'minimum_rename_confidence':'STRONG'}};(ida/'metadata.json').write_text(json.dumps(meta,indent=2),encoding='utf-8');src=Path(__file__).resolve().parents[1]/'ida'/'import_mobile_ghidra.py'
if not src.exists():raise SystemExit(f'IDA importer source missing: {src}')
shutil.copy2(src,ida/'import_mobile_ghidra.py');md='# IDA Pro annotation bridge\n\nOpen the same ELF in IDA Pro and run `import_mobile_ghidra.py`. Comments are imported by default. Strong renames are disabled by default. No byte patching, function creation, or boundary changes are performed.\n';(ida/'README.md').write_text(md,encoding='utf-8');css='body{font-family:system-ui,-apple-system,sans-serif;background:#101114;color:#eee;max-width:900px;margin:auto;padding:16px}code{font-family:ui-monospace,monospace}.warn{color:#ffb86c}';(ida/'README.html').write_text(f'<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>{css}</style></head><body><h1>IDA Pro annotation bridge</h1><p>Open the same ELF and run <code>import_mobile_ghidra.py</code>.</p><p class="warn">No byte patching, function creation, or boundary changes. Renames are disabled by default.</p><p>{len(functions)} functions, {len(regions_out)} regions, {len(comments)} comments.</p></body></html>',encoding='utf-8');report={'functions':len(functions),'regions':len(regions_out),'comments':len(comments),'suggested_names':len(names),'important_addresses':len(important)};(root/'v55_ida_interop_report.json').write_text(json.dumps(report,indent=2),encoding='utf-8');(root/'v55_ida_interop_report.md').write_text('# V5.5 IDA Pro interop\n\nIDA support is optional and annotation-only by default. The main pipeline has no IDA dependency.\n\n'+'\n'.join(f"- {k.replace('_',' ').title()}: **{v}**" for k,v in report.items())+'\n',encoding='utf-8');print(json.dumps(report))
