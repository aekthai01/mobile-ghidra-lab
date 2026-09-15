#!/usr/bin/env python3
"""V5.5 giant/protected-function region reconstruction.

This stage never replaces forensic evidence. It builds address-bounded, confidence-tagged
C-like views from Ghidra High P-code when available and falls back to preserved Raw P-code.
The output is intentionally described as reconstruction, not original source.
"""
import csv, gzip, html, json, re, sys
from collections import Counter, defaultdict
from pathlib import Path

if len(sys.argv) != 2: raise SystemExit("usage: v55_region_reconstruct.py <analysis-output-dir>")
root=Path(sys.argv[1]); human=root/'human'; recon_root=human/'reconstructed_c'; evidence_root=root/'v55_regions'
human.mkdir(exist_ok=True); recon_root.mkdir(exist_ok=True); evidence_root.mkdir(exist_ok=True)

def rows(name):
 p=root/name
 if not p.exists() or not p.stat().st_size:return []
 with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))
def canon(v):
 v=(v or '').strip(); v=v[2:] if v.lower().startswith('0x') else v
 try:return f'{int(v,16):08X}'
 except:return v.upper()
def hx(v):
 try:return int(canon(v),16)
 except:return None
def safe(v):return (re.sub(r'[^A-Za-z0-9._-]+','_',v or 'function').strip('_') or 'function')[:96]
def ident(v):
 v=(re.sub(r'[^A-Za-z0-9_]+','_',v or 'region').strip('_') or 'region')[:96]
 return '_'+v if v[0].isdigit() else v
def write_csv(path,data,fields):
 with path.open('w',encoding='utf-8',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(data)

functions={}
for r in rows('functions.csv'):
 e=canon(r.get('entry'))
 if not e:continue
 rr=dict(r);rr['_entry']=e;rr['_start']=hx(e) or 0
 try:rr['_size']=int(r.get('size_bytes') or 0)
 except:rr['_size']=0
 functions[e]=rr
selected={canon(r.get('entry')):r for r in rows('v52_selected_functions.csv') if canon(r.get('entry'))}
protected={canon(r.get('entry')):r for r in rows('v52_protected_functions.csv') if canon(r.get('entry'))}
flow={canon(r.get('entry')):r for r in rows('v5_function_flow.csv') if canon(r.get('entry'))}
v4_export={canon(r.get('entry')):r for r in rows('v4_selected_export.csv') if canon(r.get('entry'))}
high_summary={canon(r.get('function_entry')):r for r in rows('v51_high_pcode_summary.csv') if canon(r.get('function_entry'))}
v54_summary={canon(r.get('entry')):r for r in rows('v54_protected_evidence_summary.csv') if canon(r.get('entry'))}
targets={e for e,r in protected.items() if (r.get('complexity_priority') or '').lower()=='high'}|{e for e,r in selected.items() if (r.get('recommended_mode') or '').lower()=='region'}
if not targets:targets={e for e,r in selected.items() if e in functions and int(r.get('size_bytes') or 0)>=20000}

string_at=defaultdict(list)
for r in rows('string_xrefs.csv'):
 a=canon(r.get('from_address'));v=r.get('value') or ''
 if a and v and v not in string_at[a]:string_at[a].append(v)
call_at=defaultdict(list)
for r in rows('callgraph.csv'):
 a=canon(r.get('callsite'));v=r.get('callee_name') or r.get('callee_entry') or '<unresolved>'
 if a and v and v not in call_at[a]:call_at[a].append(v)
state=defaultdict(list)
for r in rows('v5_state_values.csv'):
 e=canon(r.get('function_entry'))
 if e:state[e].append(r)
indirect=defaultdict(list)
for r in rows('v5_indirect_branches.csv'):
 e=canon(r.get('function_entry'))
 if e:indirect[e].append(r)

cand=defaultdict(list)
def add(e,st,en,center,reason,source):
 e=canon(e);s,t,c=hx(st),hx(en),hx(center)
 if e not in targets or s is None or t is None:return
 if t<s:s,t=t,s
 if c is None:c=(s+t)//2
 cand[e].append({'start':s,'end':t,'center':c,'reasons':{reason or 'region'},'sources':{source}})
for r in rows('v5_slice_index.csv'):add(r.get('function_entry'),r.get('start_address'),r.get('end_address'),r.get('center_address'),r.get('reason'),'v5_slice')
for r in rows('v4_giant_region_index.csv'):add(r.get('function_entry'),r.get('start_address'),r.get('end_address'),r.get('center_address'),r.get('reason'),'v4_region')
for r in rows('v52_protected_region_index.csv'):
 a=hx(r.get('anchor_address'))
 if a is not None:add(r.get('function_entry'),f'{max(0,a-0x60):X}',f'{a+0x60:X}',r.get('anchor_address'),r.get('anchor_kind'),'v52_protected')
for e in targets:
 fn=functions.get(e,{});st=fn.get('_start',hx(e) or 0);size=max(4,int(fn.get('_size',0) or 0));hi=st+size-1
 add(e,f'{st:X}',f'{min(st+0x180,hi):X}',f'{st:X}','entry','v55_fallback')
 for q in state.get(e,[])[:24]:
  a=hx(q.get('compare_address'))
  if a is not None:add(e,f'{max(st,a-0x60):X}',f'{min(hi,a+0x60):X}',f'{a:X}','state-compare','v55_state')
 for q in indirect.get(e,[])[:24]:
  a=hx(q.get('branch_address'))
  if a is not None:add(e,f'{max(st,a-0x80):X}',f'{min(hi,a+0x80):X}',f'{a:X}','indirect-branch-resolved' if int(q.get('resolved_targets') or 0)>0 else 'indirect-branch','v55_indirect')
def merge(xs):
 out=[]
 for x in sorted(xs,key=lambda q:(q['start'],q['end'],q['center'])):
  if not out:out.append(x);continue
  z=out[-1];ov=min(z['end'],x['end'])-max(z['start'],x['start'])+1;small=max(1,min(z['end']-z['start']+1,x['end']-x['start']+1))
  if ov>0 and (ov/small>=.55 or abs(z['center']-x['center'])<=0x60):z['start']=min(z['start'],x['start']);z['end']=max(z['end'],x['end']);z['reasons'].update(x['reasons']);z['sources'].update(x['sources'])
  else:out.append(x)
 return out[:64]
regions={}
for e in sorted(targets):
 rs=merge(cand.get(e,[]));fn=functions.get(e)
 if fn:
  lo,hi=fn['_start'],fn['_start']+max(1,fn['_size'])-1
  for r in rs:r['start']=max(lo,r['start']);r['end']=min(hi,r['end'])
 for i,r in enumerate(rs,1):r.update(id=f'{i:03d}',high_ops=[],raw_ops=[],high_seen=0,raw_seen=0,strings=[],calls=[])
 regions[e]=rs
def region_for(e,a):
 x=hx(a)
 if x is None:return None
 for r in regions.get(e,[]):
  if r['start']<=x<=r['end']:return r
 return None
for e,rs in regions.items():
 for r in rs:
  for a,vs in string_at.items():
   x=hx(a)
   if x is not None and r['start']<=x<=r['end']:
    for v in vs:
     if v not in r['strings']:r['strings'].append(v)
  for a,vs in call_at.items():
   x=hx(a)
   if x is not None and r['start']<=x<=r['end']:
    for v in vs:
     if v not in r['calls']:r['calls'].append(v)
for e,s in v54_summary.items():
 if e not in regions or (s.get('status') or '')!='ok':continue
 d=root/(s.get('evidence_dir') or '')
 for fn,addrk,valk,dest in [('strings.csv','instruction_address','value','strings'),('calls.csv','callsite','target_name','calls')]:
  p=d/fn
  if not p.exists():continue
  with p.open(encoding='utf-8',errors='replace',newline='') as f:
   for q in csv.DictReader(f):
    r=region_for(e,q.get(addrk));v=q.get(valk) or (q.get('target_address') if dest=='calls' else '') or ''
    if r is not None and v and v not in r[dest]:r[dest].append(v)
hp=root/'v51_high_pcode.csv'
if hp.exists() and hp.stat().st_size:
 with hp.open(encoding='utf-8',errors='replace',newline='') as f:
  for q in csv.DictReader(f):
   e=canon(q.get('function_entry'));r=region_for(e,q.get('sequence_address')) if e in regions else None
   if r is not None:r['high_seen']+=1;r['high_ops'].append(q) if len(r['high_ops'])<320 else None
for e,s in v54_summary.items():
 if e not in regions or (s.get('status') or '')!='ok':continue
 p=root/(s.get('evidence_dir') or '')/'raw_pcode.csv.gz'
 if not p.exists():continue
 with gzip.open(p,'rt',encoding='utf-8',errors='replace',newline='') as f:
  for q in csv.DictReader(f):
   r=region_for(e,q.get('instruction_address'))
   if r is not None:r['raw_seen']+=1;r['raw_ops'].append(q) if len(r['raw_ops'])<320 else None
rp=root/'v51_raw_pcode.csv'
if rp.exists() and rp.stat().st_size:
 with rp.open(encoding='utf-8',errors='replace',newline='') as f:
  for q in csv.DictReader(f):
   e=canon(q.get('function_entry'))
   if e not in regions or e in v54_summary:continue
   r=region_for(e,q.get('instruction_address'))
   if r is not None:r['raw_seen']+=1;r['raw_ops'].append(q) if len(r['raw_ops'])<320 else None
RULES=[('device_identity',re.compile(r'(?i)(android[_ -]?id|build[_ .]?(model|brand|device)|uuid|serial|device[_ -]?id)')),('network',re.compile(r'(?i)(https?://|curl|socket|connect|send|recv|ssl|tls|dns|getaddrinfo|host(name)?)')),('crypto_decode',re.compile(r'(?i)(decrypt|decode|aes|chacha|cipher|base64|xor|key schedule|openssl)')),('jni_bridge',re.compile(r'(?i)(jni|java_|getmethodid|getfieldid|call[a-z]+method|findclass|registerNatives)')),('anti_analysis',re.compile(r'(?i)(ptrace|tracerpid|frida|debugger|/proc/self|maps|anti.?debug)')),('file_io',re.compile(r'(?i)(fopen|fread|fwrite|open64|readlink|filepath|filename|/data/|/sdcard/)'))]
def classify(e,r):
 text=' '.join(sorted(r['reasons']))+' '+' '.join(r['strings'])+' '+' '.join(r['calls']);low=text.lower();sem='';hits=0
 for name,rx in RULES:
  n=len(rx.findall(text))
  if n>hits:sem,hits=name,n
 resolved=sum(int(q.get('resolved_targets') or 0) for q in indirect.get(e,[]) if (lambda a:a is not None and r['start']<=a<=r['end'])(hx(q.get('branch_address'))))
 if 'dispatcher' in low:return 'STATE_DISPATCHER','state_dispatcher','STRONG'
 if 'indirect-branch' in low:return 'INDIRECT_FLOW',sem or 'indirect_flow','STRONG' if resolved else 'PROBABLE'
 if 'state-compare' in low:return 'STATE_UPDATE',sem or 'state_logic','PROBABLE'
 if sem:return 'REAL_LOGIC',sem,'STRONG' if hits>=2 and len(r['strings'])+len(r['calls'])>=2 else 'PROBABLE'
 ops=r['high_ops'] or r['raw_ops'];mn=[str(x.get('mnemonic') or '').upper() for x in ops];meaningful=sum(m in {'LOAD','STORE','CALL','CALLIND','BRANCH','CBRANCH','BRANCHIND','RETURN'} for m in mn);arith=sum(m.startswith(('INT_','BOOL_','FLOAT_')) or m in {'COPY','PIECE','SUBPIECE'} for m in mn)
 if 'coverage-sample' in low and not r['strings'] and not r['calls'] and meaningful==0 and arith>=24:return 'LIKELY_JUNK','opaque_arithmetic_candidate','CANDIDATE'
 if 'entry' in low:return 'CONTROL_FLOW','entry','PROBABLE'
 return 'UNKNOWN','unknown_region','CANDIDATE'
OPS={'INT_ADD':'+','INT_SUB':'-','INT_MULT':'*','INT_DIV':'/','INT_SDIV':'/','INT_REM':'%','INT_SREM':'%','INT_AND':'&','INT_OR':'|','INT_XOR':'^','INT_LEFT':'<<','INT_RIGHT':'>>','INT_SRIGHT':'>>','INT_EQUAL':'==','INT_NOTEQUAL':'!=','INT_LESS':'<','INT_SLESS':'<','INT_LESSEQUAL':'<=','INT_SLESSEQUAL':'<=','BOOL_AND':'&&','BOOL_OR':'||','BOOL_XOR':'^'}
def cv(v):return ((v or '').strip().replace('\n',' ')[:180] or '/*void*/')
def ins(v):return [cv(x) for x in (v or '').split(' | ') if x.strip()]
def pseudo(q):
 m=(q.get('mnemonic') or '').upper();o=cv(q.get('output'));a=ins(q.get('inputs'))
 if m=='COPY' and a:return f'{o} = {a[0]};'
 if m in OPS and len(a)>=2:return f'{o} = {a[0]} {OPS[m]} {a[1]};'
 if m in {'INT_ZEXT','INT_SEXT','CAST'} and a:return f'{o} = {m.lower()}({a[0]});'
 if m=='LOAD' and a:return f'{o} = MEM[{a[-1]}];'
 if m=='STORE' and len(a)>=2:return f'MEM[{a[-2]}] = {a[-1]};'
 if m=='CALL':return f"call({', '.join(a)});"
 if m=='CALLIND':return f"call_indirect({', '.join(a)});"
 if m=='BRANCH' and a:return f'goto {a[0]};'
 if m=='CBRANCH' and a:return f"if ({a[1] if len(a)>1 else 'condition'}) goto {a[0]};"
 if m=='BRANCHIND' and a:return f'goto *({a[0]});'
 if m=='RETURN':return f"return /* {', '.join(a)} */;"
 if m=='MULTIEQUAL':return f"{o} = phi({', '.join(a)});"
 return f"{o} = {m.lower()}({', '.join(a)});" if o!='/*void*/' else f"{m.lower()}({', '.join(a)});"
region_rows=[];summaries=[];fail=[];high_required=[e for e,r in protected.items() if (r.get('complexity_priority') or '').lower()=='high']
for e in sorted(targets,key=lambda x:int(x,16) if re.fullmatch(r'[0-9A-F]+',x) else 0):
 fn=functions.get(e,{});pr=protected.get(e,{});fr=flow.get(e,{});name=fn.get('name') or pr.get('name') or f'sub_{e}';display=name if not name.startswith(('FUN_','LAB_','SUB_')) else f'sub_{e}';fd=recon_root/e;fd.mkdir(parents=True,exist_ok=True);ed=evidence_root/e;ed.mkdir(parents=True,exist_ok=True);rs=regions.get(e,[]);clike=0
 vals=[]
 for q in state.get(e,[]):
  v=q.get('constant') or ''
  if v and v not in vals:vals.append(v)
 overview=['/*',' * Mobile Ghidra Lab V5.5 reconstructed C overview.',' * NOT original source; regions are address-ordered evidence views.',f' * Function: {display} @ 0x{e}',f" * Protection: {pr.get('complexity_priority','')} score={pr.get('complexity_priority_score','')}",f" * Whole-function decompile: {v4_export.get(e,{}).get('decompile_status','unknown')}",' */','',f'void {ident(display)}_reconstructed(void *ctx)','{']
 if fr.get('state_register'):overview.append(f"    /* observed state register: {fr.get('state_register')}; values: {', '.join(vals[:32]) or 'none'} */")
 for r in rs:
  cls,sem,conf=classify(e,r);ops=r['high_ops'] if r['high_ops'] else r['raw_ops'];source='HIGH_PCODE_SSA' if r['high_ops'] else ('V54_RAW_PCODE_FULL' if e in v54_summary else 'V51_RAW_PCODE_FALLBACK');render=[];last=None
  for q in ops:
   line=pseudo(q)
   if line==last:continue
   last=line;render.append(line)
   if len(render)>=180:break
  rid=r['id'];rname=ident(f'region_{e}_{rid}_{sem}');cp=fd/f'region_{rid}_{safe(sem)}.c';ep=ed/f'region_{rid}.json'
  with cp.open('w',encoding='utf-8') as w:
   w.write(f"/*\n * V5.5 region reconstruction; NOT original source.\n * Function: {display} @ 0x{e}\n * Region: {rid} 0x{r['start']:08X}..0x{r['end']:08X}\n * Classification: {cls}\n * Semantic: {sem}\n * Confidence: {conf}\n * Reasons: {', '.join(sorted(r['reasons']))}\n * P-code source: {source}; high_seen={r['high_seen']} raw_seen={r['raw_seen']}\n */\n\nstatic void {rname}(void *ctx)\n{{\n")
   if r['strings']:
    w.write('    /* Exact string xrefs:\n');[w.write('     * '+s.replace('*/','* /').replace('\n','\\n')[:220]+'\n') for s in r['strings'][:20]];w.write('     */\n')
   if r['calls']:w.write('    /* Calls: '+', '.join(x[:100] for x in r['calls'][:20]).replace('*/','* /')+' */\n')
   if not render:w.write('    /* No bounded P-code available; see ARM64/forensic evidence. */\n')
   for line in render:w.write('    '+line.replace('*/','* /')+'\n')
   w.write('}\n')
  ep.write_text(json.dumps({'function_entry':e,'function_name':display,'region_id':rid,'start_address':f"{r['start']:08X}",'end_address':f"{r['end']:08X}",'center_address':f"{r['center']:08X}",'reasons':sorted(r['reasons']),'sources':sorted(r['sources']),'classification':cls,'semantic_name':sem,'confidence':conf,'pcode_source':source,'high_pcode_ops_seen':r['high_seen'],'raw_pcode_ops_seen':r['raw_seen'],'strings':r['strings'],'calls':r['calls'],'c_path':str(cp.relative_to(root))},indent=2,ensure_ascii=False),encoding='utf-8')
  overview.append(f'    {rname}(ctx); /* {cls} / {sem} / {conf} */');clike+=1 if render or r['strings'] or r['calls'] else 0
  region_rows.append({'function_entry':e,'function_name':display,'region_id':rid,'start_address':f"{r['start']:08X}",'end_address':f"{r['end']:08X}",'center_address':f"{r['center']:08X}",'reasons':'|'.join(sorted(r['reasons'])),'sources':'|'.join(sorted(r['sources'])),'classification':cls,'semantic_name':sem,'confidence':conf,'pcode_source':source,'high_pcode_ops_seen':r['high_seen'],'raw_pcode_ops_seen':r['raw_seen'],'pcode_ops_rendered':len(render),'string_count':len(r['strings']),'call_count':len(r['calls']),'c_path':str(cp.relative_to(root)),'evidence_path':str(ep.relative_to(root))})
 overview+=['}',''];op=fd/'overview.c';op.write_text('\n'.join(overview),encoding='utf-8');s={'entry':e,'name':display,'size_bytes':fn.get('size_bytes',pr.get('size_bytes','')),'protection':pr.get('complexity_priority',''),'protection_score':pr.get('complexity_priority_score',''),'whole_decompile_status':v4_export.get(e,{}).get('decompile_status',''),'high_pcode_status':high_summary.get(e,{}).get('status',''),'region_count':len(rs),'c_like_regions':clike,'dispatcher_candidates':fr.get('dispatcher_candidates',''),'top_dispatcher_score':fr.get('top_dispatcher_score',''),'state_register':fr.get('state_register',''),'overview_path':str(op.relative_to(root))};summaries.append(s)
 if e in high_required:
  q=v54_summary.get(e)
  if not q or (q.get('status') or '')!='ok':fail.append(f'0x{e}: V5.4 full evidence missing/not-ok')
  if not rs:fail.append(f'0x{e}: no V5.5 regions')
for se in ('00267564','001D3CA4'):
 if se in functions and not next((x for x in summaries if x['entry']==se and int(x['region_count'] or 0)>0),None):fail.append(f'stress target 0x{se}: no reconstructed regions')
name_to_entry={r.get('name',''):e for e,r in functions.items()}
if '_INIT_2' in name_to_entry:
 e=name_to_entry['_INIT_2']
 if not next((x for x in summaries if x['entry']==e and int(x['region_count'] or 0)>0),None):fail.append('_INIT_2: no reconstructed regions')
rf=['function_entry','function_name','region_id','start_address','end_address','center_address','reasons','sources','classification','semantic_name','confidence','pcode_source','high_pcode_ops_seen','raw_pcode_ops_seen','pcode_ops_rendered','string_count','call_count','c_path','evidence_path'];sf=['entry','name','size_bytes','protection','protection_score','whole_decompile_status','high_pcode_status','region_count','c_like_regions','dispatcher_candidates','top_dispatcher_score','state_register','overview_path'];write_csv(root/'v55_region_map.csv',region_rows,rf);write_csv(root/'v55_reconstruction_summary.csv',summaries,sf)
stats={'target_functions':len(targets),'high_protection_functions':len(high_required),'regions':len(region_rows),'regions_with_c_like_evidence':sum(int(r['pcode_ops_rendered'])>0 or int(r['string_count'])>0 or int(r['call_count'])>0 for r in region_rows),'state_dispatcher_regions':sum(r['classification']=='STATE_DISPATCHER' for r in region_rows),'indirect_flow_regions':sum(r['classification']=='INDIRECT_FLOW' for r in region_rows),'raw_pcode_fallback_regions':sum(r['pcode_source']!='HIGH_PCODE_SSA' for r in region_rows),'validation_failures':fail};(root/'v55_reconstruction_stats.json').write_text(json.dumps(stats,indent=2),encoding='utf-8')
with (root/'v55_reconstruction_report.md').open('w',encoding='utf-8') as w:
 w.write('# V5.5 large-function reconstruction\n\nV5.5 builds bounded semantic regions and C-like evidence views. It never labels reconstructed output as original source, and keeps V5.4 full protected evidence untouched.\n\n');[w.write(f"- {k.replace('_',' ').title()}: **{v}**\n") for k,v in stats.items() if k!='validation_failures']
css='body{font-family:system-ui,-apple-system,sans-serif;background:#101114;color:#eee;max-width:1180px;margin:auto;padding:16px}a{color:#7db7ff}table{width:100%;border-collapse:collapse}th,td{padding:8px;border-bottom:1px solid #30333a;text-align:left;vertical-align:top}code{font-family:ui-monospace,monospace}.warn{color:#ffb86c}';parts=[f'<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>V5.5 Reconstructed C</title><style>{css}</style></head><body>','<h1>V5.5 Reconstructed C</h1>','<p class="warn"><b>Not original source.</b> Confidence-tagged reconstruction from ARM64/P-code/string/call evidence.</p>','<table><tr><th>Function</th><th>Protection</th><th>Regions</th><th>Open</th></tr>']
for s in summaries:parts.append(f"<tr><td><code>{html.escape(s['name'])}</code><br><small>0x{s['entry']}</small></td><td>{html.escape(str(s['protection']))} / {html.escape(str(s['protection_score']))}</td><td>{s['region_count']} ({s['c_like_regions']} with evidence)</td><td><a href='reconstructed_c/{s['entry']}/overview.c'>overview.c</a></td></tr>")
parts+=['</table>','</body></html>'];(human/'V55_RECONSTRUCTION.html').write_text('\n'.join(parts),encoding='utf-8');start=human/'START_HERE.html'
if start.exists():
 txt=start.read_text(encoding='utf-8',errors='replace')
 if 'V55_RECONSTRUCTION.html' not in txt:
  block='<section><h2>V5.5 Large Function Reconstruction</h2><p><a href="V55_RECONSTRUCTION.html">Open reconstructed C / semantic regions</a></p><p><a href="ida/README.html">IDA Pro annotation bridge</a></p></section>'
  start.write_text(txt.replace('</body>',block+'</body>') if '</body>' in txt else txt+block,encoding='utf-8')
if fail:raise SystemExit('V5.5 reconstruction validation failed: '+'; '.join(fail))
print(json.dumps(stats))
