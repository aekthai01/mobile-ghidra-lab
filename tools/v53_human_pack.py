#!/usr/bin/env python3
import csv, html, json, re, shutil, sys
from collections import defaultdict
from pathlib import Path
if len(sys.argv)!=2: raise SystemExit('usage: v53_human_pack.py <analysis-output-dir>')
root=Path(sys.argv[1]); human=root/'human'; asm_out=human/'asm'; region_out=human/'regions'; pseudo_out=human/'pseudocode'
for p in (human,asm_out,region_out,pseudo_out):p.mkdir(parents=True,exist_ok=True)
def rows(n):
 p=root/n
 if not p.exists() or not p.stat().st_size:return []
 with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))
def canon(x):
 try:return f'{int((x or "").strip(),16):08X}'
 except:return (x or '').strip().upper()
def cleanval(v):
 s=(v or '').strip()
 if len(s)>=2 and s[0]=='"' and s[-1]=='"':s=s[1:-1]
 return s
selected=rows('v52_selected_functions.csv') or rows('v51_selected_functions.csv')
protected={canon(r.get('entry')):r for r in rows('v52_protected_functions.csv')}
exports={canon(r.get('entry')):r for r in rows('v4_selected_export.csv')}
strings=rows('string_xrefs.csv'); calls=rows('callgraph.csv')
by_fn=defaultdict(list)
for r in strings:by_fn[(r.get('from_function') or '').strip()].append(r)
callers=defaultdict(list);callees=defaultdict(list)
for r in calls:
 a,b=canon(r.get('caller_entry')),canon(r.get('callee_entry'))
 if a:callees[a].append(r)
 if b:callers[b].append(r)
chosen=[];seen=set()
for r in selected[:50]:
 e=canon(r.get('entry'))
 if e and e not in seen:chosen.append(r);seen.add(e)
for r in selected:
 e=canon(r.get('entry'));p=protected.get(e,{})
 if e not in seen and (p.get('complexity_priority') or '').lower()=='high':chosen.append(r);seen.add(e)
 if len(chosen)>=60:break
def file_by_prefix(base,e,suffix):
 p=root/base
 if not p.exists():return None
 short=e.lstrip('0') or '0'
 xs=list(p.glob(f'{short}*{suffix}'))+list(p.glob(f'{e}*{suffix}'))
 return xs[0] if xs else None
def safe(s):return re.sub(r'[^A-Za-z0-9._-]+','_',s or 'function')[:60]
index=[]
for rank,r in enumerate(chosen,1):
 e=canon(r.get('entry'));name=(r.get('name') or 'sub_'+e).strip();asm_rel='';pseudo_rel='';region_rel=''
 af=file_by_prefix('v4_selected_ida',e,'.asm')
 if af:
  of=asm_out/f'{rank:03d}_{e}_{safe(name)}.asm';shutil.copyfile(af,of);asm_rel=str(of.relative_to(human))
 cf=file_by_prefix('v4_decompiled_selected',e,'.c')
 if cf:
  of=pseudo_out/f'{rank:03d}_{e}_{safe(name)}.c';shutil.copyfile(cf,of);pseudo_rel=str(of.relative_to(human))
 rb=root/'v4_giant_regions';short=e.lstrip('0') or '0'
 if rb.exists():
  ds=[d for d in rb.iterdir() if d.is_dir() and (d.name.upper().startswith(short.upper()+'_') or d.name.upper().startswith(e.upper()+'_'))]
  if ds:
   files=sorted(ds[0].glob('*.asm'))[:20]
   if files:
    of=region_out/f'{rank:03d}_{e}_{safe(name)}_regions.asm'
    with of.open('w',encoding='utf-8') as w:
     w.write('; V5.3 combined protected-function regions. ARM64 lines contain inline string xrefs when Ghidra recovered them.\n\n')
     for i,f in enumerate(files,1):
      w.write('\n; ============================================================================\n; REGION %02d: %s\n; ============================================================================\n'%(i,f.name))
      w.write(f.read_text(encoding='utf-8',errors='replace'))
    region_rel=str(of.relative_to(human))
 p=protected.get(e,{}); ex=exports.get(e,{})
 uniq=[]; seen_s=set()
 for x in by_fn.get(name,[]):
  k=(canon(x.get('string_address')),cleanval(x.get('value')))
  if k not in seen_s:seen_s.add(k);uniq.append(x)
 index.append({'rank':rank,'entry':e,'name':name,'tier':r.get('v52_priority_tier') or r.get('v51_priority_tier',''),'score':r.get('v52_score') or r.get('v51_score') or r.get('score',''),'mode':r.get('recommended_mode',''),'protection':p.get('complexity_priority','normal'),'protection_score':p.get('complexity_priority_score',''),'size':r.get('size_bytes',''),'indirect':r.get('indirect_jumps',''),'state_reg':r.get('state_register',''),'state_hits':r.get('state_compare_hits',''),'decompile_status':ex.get('decompile_status',''),'strings':uniq[:24],'asm':asm_rel,'regions':region_rel,'pseudo':pseudo_rel})
css='body{font-family:system-ui,-apple-system,sans-serif;background:#111;color:#eee;max-width:1120px;margin:auto;padding:16px}a{color:#79b8ff}table{border-collapse:collapse;width:100%;font-size:13px}th,td{padding:7px;border-bottom:1px solid #333;text-align:left;vertical-align:top}.card{padding:13px;border:1px solid #333;border-radius:10px;margin:14px 0;background:#181818}.high{border-left:5px solid #ff885c}.tag{display:inline-block;border:1px solid #555;border-radius:999px;padding:2px 7px;margin:2px;font-size:12px}code,.mono{font-family:ui-monospace,SFMono-Regular,monospace}.muted{color:#aaa}'
parts=[f'<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Mobile Ghidra Lab V5.3</title><style>{css}</style></head><body>', '<h1>Mobile Ghidra Lab V5.3: START HERE</h1>', '<p>หน้านี้คือฉบับสำหรับคน ไม่ต้องเปิด CSV/P-code หลายร้อย MB เอง ARM64 ที่ลิงก์จากหน้านี้ฝัง string xrefs ไว้ในบรรทัด instruction แล้วแบบ IDA-like.</p>', '<p class="muted">Protection สูงหมายถึงควรตรวจลึก ไม่ได้พิสูจน์ว่าฟังก์ชันสำคัญเสมอ String ที่แสดงมาจาก Ghidra xref evidence ที่ address นั้นโดยตรง.</p>', '<h2>Top / protected targets</h2><table><tr><th>#</th><th>Function</th><th>Tier</th><th>Protection</th><th>Size</th><th>Open</th></tr>']
for r in index:
 links=[]
 if r['asm']:links.append(f'<a href="{html.escape(r["asm"])}">ARM64+strings</a>')
 if r['regions']:links.append(f'<a href="{html.escape(r["regions"])}">protected regions</a>')
 if r['pseudo']:links.append(f'<a href="{html.escape(r["pseudo"])}">pseudocode</a>')
 parts.append(f'<tr><td>{r["rank"]}</td><td><a href="#f{r["rank"]}"><code>{html.escape(r["name"])}</code><br><span class="muted">0x{r["entry"]}</span></a></td><td>{html.escape(str(r["tier"]))}</td><td>{html.escape(str(r["protection"]))}</td><td>{html.escape(str(r["size"]))}</td><td>{" · ".join(links) or "-"}</td></tr>')
parts.append('</table><h2>Function dossiers</h2>')
for r in index:
 parts.append(f'<section id="f{r["rank"]}" class="card {"high" if r["protection"]=="high" else ""}"><h3>{r["rank"]}. <code>{html.escape(r["name"])}</code> <span class="muted">0x{r["entry"]}</span></h3>')
 for tag in (r['tier'],'protection:'+str(r['protection']),'mode:'+str(r['mode']),'size:'+str(r['size']),'indirect:'+str(r['indirect']),'state:'+str(r['state_reg'])+'/'+str(r['state_hits'])):parts.append(f'<span class="tag">{html.escape(tag)}</span>')
 parts.append(f'<p><b>Decompiler:</b> <code>{html.escape(str(r["decompile_status"]))}</code></p>')
 links=[]
 if r['asm']:links.append(f'<a href="{html.escape(r["asm"])}">ARM64 + inline strings</a>')
 if r['regions']:links.append(f'<a href="{html.escape(r["regions"])}">combined protected regions</a>')
 if r['pseudo']:links.append(f'<a href="{html.escape(r["pseudo"])}">pseudocode</a>')
 if links:parts.append('<p>'+ ' · '.join(links)+'</p>')
 if r['strings']:
  parts.append('<details open><summary><b>Strings referenced by this function</b></summary><ul>')
  for x in r['strings']:
   v=cleanval(x.get('value')).replace('\n','\\n').replace('\r','\\r')
   if len(v)>260:v=v[:257]+'...'
   parts.append(f'<li><code>0x{canon(x.get("from_address"))}</code> → <span class="mono">{html.escape(v)}</span></li>')
  parts.append('</ul></details>')
 cs=callers.get(r['entry'],[])[:8];ds=callees.get(r['entry'],[])[:12]
 if cs or ds:
  parts.append('<details><summary>Call evidence</summary>')
  if cs:parts.append('<p><b>Callers:</b> '+', '.join(f'<code>{html.escape(x.get("caller_name",""))}@0x{canon(x.get("callsite"))}</code>' for x in cs)+'</p>')
  if ds:parts.append('<p><b>Callees:</b> '+', '.join(f'<code>{html.escape(x.get("callee_name",""))}</code>' for x in ds)+'</p>')
  parts.append('</details>')
 parts.append('</section>')
parts.append('</body></html>')
(human/'START_HERE.html').write_text('\n'.join(parts),encoding='utf-8')
with (human/'START_HERE.txt').open('w',encoding='utf-8') as w:
 w.write('Mobile Ghidra Lab V5.3 human pack\nOpen START_HERE.html first.\nARM64 files already contain inline Ghidra string-xref comments.\n\n')
 for r in index[:30]:w.write(f"{r['rank']:02d}. 0x{r['entry']} {r['name']} tier={r['tier']} protection={r['protection']}\n")
with (human/'index.json').open('w',encoding='utf-8') as f:json.dump(index,f,indent=2,ensure_ascii=False)
stats={'functions':len(index),'asm_files':sum(bool(r['asm']) for r in index),'combined_region_files':sum(bool(r['regions']) for r in index),'pseudocode_files':sum(bool(r['pseudo']) for r in index),'total_human_files':sum(1 for _ in human.rglob('*') if _.is_file())}
(root/'v53_human_pack_stats.json').write_text(json.dumps(stats,indent=2),encoding='utf-8')
with (root/'v53_human_pack_report.md').open('w',encoding='utf-8') as w:
 w.write('# V5.3 human-first artifact\n\n')
 for k,v in stats.items():w.write(f'- {k.replace("_"," ").title()}: **{v}**\n')
 w.write('\nOpen `human/START_HERE.html`. Region-mode functions are consolidated into one ARM64 file per function instead of dozens of region files.\n')
print(json.dumps(stats))
