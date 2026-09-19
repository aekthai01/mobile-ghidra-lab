#!/usr/bin/env python3
import csv,json,math,re,sys
from collections import defaultdict
from pathlib import Path

if len(sys.argv)!=2: raise SystemExit('usage: v56_all_c_validate.py <analysis-output-dir>')
root=Path(sys.argv[1]); WINDOW=180; STEP=160

def rows(name):
 p=root/name
 if not p.is_file() or not p.stat().st_size:return []
 with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))
def canon(v):
 v=(v or '').strip(); v=v[2:] if v.lower().startswith('0x') else v
 try:return f'{int(v,16):08X}'
 except:return v.upper()
def as_int(v):
 try:return int(float(v or 0))
 except:return 0
def expected(n):
 if n<=0:return 0
 if n<=WINDOW:return 1
 return 1+math.ceil((n-WINDOW)/STEP)
def meaningful(path):
 if not path.is_file() or path.stat().st_size<80:return False,''
 t=path.read_text(encoding='utf-8',errors='replace'); b=re.sub(r'/\*.*?\*/','',t,flags=re.S); b=re.sub(r'//.*','',b)
 return ('{' in b and '}' in b and '(' in b and ')' in b and any(x in b for x in ('=','return','if (','if(','FUN_','sub_','goto '))),t

all_rows=rows('v56_all_c_index.csv'); regions=rows('v56_region_c_index.csv'); seeds=rows('v56_login_seeds.csv')
by_fn=defaultdict(list)
for r in regions:by_fn[canon(r.get('function_entry'))].append(r)
imm={canon(r.get('function_entry')) for r in seeds if r.get('kind')=='imm_0x2712'}
https={canon(r.get('function_entry')) for r in seeds if r.get('kind')=='https_xref'}
strong=imm & https
errors=[]; whole=0; fallback=0; complete=0; details=[]
for r in all_rows:
 e=canon(r.get('entry')); st=(r.get('status') or '').lower(); ins=as_int(r.get('instructions')); text=''; ok=False
 if st=='ok' and r.get('c_file'):
  ok,text=meaningful(root/r['c_file']); whole+=1
  if not ok:errors.append(f'{e}: whole C file is missing or not meaningful')
 else:
  fallback+=1; exp=expected(ins); rr=[x for x in by_fn.get(e,[]) if 'v56-exhaustive-coverage' in (x.get('reason') or '')]
  good=[]
  for x in rr:
   if (x.get('status') or '').lower().startswith('ok') and x.get('c_file'):
    m,t=meaningful(root/x['c_file'])
    if m:good.append(x);text+='\n'+t
  if exp<=0:errors.append(f'{e}: fallback has no instruction coverage')
  elif len(good)!=exp:errors.append(f'{e}: meaningful fallback regions {len(good)} != expected {exp}')
  else:ok=True;complete+=1
 if ok and e in imm and not (('0x2712' in text.lower()) or ('10002' in text)):
  errors.append(f'{e}: C output lost 0x2712/10002 login evidence')
 if ok and e in strong and 'https' not in text.lower():
  errors.append(f'{e}: strong login C output lost HTTPS evidence')
 details.append({'entry':e,'status':st,'instructions':ins,'complete':ok,'login_0x2712':e in imm,'strong_login':e in strong})

inventory=rows('functions.csv')
internal=[r for r in inventory if (r.get('is_external') or '').strip().lower()!='true']
internal_entries={canon(r.get('entry')) for r in internal}; all_entries={canon(r.get('entry')) for r in all_rows}
missing=sorted(internal_entries-all_entries); extra=sorted(all_entries-internal_entries)
if len(all_rows)!=len(internal) or missing or extra:
 errors.append(f'all-C inventory mismatch: indexed={len(all_rows)} internal_discovered={len(internal)} missing={len(missing)} extra={len(extra)}')
if not all_rows:errors.append('v56_all_c_index.csv is empty')
report={'status':'pass' if not errors else 'fail','discovered_functions':len(inventory),'internal_discovered_functions':len(internal),'all_c_functions':len(all_rows),'whole_c_functions':whole,'fallback_functions':fallback,'fallback_complete':complete,'missing_internal_entries':missing,'extra_entries':extra,'immediate_0x2712_functions':sorted(imm),'strong_0x2712_https_functions':sorted(strong),'errors':errors,'functions':details}
(root/'v56_all_c_acceptance.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
with (root/'v56_all_c_acceptance.md').open('w',encoding='utf-8') as w:
 w.write('# V5.6 All-C acceptance\n\n');w.write(f"- Status: **{report['status']}**\n- Discovered functions: **{len(inventory)}**\n- Internal discovered functions: **{len(internal)}**\n- All-C indexed functions: **{len(all_rows)}**\n- Whole C: **{whole}**\n- Fallback functions: **{fallback}**\n- Complete fallback: **{complete}**\n- 0x2712 functions: **{len(imm)}**\n- Strong 0x2712 + HTTPS: **{len(strong)}**\n")
 if errors:
  w.write('\n## Errors\n\n');[w.write(f'- {x}\n') for x in errors[:1000]]
if errors:raise SystemExit('V5.6 All-C failed: '+'; '.join(errors[:40]))
print(json.dumps({k:v for k,v in report.items() if k not in ('errors','functions')}))
