#!/usr/bin/env python3
import csv,re,sys
from pathlib import Path
root=Path(sys.argv[1])
def n(v):
    try:return int(float(v or 0))
    except:return 0
p=root/'priority_metrics.csv'
rows=list(csv.DictReader(p.open(encoding='utf-8',newline='')))
runtime=re.compile(r'(?i)(^operator (new|delete)|^__cxa_|^__thread|^pthread_|^std::|system_error|basic_string|^mem(cpy|move|set)|^malloc$|^free$|^dlopen$|^dlsym$|^mmap$|^mprotect$)')
for r in rows:
    third=(r.get('third_party') or '').lower()=='true' or bool((r.get('third_party_family') or '').strip())
    high=r.get('complexity_priority')=='high'; med=r.get('complexity_priority')=='medium'
    score=n(r.get('v51_score'))
    if high and not third:score+=24000
    elif med and not third:score+=9000
    if runtime.search(r.get('name') or '') and not high:score-=10000
    tier=r.get('v51_priority_tier') or 'D'
    if high and not third and not tier.startswith('A-'):tier='A-protected'
    elif med and not third and tier in ('C-interesting','D','Y-api-context'):tier='B-protected'
    r['v52_score']=score;r['v52_priority_tier']=tier
    r['v51_score']=score;r['v51_priority_tier']=tier
order={'A-seed':0,'A-callback':1,'A-forward':2,'A-protected':3,'B-callback-flow':4,'B-forward':5,'B-protected':6,'C-interesting':7,'D':8,'Y-api-context':9,'Z-third-party':10}
rows.sort(key=lambda r:(order.get(r.get('v52_priority_tier','D'),99),-n(r.get('v52_score')),-n(r.get('complexity_priority_score'))))
sel=[];seen=set();regions=thirds=0
def add(r,force=False):
    global regions,thirds
    e=r.get('entry','')
    if not e or e in seen:return False
    third=(r.get('third_party') or '').lower()=='true' or bool((r.get('third_party_family') or '').strip())
    region=r.get('recommended_mode')=='region'
    if third and thirds>=12:return False
    if region and regions>=180 and not force:return False
    sel.append(r);seen.add(e);regions+=1 if region else 0;thirds+=1 if third else 0;return True
for r in rows:
    if len(sel)>=240:break
    if (r.get('v52_priority_tier') or '').startswith(('A-','B-')):add(r,r.get('complexity_priority')=='high')
reserve=0
for r in sorted((x for x in rows if x.get('complexity_priority')=='high' and (x.get('third_party') or '').lower()!='true'),key=lambda x:-n(x.get('complexity_priority_score'))):
    if reserve>=120 or len(sel)>=360:break
    if add(r,True):reserve+=1
for r in rows:
    if len(sel)>=420:break
    third=(r.get('third_party') or '').lower()=='true' or bool((r.get('third_party_family') or '').strip())
    if (not third and n(r.get('v52_score'))>=4500) or (third and n(r.get('v52_score'))>=15000):add(r,r.get('complexity_priority')=='high')
fields=list(rows[0].keys())
for fn,data in [('v52_function_metrics.csv',rows),('v52_selected_functions.csv',sel)]:
    with (root/fn).open('w',encoding='utf-8',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(data)
prot=sorted((r for r in rows if r.get('complexity_priority') in ('high','medium') and (r.get('third_party') or '').lower()!='true'),key=lambda r:-n(r.get('complexity_priority_score')))
with (root/'v52_protected_functions.csv').open('w',encoding='utf-8',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(prot)
with (root/'v52_priority.md').open('w',encoding='utf-8') as w:
    w.write('# V5.2 protection-aware priority\n\nHeavily protected unknown/app functions receive reserved analysis capacity even when a direct JNI path was not recovered. Protection raises priority; it is not proof of semantic importance.\n\n')
    w.write(f'- Selected: **{len(sel)}**\n- High-complexity reserve added: **{reserve}**\n- High/medium candidates: **{len(prot)}**\n\n')
    w.write('| # | Complexity | Score | Entry | Tier | Mode | Function |\n|---:|---|---:|---|---|---|---|\n')
    for i,r in enumerate(prot[:120],1):w.write(f"| {i} | {r.get('complexity_priority')} | {r.get('complexity_priority_score')} | `0x{r.get('entry')}` | {r.get('v52_priority_tier')} | {r.get('recommended_mode')} | `{r.get('name','')}` |\n")
print('v5.2 selected',len(sel),'protected reserve',reserve)
