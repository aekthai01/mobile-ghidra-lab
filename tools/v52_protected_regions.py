#!/usr/bin/env python3
import bisect,csv,sys
from collections import defaultdict
from pathlib import Path
root=Path(sys.argv[1])
def rows(n):
 p=root/n
 if not p.exists() or not p.stat().st_size:return []
 with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))
def canon(x):
 try:return f'{int((x or "").strip(),16):08X}'
 except:return (x or '').strip().upper()
prot={canon(r.get('entry')):r for r in rows('v52_protected_functions.csv') if r.get('complexity_priority')=='high'}
ind=defaultdict(list);state=defaultdict(list);raw=defaultdict(list)
for r in rows('v5_indirect_branches.csv'):ind[canon(r.get('function_entry'))].append(r)
for r in rows('v5_state_values.csv'):state[canon(r.get('function_entry'))].append(r)
for r in rows('v51_raw_pcode.csv'):raw[canon(r.get('function_entry'))].append(r)
allins=[]
p=root/'disassembly.txt'
if p.exists():
 with p.open(encoding='utf-8',errors='replace') as f:
  for line in f:
   q=line.rstrip('\n').split('\t',2)
   if len(q)<3:continue
   try:allins.append((int(q[0],16),q[2].strip()))
   except:pass
allins.sort();aa=[x[0] for x in allins]
outdir=root/'v52_protected_regions';outdir.mkdir(exist_ok=True);idx=[]
for e,r in list(prot.items())[:100]:
 anchors=[(canon(x.get('branch_address')),'indirect-branch') for x in ind.get(e,[])[:12]]+[(canon(x.get('compare_address')),'state-compare') for x in state.get(e,[])[:12]]
 seen=[]
 for a,kind in anchors:
  try:x=int(a,16)
  except:continue
  if any(abs(x-y)<0x40 for y in seen):continue
  seen.append(x);lo=bisect.bisect_left(aa,x-0x60);hi=bisect.bisect_right(aa,x+0x60);arm=allins[lo:hi]
  pc=[]
  for q in raw.get(e,[]):
   try:y=int(canon(q.get('instruction_address')),16)
   except:continue
   if abs(y-x)<=0x60:pc.append(q)
  path=outdir/f'{e}_{a}_{kind}.md'
  with path.open('w',encoding='utf-8') as w:
   w.write(f'# Protected region `0x{e}` / `0x{a}`\n\n- Function: `{r.get("name","")}`\n- Anchor: `{kind}`\n- Complexity score: **{r.get("complexity_priority_score","")}**\n\n```asm\n')
   for ad,t in arm:w.write(f'{ad:016X}  {t}\n')
   w.write('```\n\n```text\n')
   for q in pc:w.write(f"0x{canon(q.get('instruction_address'))} [{q.get('pcode_index')}] {q.get('mnemonic')} {q.get('output')} <- {q.get('inputs')}\n")
   w.write('```\n')
  idx.append({'function_entry':e,'function_name':r.get('name',''),'anchor_address':a,'anchor_kind':kind,'complexity_score':r.get('complexity_priority_score',''),'path':str(path.relative_to(root))})
fields=['function_entry','function_name','anchor_address','anchor_kind','complexity_score','path']
with (root/'v52_protected_region_index.csv').open('w',encoding='utf-8',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(idx)
with (root/'v52_protected_regions.md').open('w',encoding='utf-8') as w:w.write(f'# V5.2 protected-function regions\n\n- Focused regions: **{len(idx)}**\n- High-complexity functions: **{len(prot)}**\n\nBounded ARM64/P-code windows preserve evidence for giant protected functions even when whole-function decompilation cannot finish.\n')
print('protected regions',len(idx))
