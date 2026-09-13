#!/usr/bin/env python3
import csv,json,sys
from collections import defaultdict
from pathlib import Path

if len(sys.argv)!=2:raise SystemExit('usage: v51_ai_context.py <analysis-output-dir>')
root=Path(sys.argv[1])

def rows(name):
 p=root/name
 if not p.exists() or p.stat().st_size==0:return []
 with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))

def canon(x):
 try:return f'{int((x or "").strip(),16):08X}'
 except:return (x or '').strip().upper()

selected=rows('v51_selected_functions.csv')
flow={canon(r.get('entry')):r for r in rows('v5_function_flow.csv')}
call=rows('callgraph.csv');strings=rows('string_xrefs.csv')
high={ (canon(r.get('function_entry')),canon(r.get('branch_address'))):r for r in rows('v51_high_pcode_indirect_slices.csv') }
ind=defaultdict(list)
for r in rows('v5_indirect_branches.csv'):ind[canon(r.get('function_entry'))].append(r)
state=defaultdict(list)
for r in rows('v5_state_values.csv'):state[canon(r.get('function_entry'))].append(r)
writers=defaultdict(list)
for r in rows('v51_table_writer_candidates.csv'):writers[canon(r.get('table_address'))].append(r)
fallback={canon(r.get('entry')):r for r in rows('v51_decompile_fallback.csv')}
callers=defaultdict(list);callees=defaultdict(list)
for r in call:
 a,b=canon(r.get('caller_entry')),canon(r.get('callee_entry'))
 if a and b:callees[a].append(r);callers[b].append(r)
name_entries=defaultdict(list)
for r in selected:name_entries[r.get('name','')].append(canon(r.get('entry')))
str_by=defaultdict(list)
for r in strings:
 for e in name_entries.get(r.get('from_function',''),[]):
  v=(r.get('value') or '').strip()
  if v and v not in str_by[e]:str_by[e].append(v)

ctx=root/'ai_context_v51';cards=ctx/'function_cards';cards.mkdir(parents=True,exist_ok=True)
index=[]
for rank,r in enumerate(selected[:120],1):
 e=canon(r.get('entry'));f=flow.get(e,{});inds=ind.get(e,[]);sts=state.get(e,[])
 path=cards/f'{rank:03d}_{e}.md'
 with path.open('w',encoding='utf-8') as w:
  w.write(f'# {rank}. {r.get("name") or "sub_"+e}\n\n')
  w.write(f'- Entry: `0x{e}`\n- V5.1 tier: `{r.get("v51_priority_tier","")}`\n- V5.1 score: **{r.get("v51_score","")}**\n- Mode: `{r.get("recommended_mode","")}`\n- Size: **{r.get("size_bytes","")} bytes**\n')
  w.write(f'- Forward call distance: `{r.get("forward_distance","")}`\n- Callback distance: `{r.get("callback_distance","")}`\n- Third-party family: `{r.get("third_party_family","")}`\n')
  if f:w.write(f'- Blocks: **{f.get("basic_blocks","")}**\n- Indirect branches: **{f.get("indirect_branches","")}**\n- Dispatcher score: **{f.get("top_dispatcher_score","")}**\n- State register: `{f.get("state_register","")}` ({f.get("state_compare_hits","")} compares)\n')
  if e in fallback:w.write(f'- Whole decompile fallback: `{fallback[e].get("fallback_path","")}`\n')
  w.write('\n## Callers\n\n')
  for x in callers.get(e,[])[:24]:w.write(f'- `0x{canon(x.get("caller_entry"))}` `{x.get("caller_name","")}` at `0x{canon(x.get("callsite"))}`\n')
  if not callers.get(e):w.write('- none recovered\n')
  w.write('\n## Callees\n\n')
  for x in callees.get(e,[])[:36]:w.write(f'- `0x{canon(x.get("callee_entry"))}` `{x.get("callee_name","")}` from `0x{canon(x.get("callsite"))}`\n')
  if not callees.get(e):w.write('- none recovered\n')
  if inds:
   w.write('\n## Indirect control flow\n\n')
   for x in inds[:24]:
    key=(e,canon(x.get('branch_address')));h=high.get(key,{})
    w.write(f'- `0x{key[1]}` pattern={x.get("pattern","")} table=`0x{x.get("table_address","")}`')
    if h:w.write(f' high-P-code=`{h.get("target_expression","")[:260]}`')
    w.write('\n')
  if sts:
   w.write('\n## State comparisons\n\n')
   for x in sts[:32]:w.write(f'- `0x{canon(x.get("compare_address"))}` {x.get("register","")} vs `{x.get("constant","")}` {x.get("condition","")} -> `{x.get("true_target","")}` / `{x.get("false_target","")}`\n')
  if str_by.get(e):
   w.write('\n## Referenced strings\n\n')
   for s in str_by[e][:30]:w.write(f'- `{s[:260]}`\n')
  w.write('\n## Best next evidence\n\n')
  if r.get('recommended_mode')=='region':w.write(f'- `v5_slices/{e}/` and `v51_high_pcode_slices/` for recovered indirect-flow expressions.\n')
  else:w.write('- `v4_selected_ida/` + `v4_decompiled_selected/`; if decompile failed, use `v51_decompile_fallback/`.\n')
 index.append({'rank':rank,'entry':e,'name':r.get('name',''),'tier':r.get('v51_priority_tier',''),'score':r.get('v51_score',''),'mode':r.get('recommended_mode',''),'card':str(path.relative_to(root))})

with (ctx/'overview.md').open('w',encoding='utf-8') as w:
 w.write('# Mobile Ghidra Lab V5.1 AI context\n\nRead this first. V5.1 prioritizes directed JNI/app execution paths, callback/function-pointer evidence and validated indirect-flow evidence before generic complexity.\n\n')
 w.write('| # | Tier | Score | Entry | Mode | Function | Card |\n|---:|---|---:|---|---|---|---|\n')
 for r in index[:70]:w.write(f"| {r['rank']} | {r['tier']} | {r['score']} | `0x{r['entry']}` | {r['mode']} | `{r['name']}` | `{r['card']}` |\n")
 w.write('\n## Global evidence to read next\n\n- `v51_ranking.md`\n- `v51_quality_report.md`\n- `v51_high_pcode_slices_report.md`\n- `v51_runtime_table_report.md`\n- `v51_dispatcher_app.csv`\n- `v51_runtime_table_probe.js` when static table bytes remain invalid at runtime-sensitive sites.\n')
(ctx/'index.json').write_text(json.dumps(index,indent=2),encoding='utf-8')
print(json.dumps({'cards':len(index),'overview':'ai_context_v51/overview.md'}))
