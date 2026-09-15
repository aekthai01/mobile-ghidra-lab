#!/usr/bin/env python3
import csv,json,sys
from collections import defaultdict
from pathlib import Path
if len(sys.argv)!=2: raise SystemExit('usage: v55_cfg_metrics.py <analysis-output-dir>')
root=Path(sys.argv[1]); human=root/'human'; human.mkdir(exist_ok=True)
def rows(n):
 p=root/n
 if not p.exists() or not p.stat().st_size:return []
 with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))
def canon(v):
 v=(v or '').strip(); v=v[2:] if v.lower().startswith('0x') else v
 try:return f'{int(v,16):08X}'
 except:return v.upper()
def write_csv(name,data,fields):
 with (root/name).open('w',encoding='utf-8',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(data)
flow={canon(r.get('entry')):r for r in rows('v5_function_flow.csv') if canon(r.get('entry'))}
edges_by_fn=defaultdict(list)
for r in rows('v5_clean_edges.csv'):
 e=canon(r.get('function_entry'));a=canon(r.get('from_block'));b=canon(r.get('to_block'))
 if e and a and b:edges_by_fn[e].append((a,b,r.get('edge_type') or ''))
def tarjan(nodes,adj):
 idx=0;stack=[];on=set();ind={};low={};comps=[];sys.setrecursionlimit(max(10000,len(nodes)*3+100))
 def visit(v):
  nonlocal idx
  ind[v]=low[v]=idx;idx+=1;stack.append(v);on.add(v)
  for w in adj.get(v,()):
   if w not in ind:visit(w);low[v]=min(low[v],low[w])
   elif w in on:low[v]=min(low[v],ind[w])
  if low[v]==ind[v]:
   c=[]
   while True:
    w=stack.pop();on.remove(w);c.append(w)
    if w==v:break
   comps.append(c)
 for v in sorted(nodes):
  if v not in ind:visit(v)
 return comps
def immediate_dominators(nodes,adj,preds,entry):
 nodes=set(nodes)
 if not nodes:return {},set()
 if entry not in nodes:entry=min(nodes,key=lambda x:int(x,16))
 seen={entry};post=[];stack=[(entry,0,sorted(adj.get(entry,set()),key=lambda x:int(x,16)))]
 while stack:
  n,i,kids=stack[-1]
  if i<len(kids):
   w=kids[i];stack[-1]=(n,i+1,kids)
   if w not in seen:seen.add(w);stack.append((w,0,sorted(adj.get(w,set()),key=lambda x:int(x,16))))
  else:post.append(n);stack.pop()
 rpo=list(reversed(post));pos={n:i for i,n in enumerate(rpo)};idom={entry:entry}
 def intersect(a,b):
  while a!=b:
   while pos[a]>pos[b]:a=idom[a]
   while pos[b]>pos[a]:b=idom[b]
  return a
 changed=True
 while changed:
  changed=False
  for n in rpo[1:]:
   ps=[p for p in preds.get(n,()) if p in idom]
   if not ps:continue
   new=ps[0]
   for q in ps[1:]:new=intersect(q,new)
   if idom.get(n)!=new:idom[n]=new;changed=True
 idom[entry]='';return idom,seen
def dom_intervals(idom,entry):
 tree=defaultdict(list)
 for n,p in idom.items():
  if p:tree[p].append(n)
 tin={};tout={};depth={entry:0};tick=0;stack=[(entry,0,False)]
 while stack:
  n,d,exit_=stack.pop()
  if exit_:tout[n]=tick;tick+=1;continue
  tin[n]=tick;tick+=1;depth[n]=d;stack.append((n,d,True))
  for c in sorted(tree.get(n,()),key=lambda x:int(x,16),reverse=True):stack.append((c,d+1,False))
 return tin,tout,depth
def dominates(a,b,tin,tout):return a in tin and b in tin and tin[a]<=tin[b] and tout[b]<=tout[a]
def natural_loop(src,header,preds):
 loop={header,src};q=[src]
 while q:
  n=q.pop()
  for p in preds.get(n,()):
   if p not in loop:loop.add(p);q.append(p)
 return loop
fn_rows=[];block_rows=[];back_rows=[];scc_rows=[]
for e,edges in sorted(edges_by_fn.items(),key=lambda kv:int(kv[0],16)):
 nodes={e};adj=defaultdict(set);preds=defaultdict(set)
 for a,b,k in edges:nodes.update((a,b));adj[a].add(b);preds[b].add(a)
 comps=tarjan(nodes,adj);sid={};ssz={};cyc={};irr_by={};irreducible=0
 for i,c in enumerate(sorted(comps,key=lambda c:min(int(x,16) for x in c)),1):
  s=f'S{i:04d}';cs=set(c);entries={n for n in c for p in preds.get(n,()) if p not in cs};iscyc=len(c)>1 or any(n in adj.get(n,set()) for n in c);irr=iscyc and len(entries)>1
  if irr:irreducible+=1
  for n in c:sid[n]=s;ssz[n]=len(c);cyc[n]=iscyc;irr_by[n]=irr
  scc_rows.append({'function_entry':e,'scc_id':s,'size':len(c),'cyclic':str(iscyc).lower(),'external_entry_nodes':len(entries),'irreducible':str(irr).lower(),'nodes':' '.join(sorted(c,key=lambda x:int(x,16)))})
 entry=e if e in nodes else min(nodes,key=lambda x:int(x,16));idom,reachable=immediate_dominators(nodes,adj,preds,entry);tin,tout,depth=dom_intervals(idom,entry)
 loop_headers=set();loop_size={};bin_=defaultdict(int);bout=defaultdict(int)
 for a,b,k in edges:
  if dominates(b,a,tin,tout):
   lp=natural_loop(a,b,preds);loop_headers.add(b);loop_size[b]=max(loop_size.get(b,0),len(lp));bout[a]+=1;bin_[b]+=1;back_rows.append({'function_entry':e,'from_block':a,'to_block':b,'edge_type':k,'natural_loop_blocks':len(lp),'header_scc':sid.get(b,'')})
 for n in nodes:
  if n not in depth:depth[n]=0
  block_rows.append({'function_entry':e,'block_address':n,'scc_id':sid.get(n,''),'scc_size':ssz.get(n,1),'cyclic_scc':str(cyc.get(n,False)).lower(),'irreducible_scc':str(irr_by.get(n,False)).lower(),'is_loop_header':str(n in loop_headers).lower(),'backedge_in':bin_[n],'backedge_out':bout[n],'idom':idom.get(n,''),'dom_depth':depth[n],'in_degree':len(preds.get(n,set())),'out_degree':len(adj.get(n,set()))})
 f=flow.get(e,{});cyclic=sum(1 for c in comps if len(c)>1 or any(n in adj.get(n,set()) for n in c));bes=sum(1 for r in back_rows if r['function_entry']==e);ds=list(depth.values())
 fn_rows.append({'entry':e,'name':f.get('name',''),'nodes':len(nodes),'edges':len(edges),'scc_count':len(comps),'cyclic_sccs':cyclic,'max_scc_size':max([len(c) for c in comps] or [0]),'back_edges':bes,'loop_headers':len(loop_headers),'max_natural_loop_blocks':max(loop_size.values()) if loop_size else 0,'irreducible_sccs':irreducible,'dominator_depth_max':max(ds or [0]),'dominator_depth_mean':f'{sum(ds)/max(1,len(ds)):.2f}','entry_dominates_pct':f'{100.0*len(reachable)/max(1,len(nodes)):.1f}','dispatcher_candidates':f.get('dispatcher_candidates','0'),'top_dispatcher_score':f.get('top_dispatcher_score','0'),'state_register':f.get('state_register',''),'state_compare_hits':f.get('state_compare_hits','0')})
write_csv('v55_cfg_function_metrics.csv',fn_rows,['entry','name','nodes','edges','scc_count','cyclic_sccs','max_scc_size','back_edges','loop_headers','max_natural_loop_blocks','irreducible_sccs','dominator_depth_max','dominator_depth_mean','entry_dominates_pct','dispatcher_candidates','top_dispatcher_score','state_register','state_compare_hits'])
write_csv('v55_cfg_blocks.csv',block_rows,['function_entry','block_address','scc_id','scc_size','cyclic_scc','irreducible_scc','is_loop_header','backedge_in','backedge_out','idom','dom_depth','in_degree','out_degree'])
write_csv('v55_cfg_back_edges.csv',back_rows,['function_entry','from_block','to_block','edge_type','natural_loop_blocks','header_scc'])
write_csv('v55_cfg_scc.csv',scc_rows,['function_entry','scc_id','size','cyclic','external_entry_nodes','irreducible','nodes'])
summary={'functions':len(fn_rows),'blocks':len(block_rows),'edges':sum(int(r['edges']) for r in fn_rows),'back_edges':len(back_rows),'cyclic_sccs':sum(int(r['cyclic_sccs']) for r in fn_rows),'irreducible_sccs':sum(int(r['irreducible_sccs']) for r in fn_rows)}
(root/'v55_cfg_report.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
(root/'v55_cfg_report.md').write_text('# V5.5 CFG intelligence\n\n'+''.join(f'- {k.replace("_"," ").title()}: **{v}**\n' for k,v in summary.items()),encoding='utf-8')
(human/'V55_CFG.html').write_text('<!doctype html><meta charset="utf-8"><h1>V5.5 CFG Intelligence</h1><p>See forensic CSV files for SCC, back-edge, loop, and dominator metrics.</p>',encoding='utf-8')
print(json.dumps(summary))
