#!/usr/bin/env python3
import csv,re,sys
from pathlib import Path
root=Path(sys.argv[1])
def rows(n):
 p=root/n
 if not p.exists() or not p.stat().st_size:return []
 with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))
base=rows('v51_high_pcode_indirect_slices.csv');ind=rows('v5_indirect_branches.csv')
meta={(r.get('function_entry','').upper(),r.get('branch_address','').upper()):r for r in ind}
out=[]
for r in base:
 x=dict(r);v=r.get('target_high_varnode','');m=re.search(r',\s*(\d+)\)$',v);size=int(m.group(1)) if m else 0
 k=(r.get('function_entry','').upper(),r.get('branch_address','').upper());pat=meta.get(k,{}).get('pattern','')
 role='branch_target_expression'
 if size and size<=4:role='selector_or_switch_index'
 if pat=='relative32' and size and size<=4:role='selector_for_relative_jump_table'
 x['varnode_size_bytes']=size;x['expression_role']=role;x['indirect_pattern']=pat;x['table_address']=meta.get(k,{}).get('table_address','');out.append(x)
fields=list(out[0].keys()) if out else ['function_entry']
with (root/'v52_indirect_expression_roles.csv').open('w',encoding='utf-8',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(out)
with (root/'v52_indirect_expression_roles.md').open('w',encoding='utf-8') as w:
 w.write('# V5.2 indirect-expression roles\n\nHigh P-code `BRANCHIND` inputs are labeled conservatively. A 32-bit value on an ARM64 indirect branch is treated as a selector/index candidate, not automatically as the final 64-bit branch address.\n\n')
 for role in ('selector_for_relative_jump_table','selector_or_switch_index','branch_target_expression'):
  w.write(f'- {role}: **{sum(r.get("expression_role")==role for r in out)}**\n')
print('indirect expression roles',len(out))
