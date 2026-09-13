#!/usr/bin/env python3
import csv,sys
from pathlib import Path
root=Path(sys.argv[1])
p=root/'v51_function_metrics.csv'
rows=list(csv.DictReader(p.open(encoding='utf-8',newline='')))
for r in rows:
    def n(k):
        try:return int(float(r.get(k) or 0))
        except:return 0
    signals=sum((n('indirect_jumps')>=5,n('state_compare_hits')>=80,n('conditional_branches')>=160,n('estimated_blocks')>=280,n('size_bytes')>=12000,n('instruction_count')>=3500))
    score=n('indirect_jumps')*900+n('state_compare_hits')*20+n('conditional_branches')*8+min(8000,n('size_bytes')//32)
    r['complexity_priority_score']=score
    r['complexity_signal_count']=signals
    r['complexity_priority']='high' if signals>=3 else ('medium' if signals>=2 else 'normal')
fields=list(rows[0].keys())
with (root/'priority_metrics.csv').open('w',encoding='utf-8',newline='') as f:
    w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
print('priority metrics:',len(rows))
