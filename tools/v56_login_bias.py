#!/usr/bin/env python3
import csv, json, sys
from collections import defaultdict, deque
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: v56_login_bias.py <analysis-output-dir>')
root = Path(sys.argv[1])

def rows(name):
    p = root / name
    if not p.exists() or not p.stat().st_size:
        return []
    with p.open(encoding='utf-8', errors='replace', newline='') as f:
        return list(csv.DictReader(f))

def canon(v):
    v = (v or '').strip()
    if v.lower().startswith('0x'):
        v = v[2:]
    try:
        return f'{int(v, 16):08X}'
    except Exception:
        return v.upper()

def as_int(v):
    try:
        return int(float(v or 0))
    except Exception:
        return 0

metrics = rows('priority_metrics.csv')
if not metrics:
    raise SystemExit('priority_metrics.csv missing')
by_entry = {canon(r.get('entry')): r for r in metrics if canon(r.get('entry'))}

seed_rows = rows('v56_login_seeds.csv')
immediate = {canon(r.get('function_entry')) for r in seed_rows if r.get('kind') == 'imm_0x2712' and canon(r.get('function_entry')) in by_entry}
https_refs = {canon(r.get('function_entry')) for r in seed_rows if r.get('kind') == 'https_xref' and canon(r.get('function_entry')) in by_entry}

# 0x2712 is the requested primary entry point. If absent, normal ranking is preserved.
active = bool(immediate)
callees, callers = defaultdict(set), defaultdict(set)
for r in rows('callgraph.csv'):
    a, b = canon(r.get('caller_entry')), canon(r.get('callee_entry'))
    if a in by_entry and b in by_entry:
        callees[a].add(b)
        callers[b].add(a)

def bfs(starts, graph, max_depth):
    dist = {}
    q = deque((s, 0) for s in starts)
    while q:
        e, d = q.popleft()
        if e in dist and dist[e] <= d:
            continue
        dist[e] = d
        if d >= max_depth:
            continue
        for n in graph.get(e, ()):
            q.append((n, d + 1))
    return dist

forward = bfs(immediate, callees, 4) if active else {}
reverse = bfs(immediate, callers, 3) if active else {}
strong = immediate & https_refs
boost_by_distance = {0: 120000, 1: 50000, 2: 22000, 3: 9000, 4: 3500}
for e, r in by_entry.items():
    evidence = []
    dist_candidates = []
    if active and e in immediate:
        evidence.append('imm:0x2712')
        dist_candidates.append(0)
    if active and e in https_refs:
        evidence.append('https')
    if active and e in forward:
        evidence.append(f'callee-distance:{forward[e]}')
        dist_candidates.append(forward[e])
    if active and e in reverse:
        evidence.append(f'caller-distance:{reverse[e]}')
        dist_candidates.append(reverse[e] + 1)

    d = min(dist_candidates) if dist_candidates else None
    boost = boost_by_distance.get(d, 0) if d is not None else 0
    if e in strong:
        boost += 60000
        evidence.append('strong:0x2712+https')
    elif e in https_refs and d is not None and d <= 1:
        boost += 25000
        evidence.append('network-context')

    if boost:
        r['v51_score'] = as_int(r.get('v51_score')) + boost
        if e in immediate:
            r['v51_priority_tier'] = 'A-seed'
        elif d is not None and d <= 1:
            r['v51_priority_tier'] = 'A-forward'
        elif d is not None and d <= 2:
            r['v51_priority_tier'] = 'B-forward'
        old = [x for x in (r.get('v51_reasons') or '').split(';') if x]
        old.extend(x for x in evidence if x not in old)
        r['v51_reasons'] = ';'.join(old)
    r['v56_login_priority'] = 'strong' if e in strong else ('seed' if e in immediate else ('context' if boost else ''))
    r['v56_login_distance'] = '' if d is None else str(d)
    r['v56_login_boost'] = str(boost)
    r['v56_login_evidence'] = ';'.join(evidence)

fields = list(metrics[0].keys())
for extra in ('v56_login_priority','v56_login_distance','v56_login_boost','v56_login_evidence'):
    if extra not in fields:
        fields.append(extra)
with (root / 'priority_metrics.csv').open('w', encoding='utf-8', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader(); w.writerows(metrics)

report = {
    'active': active,
    'imm_0x2712_functions': sorted(immediate),
    'https_functions': sorted(https_refs),
    'strong_functions': sorted(strong),
    'forward_reachable': len(forward),
    'reverse_reachable': len(reverse),
}
(root / 'v56_login_priority.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
with (root / 'v56_login_priority.md').open('w', encoding='utf-8') as w:
    w.write('# V5.6 login/network priority\n\n')
    if not active:
        w.write('No `0x2712` immediate was recovered, so normal ranking is preserved.\n')
    else:
        w.write('`0x2712` is the requested primary seed. HTTPS evidence strengthens a seed but is not treated as proof of login by itself.\n\n')
        w.write(f'- 0x2712 seed functions: **{len(immediate)}**\n')
        w.write(f'- HTTPS-referencing functions: **{len(https_refs)}**\n')
        w.write(f'- Strong 0x2712 + HTTPS functions: **{len(strong)}**\n')
        w.write(f'- Forward context functions: **{len(forward)}**\n')
        w.write(f'- Reverse caller context functions: **{len(reverse)}**\n\n')
        w.write('| Entry | Priority | Boost | Distance | Evidence |\n|---|---|---:|---:|---|\n')
        ranked = sorted((r for r in metrics if as_int(r.get('v56_login_boost')) > 0), key=lambda r: -as_int(r.get('v56_login_boost')))
        for r in ranked[:120]:
            w.write(f"| `0x{canon(r.get('entry'))}` | {r.get('v56_login_priority','')} | {r.get('v56_login_boost','0')} | {r.get('v56_login_distance','')} | {r.get('v56_login_evidence','')} |\n")
print(json.dumps(report))
