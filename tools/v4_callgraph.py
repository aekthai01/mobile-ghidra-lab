#!/usr/bin/env python3
import csv
import html
import sys
from collections import defaultdict
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: v4_callgraph.py <analysis-output-dir>')

root = Path(sys.argv[1])


def rows(name):
    p = root / name
    if not p.exists() or p.stat().st_size == 0:
        return []
    with p.open(encoding='utf-8', errors='replace', newline='') as f:
        return list(csv.DictReader(f))

sel = rows('v4_selected_functions.csv')
calls = rows('callgraph.csv')
selected = {(r.get('entry') or '').strip().upper(): r for r in sel if (r.get('entry') or '').strip()}

# Cap the visualization. The CSV remains the authoritative full selected-edge list.
MAX_NODES = 180
MAX_EDGES = 420
ordered = sorted(selected.values(), key=lambda r: (-int(r.get('score') or 0), (r.get('entry') or '')))
kept = {(r.get('entry') or '').strip().upper(): r for r in ordered[:MAX_NODES]}

edges = []
for e in calls:
    a = (e.get('caller_entry') or '').strip().upper()
    b = (e.get('callee_entry') or '').strip().upper()
    if a in kept and b in kept:
        edges.append((a, b))
        if len(edges) >= MAX_EDGES:
            break

with (root / 'v4_selected_callgraph.csv').open('w', encoding='utf-8', newline='') as f:
    w = csv.writer(f)
    w.writerow(['caller_entry','callee_entry'])
    w.writerows(edges)

with (root / 'v4_selected_callgraph.dot').open('w', encoding='utf-8') as w:
    w.write('digraph selected_callgraph {\n')
    w.write('  graph [rankdir=LR, overlap=false, splines=true];\n')
    w.write('  node [shape=box, fontsize=9];\n')
    for entry, r in kept.items():
        name = (r.get('name') or entry).replace('"', '\\"')
        mode = r.get('recommended_mode') or ''
        score = r.get('score') or ''
        label = f'{name}\\n0x{entry}\\n{mode} score={score}'
        w.write(f'  n{entry} [label="{label}"];\n')
    for a, b in edges:
        w.write(f'  n{a} -> n{b};\n')
    w.write('}\n')

with (root / 'v4_graph_report.md').open('w', encoding='utf-8') as w:
    w.write('# V4 bounded call graph\n\n')
    w.write(f'- Selected functions available: **{len(selected)}**\n')
    w.write(f'- Nodes rendered: **{len(kept)}** (cap {MAX_NODES})\n')
    w.write(f'- Edges rendered: **{len(edges)}** (cap {MAX_EDGES})\n\n')
    w.write('The graph is deliberately capped. V3 attempted to feed giant CFGs to Graphviz and could spend the rest of the workflow contemplating its life choices. Full call evidence remains in `callgraph.csv` and `v4_selected_callgraph.csv`.\n')

print({'nodes': len(kept), 'edges': len(edges)})
