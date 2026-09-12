#!/usr/bin/env python3
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: v5_ai_context.py <analysis-output-dir>')
root = Path(sys.argv[1])


def rows(name):
    p = root / name
    if not p.exists() or p.stat().st_size == 0:
        return []
    with p.open(encoding='utf-8', errors='replace', newline='') as f:
        return list(csv.DictReader(f))


def canon(x):
    try:
        return f'{int((x or "").strip(), 16):08X}'
    except Exception:
        return (x or '').strip().upper()


selected = rows('v4_selected_functions.csv') or rows('v5_selected_functions.csv')
flow = rows('v5_function_flow.csv')
indirect = rows('v5_indirect_branches.csv')
states = rows('v5_state_values.csv')
call = rows('callgraph.csv')
strings = rows('string_xrefs.csv')
flow_by = {canon(r.get('entry')): r for r in flow}
ind_by = defaultdict(list)
for r in indirect:
    ind_by[canon(r.get('function_entry'))].append(r)
st_by = defaultdict(list)
for r in states:
    st_by[canon(r.get('function_entry'))].append(r)
callers = defaultdict(list)
callees = defaultdict(list)
for r in call:
    a = canon(r.get('caller_entry'))
    b = canon(r.get('callee_entry'))
    if a and b:
        callees[a].append((b, r.get('callee_name', ''), r.get('callsite', '')))
        callers[b].append((a, r.get('caller_name', ''), r.get('callsite', '')))
str_by = defaultdict(list)
name_to_entries = defaultdict(list)
for r in selected:
    name_to_entries[r.get('name', '')].append(canon(r.get('entry')))
for r in strings:
    for e in name_to_entries.get(r.get('from_function', ''), []):
        v = (r.get('value') or '').strip()
        if v and v not in str_by[e]:
            str_by[e].append(v)

cards = root / 'ai_context' / 'function_cards'
cards.mkdir(parents=True, exist_ok=True)
summary = []
for rank, r in enumerate(selected[:80], 1):
    e = canon(r.get('entry'))
    f = flow_by.get(e, {})
    inds = ind_by.get(e, [])
    sts = st_by.get(e, [])
    card = cards / f'{rank:03d}_{e}.md'
    with card.open('w', encoding='utf-8') as w:
        w.write(f'# {rank}. {r.get("name") or "sub_" + e}\n\n')
        w.write(f'- Entry: `0x{e}`\n- Mode: `{r.get("recommended_mode", "")}`\n- Score: **{r.get("score", "")}**\n- Size: **{r.get("size_bytes", "")} bytes**\n')
        if f:
            w.write(f'- Basic blocks: **{f.get("basic_blocks", "")}**\n- Indirect branches: **{f.get("indirect_branches", "")}**\n- Resolved indirect edges: **{f.get("resolved_indirect_edges", "")}**\n- Dispatcher score: **{f.get("top_dispatcher_score", "")}**\n- State register: `{f.get("state_register", "")}` ({f.get("state_compare_hits", "")} compares)\n')
        w.write(f'- Reasons: `{r.get("reasons", "")}`\n\n')
        w.write('## Callers\n\n')
        for ce, cn, site in callers.get(e, [])[:20]:
            w.write(f'- `0x{ce}` `{cn}` at `0x{site}`\n')
        if not callers.get(e):
            w.write('- none recovered\n')
        w.write('\n## Callees\n\n')
        for ce, cn, site in callees.get(e, [])[:30]:
            w.write(f'- `0x{ce}` `{cn}` from `0x{site}`\n')
        if not callees.get(e):
            w.write('- none recovered\n')
        if inds:
            w.write('\n## Indirect control flow\n\n')
            for x in inds[:20]:
                w.write(f'- `0x{x.get("branch_address")}` {x.get("pattern")} table=`0x{x.get("table_address")}` index={x.get("index_register")} max={x.get("max_index")} resolved={x.get("resolved_targets")}\n')
        if sts:
            w.write('\n## State/constant comparisons\n\n')
            for x in sts[:30]:
                w.write(f'- `0x{x.get("compare_address")}` {x.get("register")} vs `{x.get("constant")}` {x.get("condition")} -> `{x.get("true_target")}` / `{x.get("false_target")}`\n')
        if str_by.get(e):
            w.write('\n## Referenced strings\n\n')
            for s in str_by[e][:25]:
                w.write(f'- `{s[:240]}`\n')
        w.write('\n## Suggested next evidence\n\n')
        if r.get('recommended_mode') == 'region':
            w.write(f'- Open `v5_slices/{e}/` first, then correlate with `v5_jump_tables.csv` and `v5_clean_edges.csv`.\n')
        else:
            w.write('- Open the matching file under `v4_selected_ida/` and `v4_decompiled_selected/`, then correlate with callers/callees above.\n')
    summary.append({'rank': rank, 'entry': e, 'name': r.get('name', ''), 'mode': r.get('recommended_mode', ''), 'score': r.get('score', ''), 'card': str(card.relative_to(root))})

with (root / 'ai_context' / 'overview.md').open('w', encoding='utf-8') as w:
    w.write('# Mobile Ghidra Lab V5 AI context\n\n')
    w.write('Read this file first. The function cards intentionally contain bounded evidence so a phone AI client does not need to ingest the full artifact.\n\n')
    w.write('| # | Score | Entry | Mode | Function | Card |\n|---:|---:|---|---|---|---|\n')
    for r in summary[:50]:
        w.write(f"| {r['rank']} | {r['score']} | `0x{r['entry']}` | {r['mode']} | `{r['name']}` | `{r['card']}` |\n")
    w.write('\nFor giant functions, prioritize V5 semantic slices and resolved jump tables over whole-function pseudocode. Ghidra-generated names such as `FUN_...` are identifiers, not recovered original names.\n')
(root / 'ai_context' / 'index.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
print(json.dumps({'cards': len(summary), 'overview': 'ai_context/overview.md'}))
