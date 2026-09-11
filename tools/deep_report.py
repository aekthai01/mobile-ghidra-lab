#!/usr/bin/env python3
import csv
import json
import re
import sys
from collections import defaultdict, deque
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: deep_report.py <analysis-output-dir>')
root = Path(sys.argv[1])


def rows(name):
    p = root / name
    if not p.exists() or p.stat().st_size == 0:
        return []
    with p.open(encoding='utf-8', errors='replace', newline='') as f:
        return list(csv.DictReader(f))

functions = rows('functions.csv')
callgraph = rows('callgraph.csv')
string_xrefs = rows('string_xrefs.csv')

func_by_entry = {}
func_by_name = defaultdict(list)
for r in functions:
    entry = (r.get('entry') or '').strip()
    name = (r.get('name') or '').strip()
    if entry:
        func_by_entry[entry] = r
    if name:
        func_by_name[name].append(r)

callees = defaultdict(list)
callers = defaultdict(list)
for r in callgraph:
    ce = (r.get('caller_entry') or '').strip()
    te = (r.get('callee_entry') or '').strip()
    if ce:
        callees[ce].append(r)
    if te:
        callers[te].append(r)

CATS = {
    'jni': re.compile(r'(?i)(JNI_OnLoad|JNI_OnUnload|RegisterNatives|\bJNI\b|^Java_)'),
    'network_tls': re.compile(r'(?i)(SSL_|TLS|socket|connect|send|recv|http|https|curl|websocket|dns|certificate|x509)'),
    'crypto': re.compile(r'(?i)(AES|RSA|SHA\d*|MD5|HMAC|EVP_|cipher|encrypt|decrypt|crypto|PKCS)'),
    'hook_debug': re.compile(r'(?i)(xhook|hook|ptrace|frida|substrate|dlsym|dlopen|mprotect|mmap|debug|sigsegv)'),
    'audio': re.compile(r'(?i)(audio|voice|sound|pcm|opus|aac|aaudio|opensl|speaker|microphone|playback)'),
    'auth_license': re.compile(r'(?i)(auth|token|login|password|license|serial|credential|validation)'),
    'file_system': re.compile(r'(?i)(fopen|openat|readlink|unlink|rename|mkdir|opendir|readdir|lstat|stat64|/proc/|/data/|/sdcard/)'),
}

scores = defaultdict(int)
reasons = defaultdict(set)
category_scores = defaultdict(lambda: defaultdict(int))

seed_entries = set()
for e, f in func_by_entry.items():
    n = f.get('name', '')
    if re.search(r'(?i)(^Java_|JNI_OnLoad|JNI_OnUnload|RegisterNatives|Weave|gvraudio)', n):
        seed_entries.add(e)
        scores[e] += 5000
        reasons[e].add('seed:jni/app-name')

for e, f in func_by_entry.items():
    n = f.get('name', '')
    for cat, rx in CATS.items():
        if rx.search(n):
            category_scores[e][cat] += 1
            scores[e] += 25
            reasons[e].add('name:' + cat)

api_rows = []
for r in callgraph:
    caller = (r.get('caller_entry') or '').strip()
    callee_name = (r.get('callee_name') or '').strip()
    if not caller:
        continue
    for cat, rx in CATS.items():
        if rx.search(callee_name):
            category_scores[caller][cat] += 1
            if category_scores[caller][cat] <= 5:
                scores[caller] += 60
            reasons[caller].add('calls:' + cat)
            api_rows.append({
                'category': cat,
                'caller_entry': caller,
                'caller_name': r.get('caller_name', ''),
                'callsite': r.get('callsite', ''),
                'callee_entry': r.get('callee_entry', ''),
                'callee_name': callee_name,
                'reference_type': r.get('reference_type', ''),
            })

string_rows = []
for r in string_xrefs:
    fn = (r.get('from_function') or '').strip()
    value = r.get('value', '') or ''
    targets = func_by_name.get(fn, [])
    for cat, rx in CATS.items():
        if rx.search(value):
            for f in targets:
                e = f.get('entry', '')
                if e:
                    category_scores[e][cat] += 1
                    if category_scores[e][cat] <= 3:
                        scores[e] += 90
                    reasons[e].add('string:' + cat)
            string_rows.append({
                'category': cat,
                'function_name': fn,
                'from_address': r.get('from_address', ''),
                'string_address': r.get('string_address', ''),
                'reference_type': r.get('reference_type', ''),
                'value': value,
            })

neighbor_rows = []
seen_best = {}
q = deque((e, e, 0, 'seed') for e in sorted(seed_entries))
while q:
    seed, cur, depth, direction = q.popleft()
    key = (seed, cur, direction)
    if seen_best.get(key, 99) <= depth:
        continue
    seen_best[key] = depth
    f = func_by_entry.get(cur, {})
    neighbor_rows.append({
        'seed_entry': seed,
        'direction': direction,
        'depth': depth,
        'entry': cur,
        'name': f.get('name', ''),
    })
    if depth > 0:
        scores[cur] += {1: 1800, 2: 900, 3: 400}.get(depth, 0)
        reasons[cur].add(f'near-seed:{direction}:d{depth}')
    if depth >= 3:
        continue
    for edge in callees.get(cur, []):
        nxt = (edge.get('callee_entry') or '').strip()
        if nxt in func_by_entry:
            q.append((seed, nxt, depth + 1, 'callee'))
    for edge in callers.get(cur, []):
        nxt = (edge.get('caller_entry') or '').strip()
        if nxt in func_by_entry:
            q.append((seed, nxt, depth + 1, 'caller'))

for e, f in func_by_entry.items():
    try:
        size = int(f.get('size_bytes') or 0)
    except ValueError:
        size = 0
    if str(f.get('is_thunk', '')).lower() != 'true':
        scores[e] += min(80, size // 128)

ranked = sorted(func_by_entry, key=lambda e: (-scores[e], e))

with (root / 'function_rank.csv').open('w', encoding='utf-8', newline='') as f:
    fields = ['rank','score','entry','name','size_bytes','signature','categories','reasons']
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    for i, e in enumerate(ranked, 1):
        fr = func_by_entry[e]
        cats = ';'.join(f'{k}:{v}' for k,v in sorted(category_scores[e].items(), key=lambda kv:(-kv[1],kv[0])))
        w.writerow({
            'rank': i,
            'score': scores[e],
            'entry': e,
            'name': fr.get('name',''),
            'size_bytes': fr.get('size_bytes',''),
            'signature': fr.get('signature',''),
            'categories': cats,
            'reasons': ';'.join(sorted(reasons[e])),
        })

for filename, data, fields in [
    ('api_calls_by_function.csv', api_rows, ['category','caller_entry','caller_name','callsite','callee_entry','callee_name','reference_type']),
    ('categorized_string_xrefs.csv', string_rows, ['category','function_name','from_address','string_address','reference_type','value']),
    ('seed_neighborhood.csv', neighbor_rows, ['seed_entry','direction','depth','entry','name']),
]:
    with (root / filename).open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(data)

decomp = root / 'decompiled.c'
focus_dir = root / 'decompiled_focus'
focus_dir.mkdir(exist_ok=True)
blocks = {}
if decomp.exists():
    text = decomp.read_text(encoding='utf-8', errors='replace')
    marker = re.compile(r'(?ms)(/\* ={20,}\n \* ([0-9A-Fa-f]+)\s+([^\n]+)\n \* size=.*?\n \* ={20,} \*/\n.*?)(?=\n/\* ={20,}|\Z)')
    for m in marker.finditer(text):
        blocks[m.group(2).lower()] = m.group(1).strip() + '\n'

selected = [e for e in ranked if e.lower() in blocks][:300]
with (root / 'decompiled_focus.c').open('w', encoding='utf-8') as out:
    out.write('/* Top-ranked functions selected from the full Ghidra pseudocode output. */\n')
    for e in selected:
        out.write('\n' + blocks[e.lower()] + '\n')
        name = func_by_entry[e].get('name', 'function')
        safe = re.sub(r'[^A-Za-z0-9._-]+', '_', name)[:80] or 'function'
        (focus_dir / f'{e}_{safe}.c').write_text(blocks[e.lower()], encoding='utf-8')

by_cat = defaultdict(list)
for e in ranked:
    for cat, count in category_scores[e].items():
        if count:
            by_cat[cat].append(e)

with (root / 'deep_report.md').open('w', encoding='utf-8') as w:
    w.write('# Deep native analysis report\n\n')
    w.write('This report ranks functions using JNI proximity, call graph relationships, API calls, and referenced strings. ')
    w.write('Scores are heuristics for triage, not proof of behavior.\n\n')
    w.write(f'- Functions inventoried: **{len(functions)}**\n')
    w.write(f'- Call graph edges: **{len(callgraph)}**\n')
    w.write(f'- String xrefs: **{len(string_xrefs)}**\n')
    w.write(f'- Seed functions: **{len(seed_entries)}**\n')
    w.write(f'- Focus pseudocode snippets exported: **{len(selected)}**\n\n')

    w.write('## Seed functions\n\n')
    for e in sorted(seed_entries):
        f = func_by_entry.get(e, {})
        w.write(f'- `{e}` `{f.get("name", "")}`\n')
    w.write('\n')

    w.write('## Top 50 functions to inspect\n\n')
    w.write('| # | Score | Entry | Function | Why |\n|---:|---:|---|---|---|\n')
    for i, e in enumerate(ranked[:50], 1):
        f = func_by_entry[e]
        why = ', '.join(sorted(reasons[e]))[:180].replace('|','\\|')
        name = (f.get('name','') or '').replace('|','\\|')
        w.write(f'| {i} | {scores[e]} | `{e}` | `{name}` | {why} |\n')
    w.write('\n')

    w.write('## Category leaders\n\n')
    for cat in sorted(CATS):
        w.write(f'### {cat}\n\n')
        entries = sorted(by_cat.get(cat, []), key=lambda e: (-category_scores[e][cat], -scores[e], e))[:20]
        if not entries:
            w.write('_No classified functions._\n\n')
            continue
        w.write('| Hits | Score | Entry | Function |\n|---:|---:|---|---|\n')
        for e in entries:
            n = (func_by_entry[e].get('name','') or '').replace('|','\\|')
            w.write(f'| {category_scores[e][cat]} | {scores[e]} | `{e}` | `{n}` |\n')
        w.write('\n')

    w.write('## How to continue\n\n')
    w.write('1. Start with JNI/app-name seeds and `decompiled_focus.c`.\n')
    w.write('2. Use `seed_neighborhood.csv` to walk callers/callees up to depth 3.\n')
    w.write('3. Use `categorized_string_xrefs.csv` for behavior clues preserved in the stripped binary.\n')
    w.write('4. Use `api_calls_by_function.csv` to find callers of networking, crypto, hook/debug, audio, auth, and filesystem APIs.\n')
    w.write('5. Confirm important conclusions against `disassembly.txt`; decompiler pseudocode is reconstructed, not original source.\n')

manifest = {
    'functions': len(functions),
    'callgraph_edges': len(callgraph),
    'string_xrefs': len(string_xrefs),
    'seed_functions': len(seed_entries),
    'focus_pseudocode_snippets': len(selected),
    'categories': {cat: len(by_cat.get(cat, [])) for cat in sorted(CATS)},
}
(root / 'deep_report.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
print(json.dumps(manifest))
