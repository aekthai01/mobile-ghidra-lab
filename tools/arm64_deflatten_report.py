#!/usr/bin/env python3
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: arm64_deflatten_report.py <analysis-output-dir>')

root = Path(sys.argv[1])
asm_dir = root / 'ida_like_functions'
if not asm_dir.is_dir():
    print('ida_like_functions/ missing; skipping de-flatten report')
    raise SystemExit(0)


def rows(name):
    p = root / name
    if not p.exists() or p.stat().st_size == 0:
        return []
    with p.open(encoding='utf-8', errors='replace', newline='') as f:
        return list(csv.DictReader(f))


def canon(value):
    value = (value or '').strip()
    if not value:
        return ''
    try:
        return f'{int(value, 16):08X}'
    except ValueError:
        return value.upper()


priority_rows = rows('analysis_priority.csv')
suspicious_rows = rows('arm64_suspicious_functions.csv')
priority = {canon(r.get('entry')): r for r in priority_rows if canon(r.get('entry'))}
suspicious = {canon(r.get('entry')): r for r in suspicious_rows if canon(r.get('entry'))}

INS_RE = re.compile(
    r'^\.text:([0-9A-Fa-f]{16})\s+'
    r'((?:[0-9A-Fa-f]{2}\s+){3}[0-9A-Fa-f]{2})\s+'
    r'([A-Za-z0-9_.]+)\s*(.*?)(?:\s+;.*)?$'
)
FUNC_RE = re.compile(r'^; FUNCTION\s+(.+)$')
START_RE = re.compile(r'^; start=([0-9A-Fa-f]+)\s+size=0x([0-9A-Fa-f]+)')
TARGET_RE = re.compile(r'\b(?:loc|sub)_([0-9A-Fa-f]+)\b')
REG_RE = re.compile(r'\b([WX][0-9]{1,2})\b', re.I)
IMM_RE = re.compile(r'#(?:0x([0-9a-fA-F]+)|([0-9]+))')

COND = {'CBZ', 'CBNZ', 'TBZ', 'TBNZ'}
INDIRECT_JUMPS = {'BR', 'BRAA', 'BRAB', 'BRAAZ', 'BRABZ'}
CALLS = {'BL', 'BLR', 'BLRAA', 'BLRAB', 'BLRAAZ', 'BLRABZ'}
TERMINAL = {'RET', 'ERET', 'BRK', 'HLT'}
CMPISH = {'CMP', 'CMN', 'TST', 'CCMP', 'CCMN'}
WRITEISH = {'STR','STRB','STRH','STP','STUR','STXR','STLXR','STLR','STLRB','STLRH'}
LOADISH = {'LDR','LDRB','LDRH','LDP','LDUR','LDXR','LDAXR','LDAR','LDARB','LDARH'}
CONSTISH = {'MOV','MOVZ','MOVN','MOVK','ADR','ADRP'}


def sanitize(s):
    return re.sub(r'[^A-Za-z0-9._-]+', '_', s)[:80] or 'function'


def is_cond(m):
    return m in COND or m.startswith('B.')


def direct_target(ops):
    m = TARGET_RE.search(ops)
    return int(m.group(1), 16) if m else None


def parse_function(path, header_only=False):
    name = path.stem
    start = None
    size = None
    ins = []
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
        m = FUNC_RE.match(line)
        if m:
            name = m.group(1).strip()
            continue
        m = START_RE.match(line)
        if m:
            start = int(m.group(1), 16)
            size = int(m.group(2), 16)
            if header_only:
                return {'name': name, 'start': start, 'size': size, 'ins': [], 'path': path}
            continue
        if header_only:
            continue
        m = INS_RE.match(line)
        if m:
            ins.append({
                'addr': int(m.group(1), 16),
                'bytes': m.group(2),
                'mnem': m.group(3).upper(),
                'ops': m.group(4).strip(),
                'line': line,
            })
    if start is None:
        m = re.match(r'([0-9A-Fa-f]+)_', path.name)
        if m:
            start = int(m.group(1), 16)
    if header_only:
        return None if start is None else {'name': name, 'start': start, 'size': size or 0, 'ins': [], 'path': path}
    if not ins:
        return None
    if start is None:
        start = ins[0]['addr']
    if size is None:
        size = ins[-1]['addr'] - start + 4
    return {'name': name, 'start': start, 'size': size, 'ins': ins, 'path': path}


def build_cfg(fn):
    ins = fn['ins']
    addr_set = {i['addr'] for i in ins}
    starts = {ins[0]['addr']}
    for idx, item in enumerate(ins):
        target = direct_target(item['ops'])
        if target in addr_set and (is_cond(item['mnem']) or item['mnem'] == 'B'):
            starts.add(target)
        if (is_cond(item['mnem']) or item['mnem'] == 'B' or item['mnem'] in INDIRECT_JUMPS or item['mnem'] in TERMINAL) and idx + 1 < len(ins):
            starts.add(ins[idx + 1]['addr'])
    starts = sorted(starts)
    start_set = set(starts)
    blocks, cur = [], []
    for item in ins:
        if cur and item['addr'] in start_set:
            blocks.append(cur)
            cur = []
        cur.append(item)
    if cur:
        blocks.append(cur)
    block_by = {b[0]['addr']: b for b in blocks}
    ordered = sorted(block_by)
    next_block = {s: ordered[i + 1] if i + 1 < len(ordered) else None for i, s in enumerate(ordered)}
    edges = []
    for block in blocks:
        s = block[0]['addr']
        last = block[-1]
        m = last['mnem']
        target = direct_target(last['ops'])
        if is_cond(m):
            if target in block_by:
                edges.append((s, target, 'branch'))
            ft = next_block[s]
            if ft is not None:
                edges.append((s, ft, 'fallthrough'))
        elif m == 'B':
            if target in block_by:
                edges.append((s, target, 'branch'))
        elif m in INDIRECT_JUMPS or m in TERMINAL:
            pass
        else:
            ft = next_block[s]
            if ft is not None:
                edges.append((s, ft, 'fallthrough'))
    succ = defaultdict(list)
    pred = defaultdict(list)
    for a, b, k in edges:
        succ[a].append((b, k))
        pred[b].append((a, k))
    return blocks, block_by, edges, succ, pred


def tarjan(nodes, succ):
    index = 0
    stack = []
    onstack = set()
    idx = {}
    low = {}
    comps = []
    sys.setrecursionlimit(max(10000, len(nodes) * 3 + 100))

    def visit(v):
        nonlocal index
        idx[v] = index
        low[v] = index
        index += 1
        stack.append(v)
        onstack.add(v)
        for w, _ in succ.get(v, []):
            if w not in idx:
                visit(w)
                low[v] = min(low[v], low[w])
            elif w in onstack:
                low[v] = min(low[v], idx[w])
        if low[v] == idx[v]:
            comp = []
            while True:
                w = stack.pop()
                onstack.remove(w)
                comp.append(w)
                if w == v:
                    break
            comps.append(comp)

    for n in nodes:
        if n not in idx:
            visit(n)
    return comps


def block_features(block, pred, succ):
    start = block[0]['addr']
    mnems = [i['mnem'] for i in block]
    regs_cmp = []
    compare_count = 0
    for i in block:
        regs = REG_RE.findall(i['ops'])
        if i['mnem'] in CMPISH or i['mnem'] in {'CBZ','CBNZ','TBZ','TBNZ'}:
            compare_count += 1
            if regs:
                regs_cmp.append(regs[0].upper().replace('X', 'W'))
    calls = sum(1 for m in mnems if m in CALLS)
    stores = sum(1 for m in mnems if m in WRITEISH)
    loads = sum(1 for m in mnems if m in LOADISH)
    indirect = sum(1 for m in mnems if m in INDIRECT_JUMPS)
    indeg = len(pred.get(start, []))
    outdeg = len(succ.get(start, []))
    backpred = sum(1 for p, _ in pred.get(start, []) if p >= start)
    tiny = len(block) <= 4 and calls == 0 and stores == 0
    trampoline = tiny and outdeg == 1 and (mnems[-1] == 'B' or len(block) <= 2)
    return {
        'start': start,
        'instructions': len(block),
        'indegree': indeg,
        'outdegree': outdeg,
        'back_predecessors': backpred,
        'compare_count': compare_count,
        'compare_regs': regs_cmp,
        'calls': calls,
        'stores': stores,
        'loads': loads,
        'indirect_jumps': indirect,
        'trampoline': trampoline,
    }


def collapse_target(node, features, succ, seen=None):
    if seen is None:
        seen = set()
    if node in seen:
        return node
    seen.add(node)
    feat = features.get(node)
    outs = succ.get(node, [])
    if feat and feat['trampoline'] and len(outs) == 1:
        return collapse_target(outs[0][0], features, succ, seen)
    return node


def infer_indirect_context(block, idx):
    item = block[idx]
    regs = REG_RE.findall(item['ops'])
    target_reg = regs[0].upper() if regs else ''
    window = block[max(0, idx - 12):idx + 1]
    labels = []
    constants = []
    for ins in window:
        for m in TARGET_RE.finditer(ins['ops']):
            labels.append('0x' + canon(m.group(1)))
        if target_reg and target_reg in ins['ops'].upper() and ins['mnem'] in CONSTISH:
            imm = IMM_RE.search(ins['ops'])
            if imm:
                constants.append(imm.group(0))
    return target_reg, list(dict.fromkeys(labels)), constants, '\n'.join(x['line'] for x in window)


# Build candidate list from the function header itself rather than from the filename. Ghidra's
# exporter intentionally uses IDA-like short addresses in file names (e.g. 1D7440), while CSV
# tables use Ghidra's padded address strings (001d7440). Normalizing the parsed start address
# prevents leading-zero mismatches and is architecture-safe for the current 32-bit image offsets.
candidates = []
for path in asm_dir.glob('*.asm'):
    hdr = parse_function(path, header_only=True)
    if not hdr:
        continue
    entry = f'{hdr["start"]:08X}'
    pr = priority.get(entry, {})
    sus = suspicious.get(entry, {})
    try:
        sus_score = int(sus.get('suspicion_score') or 0)
    except ValueError:
        sus_score = 0
    try:
        pr_score = int(pr.get('analysis_priority') or 0)
    except ValueError:
        pr_score = 0
    third = (pr.get('is_third_party') or '').lower() == 'true'
    try:
        dist = int(pr.get('app_seed_distance')) if pr.get('app_seed_distance') not in (None, '') else 99
    except ValueError:
        dist = 99
    include = sus_score >= 20 or pr_score >= 1200 or dist <= 2
    if third and dist > 2 and sus_score < 60:
        include = False
    if include:
        weight = sus_score * 100 + max(0, pr_score)
        candidates.append((-weight, path, entry))

candidates.sort(key=lambda x: (x[0], x[2], x[1].name))
candidates = candidates[:140]

# If the obstruction report found suspicious functions but normalization somehow produced no
# candidates, fail loudly. A successful empty report is worse than a red CI light because it lies.
if suspicious_rows and not candidates:
    raise SystemExit('ARM64 suspicious functions exist but de-flatten candidate selection returned zero; address normalization/filtering is broken')

candidate_rows = []
indirect_rows = []
clean_edge_rows = []
report_dir = root / 'arm64_deflatten'
dot_dir = root / 'arm64_deflatten_dot'
report_dir.mkdir(exist_ok=True)
dot_dir.mkdir(exist_ok=True)

for _, path, expected_entry in candidates:
    fn = parse_function(path)
    if not fn:
        continue
    entry_key = f'{fn["start"]:08X}'
    blocks, block_by, edges, succ, pred = build_cfg(fn)
    nodes = sorted(block_by)
    comps = tarjan(nodes, succ)
    scc_size = {}
    for comp in comps:
        for n in comp:
            scc_size[n] = len(comp)
    features = {b[0]['addr']: block_features(b, pred, succ) for b in blocks}

    state_regs = Counter()
    dispatcher_scored = []
    for start, feat in features.items():
        for r in feat['compare_regs']:
            state_regs[r] += 1
        score = feat['indegree'] * 3 + feat['back_predecessors'] * 5 + feat['compare_count'] * 4
        if scc_size.get(start, 1) >= 6:
            score += min(30, scc_size[start] // 2)
        if feat['indirect_jumps']:
            score += 18
        if feat['outdegree'] >= 2:
            score += 5
        if feat['trampoline']:
            score -= 8
        dispatcher_scored.append((score, start))
    dispatcher_scored.sort(reverse=True)
    dispatchers = [(s, n) for s, n in dispatcher_scored if s >= 12][:12]
    top_state = state_regs.most_common(6)

    semantic_nodes = [n for n in nodes if not features[n]['trampoline']]
    clean_edges = set()
    for src in semantic_nodes:
        for dst, kind in succ.get(src, []):
            final = collapse_target(dst, features, succ)
            if final != src:
                clean_edges.add((src, final, kind))
                clean_edge_rows.append({
                    'function_entry': entry_key,
                    'function_name': fn['name'],
                    'from_block': f'{src:08X}',
                    'to_block': f'{final:08X}',
                    'kind': kind,
                    'collapsed_trampolines': str(final != dst).lower(),
                })

    function_indirect = []
    for block in blocks:
        for idx, item in enumerate(block):
            if item['mnem'] in INDIRECT_JUMPS:
                reg, labels, constants, context = infer_indirect_context(block, idx)
                row = {
                    'function_entry': entry_key,
                    'function_name': fn['name'],
                    'branch_address': f'{item["addr"]:08X}',
                    'mnemonic': item['mnem'],
                    'target_register': reg,
                    'nearby_symbolic_targets': ';'.join(labels),
                    'nearby_immediates': ';'.join(constants),
                    'context': context.replace('\n', '\\n'),
                }
                indirect_rows.append(row)
                function_indirect.append(row)

    max_scc = max((len(c) for c in comps), default=0)
    try:
        sus_score = int(suspicious.get(entry_key, {}).get('suspicion_score') or 0)
    except ValueError:
        sus_score = 0
    pr = priority.get(entry_key, {})
    candidate_rows.append({
        'entry': entry_key,
        'name': fn['name'],
        'size_bytes': fn['size'],
        'basic_blocks': len(blocks),
        'direct_edges': len(edges),
        'largest_scc': max_scc,
        'dispatcher_candidates': len(dispatchers),
        'top_dispatcher': f'{dispatchers[0][1]:08X}' if dispatchers else '',
        'top_dispatcher_score': dispatchers[0][0] if dispatchers else 0,
        'state_register_candidates': ';'.join(f'{r}:{c}' for r, c in top_state),
        'indirect_branches': len(function_indirect),
        'suspicion_score': sus_score,
        'analysis_priority': pr.get('analysis_priority', ''),
        'third_party_family': pr.get('third_party_family', ''),
    })

    out = report_dir / f'{entry_key}_{sanitize(fn["name"])}.md'
    with out.open('w', encoding='utf-8') as w:
        w.write(f'# ARM64 de-flatten triage: `{fn["name"]}`\n\n')
        w.write(f'- Entry: `0x{fn["start"]:X}`\n- Size: **{fn["size"]}** bytes\n')
        w.write(f'- Basic blocks: **{len(blocks)}**\n- Direct CFG edges: **{len(edges)}**\n')
        w.write(f'- Largest strongly-connected component: **{max_scc}** blocks\n')
        w.write(f'- Indirect branches: **{len(function_indirect)}**\n')
        w.write('\nThese are reconstruction hints, not proof that flattening is present.\n\n')
        w.write('## Dispatcher candidates\n\n| Score | Block | In | Out | Back preds | Compares | SCC |\n|---:|---|---:|---:|---:|---:|---:|\n')
        for score, start in dispatchers:
            feat = features[start]
            w.write(f'| {score} | `loc_{start:X}` | {feat["indegree"]} | {feat["outdegree"]} | {feat["back_predecessors"]} | {feat["compare_count"]} | {scc_size.get(start, 1)} |\n')
        w.write('\n## State-register candidates\n\n')
        if top_state:
            for reg, count in top_state:
                w.write(f'- `{reg}` compared/tested **{count}** times\n')
        else:
            w.write('- No dominant compared register found.\n')
        w.write('\n## Likely semantic blocks\n\n')
        sem = sorted(
            (features[n] for n in semantic_nodes),
            key=lambda x: (-(x['calls'] * 8 + x['stores'] * 3 + x['compare_count'] * 2 + x['instructions'] // 8), x['start'])
        )[:80]
        w.write('| Block | Insns | Calls | Stores | Compares | In | Out |\n|---|---:|---:|---:|---:|---:|---:|\n')
        for feat in sem:
            w.write(f'| `loc_{feat["start"]:X}` | {feat["instructions"]} | {feat["calls"]} | {feat["stores"]} | {feat["compare_count"]} | {feat["indegree"]} | {feat["outdegree"]} |\n')
        if function_indirect:
            w.write('\n## Indirect branch contexts\n\n')
            for row in function_indirect[:20]:
                w.write(f'### `0x{row["branch_address"]}` → `{row["target_register"]}`\n\n')
                if row['nearby_symbolic_targets']:
                    w.write(f'- Nearby symbolic targets: `{row["nearby_symbolic_targets"]}`\n')
                w.write('\n```asm\n' + row['context'].replace('\\n', '\n') + '\n```\n\n')

    dot = dot_dir / f'{entry_key}_{sanitize(fn["name"])}.dot'
    with dot.open('w', encoding='utf-8') as w:
        w.write('digraph cfg {\n  graph [rankdir=TB, overlap=false];\n  node [shape=box, fontsize=9];\n')
        dispatcher_nodes = {n for _, n in dispatchers[:4]}
        for n in semantic_nodes:
            feat = features[n]
            attrs = []
            if n in dispatcher_nodes:
                attrs.append('penwidth=3')
            label = f'loc_{n:X}\\nins={feat["instructions"]} calls={feat["calls"]} stores={feat["stores"]}'
            attrs.append('label="' + label + '"')
            w.write(f'  n{n:X} [{", ".join(attrs)}];\n')
        for a, b, k in sorted(clean_edges):
            w.write(f'  n{a:X} -> n{b:X} [label="{k}", fontsize=8];\n')
        w.write('}\n')

candidate_rows.sort(key=lambda r: (-int(r['suspicion_score']), -int(r['top_dispatcher_score']), -int(r['size_bytes'])))

candidate_fields = [
    'entry','name','size_bytes','basic_blocks','direct_edges','largest_scc','dispatcher_candidates',
    'top_dispatcher','top_dispatcher_score','state_register_candidates','indirect_branches',
    'suspicion_score','analysis_priority','third_party_family'
]
with (root / 'arm64_deflatten_candidates.csv').open('w', encoding='utf-8', newline='') as f:
    w = csv.DictWriter(f, fieldnames=candidate_fields)
    w.writeheader()
    w.writerows(candidate_rows)

indirect_fields = [
    'function_entry','function_name','branch_address','mnemonic','target_register',
    'nearby_symbolic_targets','nearby_immediates','context'
]
with (root / 'arm64_indirect_branches.csv').open('w', encoding='utf-8', newline='') as f:
    w = csv.DictWriter(f, fieldnames=indirect_fields)
    w.writeheader()
    w.writerows(indirect_rows)

edge_fields = ['function_entry','function_name','from_block','to_block','kind','collapsed_trampolines']
with (root / 'arm64_clean_cfg_edges.csv').open('w', encoding='utf-8', newline='') as f:
    w = csv.DictWriter(f, fieldnames=edge_fields)
    w.writeheader()
    w.writerows(clean_edge_rows)

summary = {
    'functions_triaged': len(candidate_rows),
    'functions_with_dispatcher_candidates': sum(1 for r in candidate_rows if int(r['dispatcher_candidates']) > 0),
    'indirect_branches_recorded': len(indirect_rows),
    'clean_cfg_edges': len(clean_edge_rows),
    'dot_graphs': len(list(dot_dir.glob('*.dot'))),
}
(root / 'arm64_deflatten_report.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
with (root / 'arm64_deflatten_report.md').open('w', encoding='utf-8') as w:
    w.write('# ARM64 de-flatten / indirect-flow reconstruction\n\n')
    w.write('This stage collapses trivial branch trampolines, ranks dispatcher-like blocks, finds dominant state-register candidates, records indirect-branch context, and emits simplified CFGs. It is heuristic and does not rewrite the binary.\n\n')
    for k, v in summary.items():
        w.write(f'- {k.replace("_", " ").title()}: **{v}**\n')
    w.write('\n## Top candidates\n\n| Score | Dispatcher | Entry | Blocks | SCC | Indirect | Function |\n|---:|---:|---|---:|---:|---:|---|\n')
    for r in candidate_rows[:60]:
        name = r['name'].replace('|', '\\|')
        w.write(f'| {r["suspicion_score"]} | {r["top_dispatcher_score"]} | `{r["entry"]}` | {r["basic_blocks"]} | {r["largest_scc"]} | {r["indirect_branches"]} | `{name}` |\n')
    w.write('\nOpen `arm64_deflatten/` for per-function reconstruction notes and `arm64_deflatten_svg/` for rendered simplified graphs.\n')

print(json.dumps(summary))
