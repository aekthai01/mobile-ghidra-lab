#!/usr/bin/env python3
import bisect
import csv
import json
import re
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

if len(sys.argv) not in (2, 3):
    raise SystemExit('usage: v5_arm64_flow.py <analysis-output-dir> [analyzed-elf]')

root = Path(sys.argv[1])
binary_path = Path(sys.argv[2]) if len(sys.argv) == 3 else None


def csv_rows(name):
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


def parse_int(s):
    s = (s or '').strip().replace('#', '')
    if not s:
        return None
    try:
        return int(s, 0)
    except ValueError:
        try:
            return int(s, 16)
        except ValueError:
            return None


functions = csv_rows('functions.csv')
selected = csv_rows('v4_selected_functions.csv') or csv_rows('v5_selected_functions.csv')
if not functions:
    raise SystemExit('functions.csv missing or empty')

funcs = {}
starts = []
for r in functions:
    e = canon(r.get('entry'))
    if not e:
        continue
    try:
        start = int(e, 16)
        size = int(r.get('size_bytes') or 0)
    except ValueError:
        continue
    rr = dict(r)
    rr['_entry'] = e
    rr['_start'] = start
    rr['_size'] = size
    funcs[e] = rr
    starts.append(start)
starts.sort()
start_to_entry = {r['_start']: e for e, r in funcs.items()}
selected_entries = {canon(r.get('entry')) for r in selected if canon(r.get('entry'))}


def containing_entry(addr):
    i = bisect.bisect_right(starts, addr) - 1
    if i < 0:
        return None
    st = starts[i]
    e = start_to_entry[st]
    size = funcs[e]['_size']
    return e if size <= 0 or addr < st + size else None


ins_by_func = defaultdict(list)
dis = root / 'disassembly.txt'
if not dis.exists():
    raise SystemExit('disassembly.txt missing')
with dis.open(encoding='utf-8', errors='replace') as f:
    for line in f:
        parts = line.rstrip('\n').split('\t', 2)
        if len(parts) < 3:
            continue
        try:
            addr = int(parts[0].strip(), 16)
        except ValueError:
            continue
        e = containing_entry(addr)
        if not e:
            continue
        text = parts[2].strip()
        if not text:
            continue
        xs = text.split(None, 1)
        mnem = xs[0].upper()
        ops = xs[1].strip() if len(xs) > 1 else ''
        ins_by_func[e].append({'addr': addr, 'mnem': mnem, 'ops': ops, 'text': text})

segments = []
blob = None
elf_error = ''
if binary_path and binary_path.is_file():
    try:
        from elftools.elf.elffile import ELFFile
        with binary_path.open('rb') as ef:
            elf = ELFFile(ef)
            for seg in elf.iter_segments():
                if seg['p_type'] != 'PT_LOAD':
                    continue
                segments.append((int(seg['p_vaddr']), int(seg['p_offset']), int(seg['p_filesz']), int(seg['p_memsz']), int(seg['p_flags'])))
        blob = binary_path.read_bytes()
    except Exception as exc:
        elf_error = str(exc)


def va_to_off(va, size=1):
    if blob is None:
        return None
    for vaddr, off, filesz, memsz, flags in segments:
        if vaddr <= va and va + size <= vaddr + filesz:
            return off + (va - vaddr)
    return None


def is_exec_va(va):
    for vaddr, off, filesz, memsz, flags in segments:
        if vaddr <= va < vaddr + memsz:
            return bool(flags & 1)
    return False


def split_operands(s):
    out, cur, depth = [], [], 0
    for ch in s:
        if ch in '[{(':
            depth += 1
        elif ch in ']})':
            depth = max(0, depth - 1)
        if ch == ',' and depth == 0:
            out.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur or s:
        out.append(''.join(cur).strip())
    return out


def reg_norm(s):
    s = (s or '').strip().upper()
    m = re.fullmatch(r'([WX])(\d{1,2})', s)
    if not m:
        return s
    return 'X' + m.group(2)


def imm_from_operand(s):
    m = re.search(r'#?(-?0x[0-9a-fA-F]+|-?\d+)', s or '')
    return parse_int(m.group(1)) if m else None


def direct_target(ins):
    if ins['mnem'] in {'B', 'BL', 'CBZ', 'CBNZ', 'TBZ', 'TBNZ'} or ins['mnem'].startswith('B.'):
        ms = re.findall(r'0x([0-9a-fA-F]+)', ins['ops'])
        if ms:
            return int(ms[-1], 16)
    return None


def block_graph(ins):
    if not ins:
        return {}, [], {}
    addr_to_i = {x['addr']: i for i, x in enumerate(ins)}
    leaders = {ins[0]['addr']}
    terminal_uncond = {'B', 'BR', 'BRAA', 'BRAB', 'BRAAZ', 'BRABZ', 'RET', 'ERET'}
    conditional = {'CBZ', 'CBNZ', 'TBZ', 'TBNZ'}
    for i, x in enumerate(ins):
        t = direct_target(x)
        if t in addr_to_i:
            leaders.add(t)
        if x['mnem'] in conditional or x['mnem'].startswith('B.'):
            if i + 1 < len(ins):
                leaders.add(ins[i + 1]['addr'])
        elif x['mnem'] in terminal_uncond:
            if i + 1 < len(ins):
                leaders.add(ins[i + 1]['addr'])
    leader_list = sorted(leaders)
    blocks = {}
    for bi, st in enumerate(leader_list):
        lo = addr_to_i[st]
        hi = addr_to_i[leader_list[bi + 1]] - 1 if bi + 1 < len(leader_list) else len(ins) - 1
        blocks[st] = ins[lo:hi + 1]
    block_for_addr = {}
    for st, xs in blocks.items():
        for x in xs:
            block_for_addr[x['addr']] = st
    edges = []
    starts_sorted = sorted(blocks)
    next_block = {starts_sorted[i]: starts_sorted[i + 1] if i + 1 < len(starts_sorted) else None for i in range(len(starts_sorted))}
    for st, xs in blocks.items():
        last = xs[-1]
        m = last['mnem']
        t = direct_target(last)
        if m == 'B':
            if t in block_for_addr:
                edges.append((st, block_for_addr[t], 'direct'))
        elif m in conditional or m.startswith('B.'):
            if t in block_for_addr:
                edges.append((st, block_for_addr[t], 'cond-true'))
            nb = next_block[st]
            if nb is not None:
                edges.append((st, nb, 'cond-false'))
        elif m in {'RET', 'ERET', 'BR', 'BRAA', 'BRAB', 'BRAAZ', 'BRABZ'}:
            pass
        else:
            nb = next_block[st]
            if nb is not None:
                edges.append((st, nb, 'fallthrough'))
    return blocks, edges, block_for_addr


INDIRECT_J = {'BR', 'BRAA', 'BRAB', 'BRAAZ', 'BRABZ'}
CMP = {'CMP', 'CMN', 'TST', 'CCMP', 'CCMN'}
jump_rows = []
indirect_rows = []
resolved_edges = []
state_rows = []
function_rows = []
clean_edge_rows = []
slice_specs = []

for entry, finfo in funcs.items():
    ins = ins_by_func.get(entry, [])
    if not ins:
        continue
    blocks, edges, block_for_addr = block_graph(ins)
    indeg = Counter(b for a, b, k in edges)
    outdeg = Counter(a for a, b, k in edges)

    for i, x in enumerate(ins):
        if x['mnem'] not in CMP:
            continue
        ops = split_operands(x['ops'])
        if len(ops) < 2:
            continue
        reg = reg_norm(ops[0])
        imm = imm_from_operand(ops[1])
        if not re.fullmatch(r'X\d{1,2}', reg) or imm is None:
            continue
        true_target = ''
        false_target = ''
        cond = ''
        if i + 1 < len(ins):
            nx = ins[i + 1]
            if nx['mnem'].startswith('B.') or nx['mnem'] in {'CBZ', 'CBNZ', 'TBZ', 'TBNZ'}:
                tt = direct_target(nx)
                true_target = f'{tt:08X}' if tt is not None else ''
                cond = nx['mnem']
                if i + 2 < len(ins):
                    false_target = f'{ins[i + 2]["addr"]:08X}'
        state_rows.append({
            'function_entry': entry, 'function_name': finfo.get('name', ''), 'compare_address': f'{x["addr"]:08X}',
            'register': reg, 'constant': hex(imm & 0xffffffffffffffff), 'condition': cond,
            'true_target': true_target, 'false_target': false_target,
        })

    for i, x in enumerate(ins):
        if x['mnem'] not in INDIRECT_J:
            continue
        br_ops = split_operands(x['ops'])
        target_reg = reg_norm(br_ops[0]) if br_ops else ''
        context = ins[max(0, i - 14):i + 1]
        pattern = ''
        table_va = None
        index_reg = ''
        max_index = None
        base_reg = ''
        load_i = None

        for j in range(i - 1, max(-1, i - 12), -1):
            y = ins[j]
            if y['mnem'] != 'ADD':
                continue
            op = split_operands(y['ops'])
            if len(op) >= 3 and reg_norm(op[0]) == target_reg and reg_norm(op[1]) == target_reg:
                maybe_base = reg_norm(op[2])
                for k in range(j - 1, max(-1, j - 10), -1):
                    z = ins[k]
                    if z['mnem'] != 'LDRSW':
                        continue
                    zop = split_operands(z['ops'])
                    if len(zop) < 2 or reg_norm(zop[0]) != target_reg:
                        continue
                    mm = re.search(r'\[\s*([xw]\d+)\s*,\s*([xw]\d+)\s*,\s*LSL\s*#?(0x[0-9a-f]+|\d+)\s*\]', zop[1], re.I)
                    if not mm:
                        continue
                    br = reg_norm(mm.group(1))
                    ir = reg_norm(mm.group(2))
                    sh = parse_int(mm.group(3))
                    if br != maybe_base or sh != 2:
                        continue
                    base_reg, index_reg, load_i = br, ir, k
                    pattern = 'relative32'
                    break
            if pattern:
                break

        if pattern == 'relative32':
            page = None
            off = 0
            for j in range(load_i - 1, max(-1, load_i - 16), -1):
                y = ins[j]
                op = split_operands(y['ops'])
                if y['mnem'] == 'ADD' and len(op) >= 3 and reg_norm(op[0]) == base_reg and reg_norm(op[1]) == base_reg:
                    v = imm_from_operand(op[2])
                    if v is not None:
                        off = v
                elif y['mnem'] == 'ADRP' and len(op) >= 2 and reg_norm(op[0]) == base_reg:
                    page = imm_from_operand(op[1])
                    if page is not None:
                        break
            if page is not None:
                table_va = page + off
            for j in range(load_i - 1, max(-1, load_i - 18), -1):
                y = ins[j]
                if y['mnem'] != 'CMP':
                    continue
                op = split_operands(y['ops'])
                if len(op) >= 2 and reg_norm(op[0]) == index_reg:
                    v = imm_from_operand(op[1])
                    if v is not None and 0 <= v <= 4096:
                        max_index = v
                        break

        block_st = block_for_addr.get(x['addr'], x['addr'])
        resolved = 0
        valid = 0
        if pattern == 'relative32' and table_va is not None and max_index is not None and blob is not None:
            count = min(max_index + 1, 1024)
            for idx in range(count):
                off = va_to_off(table_va + idx * 4, 4)
                if off is None:
                    break
                rel = struct.unpack_from('<i', blob, off)[0]
                target = (table_va + rel) & 0xffffffffffffffff
                in_fn = finfo['_start'] <= target < finfo['_start'] + max(1, finfo['_size'])
                exec_ok = is_exec_va(target)
                if exec_ok:
                    valid += 1
                jump_rows.append({
                    'function_entry': entry, 'function_name': finfo.get('name', ''), 'branch_address': f'{x["addr"]:08X}',
                    'table_address': f'{table_va:08X}', 'index_register': index_reg, 'index': idx,
                    'relative_offset': rel, 'target_address': f'{target:08X}', 'target_in_function': str(in_fn).lower(),
                    'target_executable': str(exec_ok).lower(), 'pattern': pattern,
                })
                if exec_ok:
                    resolved_edges.append((entry, block_st, target, 'jump-table'))
                    resolved += 1
        indirect_rows.append({
            'function_entry': entry, 'function_name': finfo.get('name', ''), 'branch_address': f'{x["addr"]:08X}',
            'branch_register': target_reg, 'pattern': pattern or 'unresolved', 'table_address': f'{table_va:08X}' if table_va is not None else '',
            'index_register': index_reg, 'max_index': '' if max_index is None else max_index,
            'resolved_targets': resolved, 'valid_exec_targets': valid,
            'context': ' | '.join(f'{q["addr"]:08X}:{q["text"]}' for q in context[-8:]),
        })
        slice_specs.append((entry, x['addr'], 'indirect-branch'))

    e2 = list(edges)
    for fe, src, target, kind in resolved_edges:
        if fe != entry:
            continue
        if target in block_for_addr:
            e2.append((src, block_for_addr[target], kind))
    indeg2 = Counter(b for a, b, k in e2)
    outdeg2 = Counter(a for a, b, k in e2)

    state_count_by_block = Counter()
    for row in state_rows:
        if row['function_entry'] != entry:
            continue
        a = int(row['compare_address'], 16)
        st = block_for_addr.get(a)
        if st is not None:
            state_count_by_block[st] += 1
    indirect_block_set = {block_for_addr.get(x['addr']) for x in ins if x['mnem'] in INDIRECT_J}
    dispatcher_candidates = []
    for st, xs in blocks.items():
        score = min(60, indeg2[st] * 3) + min(40, state_count_by_block[st] * 8) + (30 if st in indirect_block_set else 0)
        if indeg2[st] >= 8 or score >= 45:
            dispatcher_candidates.append((score, st, indeg2[st], outdeg2[st], state_count_by_block[st], st in indirect_block_set))
    dispatcher_candidates.sort(reverse=True)
    for score, st, inn, outn, sc, ij in dispatcher_candidates[:8]:
        slice_specs.append((entry, st, f'dispatcher-score:{score}'))

    trivial = {}
    for st, xs in blocks.items():
        real = [z for z in xs if z['mnem'] != 'NOP']
        if len(real) == 1 and real[0]['mnem'] == 'B':
            t = direct_target(real[0])
            if t in block_for_addr:
                trivial[st] = block_for_addr[t]

    def collapse(n):
        seen = set()
        while n in trivial and n not in seen:
            seen.add(n)
            n = trivial[n]
        return n

    clean = set()
    for a, b, k in e2:
        aa, bb = collapse(a), collapse(b)
        if aa != bb:
            clean.add((aa, bb, k))
    for a, b, k in sorted(clean):
        clean_edge_rows.append({'function_entry': entry, 'from_block': f'{a:08X}', 'to_block': f'{b:08X}', 'edge_type': k})

    state_regs = Counter()
    for row in state_rows:
        if row['function_entry'] == entry:
            state_regs[row['register']] += 1
    topreg, tophits = ('', 0)
    if state_regs:
        topreg, tophits = state_regs.most_common(1)[0]
    function_rows.append({
        'entry': entry, 'name': finfo.get('name', ''), 'size_bytes': finfo['_size'], 'instructions': len(ins),
        'basic_blocks': len(blocks), 'direct_cfg_edges': len(edges), 'clean_cfg_edges': len(clean),
        'indirect_branches': sum(1 for x in ins if x['mnem'] in INDIRECT_J),
        'resolved_indirect_edges': sum(1 for fe, *_ in resolved_edges if fe == entry),
        'dispatcher_candidates': len(dispatcher_candidates), 'top_dispatcher_score': dispatcher_candidates[0][0] if dispatcher_candidates else 0,
        'state_register': topreg, 'state_compare_hits': tophits, 'selected': str(entry in selected_entries).lower(),
    })

slice_dir = root / 'v5_slices'
slice_dir.mkdir(exist_ok=True)
slice_index = []
per_fn_count = Counter()
seen_centers = set()
for entry, center, reason in slice_specs:
    if entry not in selected_entries:
        continue
    key = (entry, center)
    if key in seen_centers or per_fn_count[entry] >= 48:
        continue
    seen_centers.add(key)
    per_fn_count[entry] += 1
    ins = ins_by_func.get(entry, [])
    if not ins:
        continue
    addrs = [x['addr'] for x in ins]
    i = bisect.bisect_right(addrs, center) - 1
    if i < 0:
        i = 0
    lo = max(0, i - 32)
    hi = min(len(ins) - 1, i + 40)
    fn = root / 'v5_slices' / entry
    fn.mkdir(exist_ok=True)
    path = fn / f'{per_fn_count[entry]:02d}_{ins[i]["addr"]:08X}.asm'
    with path.open('w', encoding='utf-8') as w:
        w.write(f'; V5 semantic slice\n; function={entry} {funcs[entry].get("name", "")}\n; center={ins[i]["addr"]:08X} reason={reason}\n')
        for z in ins[lo:hi + 1]:
            w.write(f'.text:{z["addr"]:016X}  {z["mnem"]:<9} {z["ops"]}\n')
    slice_index.append({'function_entry': entry, 'center_address': f'{ins[i]["addr"]:08X}', 'reason': reason, 'start_address': f'{ins[lo]["addr"]:08X}', 'end_address': f'{ins[hi]["addr"]:08X}', 'path': str(path.relative_to(root))})


def write_csv(name, rows, fields):
    with (root / name).open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


write_csv('v5_indirect_branches.csv', indirect_rows, ['function_entry', 'function_name', 'branch_address', 'branch_register', 'pattern', 'table_address', 'index_register', 'max_index', 'resolved_targets', 'valid_exec_targets', 'context'])
write_csv('v5_jump_tables.csv', jump_rows, ['function_entry', 'function_name', 'branch_address', 'table_address', 'index_register', 'index', 'relative_offset', 'target_address', 'target_in_function', 'target_executable', 'pattern'])
write_csv('v5_state_values.csv', state_rows, ['function_entry', 'function_name', 'compare_address', 'register', 'constant', 'condition', 'true_target', 'false_target'])
write_csv('v5_function_flow.csv', sorted(function_rows, key=lambda r: (-int(r['top_dispatcher_score']), -int(r['resolved_indirect_edges']), -int(r['basic_blocks']))), ['entry', 'name', 'size_bytes', 'instructions', 'basic_blocks', 'direct_cfg_edges', 'clean_cfg_edges', 'indirect_branches', 'resolved_indirect_edges', 'dispatcher_candidates', 'top_dispatcher_score', 'state_register', 'state_compare_hits', 'selected'])
write_csv('v5_clean_edges.csv', clean_edge_rows, ['function_entry', 'from_block', 'to_block', 'edge_type'])
write_csv('v5_slice_index.csv', slice_index, ['function_entry', 'center_address', 'reason', 'start_address', 'end_address', 'path'])

resolved_branches = sum(1 for r in indirect_rows if int(r['resolved_targets']) > 0)
summary = {
    'functions_with_disassembly': len(function_rows),
    'selected_functions': len(selected_entries),
    'indirect_branches': len(indirect_rows),
    'resolved_indirect_branches': resolved_branches,
    'jump_table_entries': len(jump_rows),
    'state_comparisons': len(state_rows),
    'clean_cfg_edges': len(clean_edge_rows),
    'semantic_slices': len(slice_index),
    'binary_mapping_available': blob is not None,
    'elf_mapping_error': elf_error,
}
(root / 'v5_flow_report.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
with (root / 'v5_flow_report.md').open('w', encoding='utf-8') as w:
    w.write('# V5 ARM64 flow recovery\n\n')
    w.write('V5 resolves conservative ARM64 control-flow evidence. A recovered edge is evidence, not a claim that the original source structure has been reconstructed.\n\n')
    for k, v in summary.items():
        w.write(f'- {k.replace("_", " ").title()}: **{v}**\n')
    w.write('\n## Highest dispatcher-like functions\n\n')
    w.write('| Entry | Function | Blocks | Indirect | Resolved edges | Dispatcher score | State reg | Hits |\n|---|---|---:|---:|---:|---:|---|---:|\n')
    for r in sorted(function_rows, key=lambda x: (-int(x['top_dispatcher_score']), -int(x['basic_blocks'])))[:50]:
        w.write(f"| `{r['entry']}` | `{r['name']}` | {r['basic_blocks']} | {r['indirect_branches']} | {r['resolved_indirect_edges']} | {r['top_dispatcher_score']} | {r['state_register']} | {r['state_compare_hits']} |\n")
    w.write('\nKey files: `v5_indirect_branches.csv`, `v5_jump_tables.csv`, `v5_state_values.csv`, `v5_clean_edges.csv`, and `v5_slices/`.\n')

print(json.dumps(summary))
