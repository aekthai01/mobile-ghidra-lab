#!/usr/bin/env python3
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: v5_pcode_slices.py <analysis-output-dir>')
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


def split_inputs(s):
    return [x.strip() for x in (s or '').split(' | ') if x.strip()]


def pretty_var(v):
    v = (v or '').strip()
    m = re.fullmatch(r'\(register, 0x([0-9a-fA-F]+), (\d+)\)', v)
    if m:
        off, size = int(m.group(1), 16), int(m.group(2))
        if off == 0x8 and size == 8:
            return 'SP'
        if 0x4000 <= off <= 0x40f8 and (off - 0x4000) % 8 == 0:
            n = (off - 0x4000) // 8
            if 0 <= n <= 31:
                return ('W' if size <= 4 else 'X') + str(n)
        return f'REG[0x{off:X}:{size}]'
    m = re.fullmatch(r'\(const, 0x([0-9a-fA-F]+), (\d+)\)', v)
    if m:
        return f'0x{int(m.group(1),16):X}'
    m = re.fullmatch(r'\(unique, 0x([0-9a-fA-F]+), (\d+)\)', v)
    if m:
        return f'u_{m.group(1).upper()}:{m.group(2)}'
    m = re.fullmatch(r'\(ram, 0x([0-9a-fA-F]+), (\d+)\)', v)
    if m:
        return f'RAM[0x{int(m.group(1),16):X}]'
    return v

pcode = rows('v5_pcode.csv')
indirect = rows('v5_indirect_branches.csv')
validation = rows('v5_jump_table_validation.csv')
valid_by_branch = {(canon(r.get('function_entry')), canon(r.get('branch_address'))): r for r in validation}

by_func = defaultdict(list)
for seq, r in enumerate(pcode):
    e = canon(r.get('function_entry'))
    if not e:
        continue
    rr = dict(r)
    rr['_seq'] = seq
    rr['_addr'] = int(canon(r.get('instruction_address')), 16)
    rr['_pi'] = int(r.get('pcode_index') or 0)
    by_func[e].append(rr)
for e in by_func:
    by_func[e].sort(key=lambda r: (r['_addr'], r['_pi'], r['_seq']))
    for i, r in enumerate(by_func[e]):
        r['_local_index'] = i


def last_def(xs, var, before):
    if not var or var.startswith('(const,') or var.startswith('(ram,'):
        return None
    for i in range(before - 1, -1, -1):
        if (xs[i].get('output') or '').strip() == var:
            return i, xs[i]
    return None


def expr(xs, var, before, depth=0, seen=None):
    if seen is None:
        seen = set()
    pv = pretty_var(var)
    if depth >= 10 or var in seen:
        return pv
    d = last_def(xs, var, before)
    if d is None:
        return pv
    idx, row = d
    key = (var, idx)
    if key in seen:
        return pv
    seen = set(seen)
    seen.add(key)
    op = row.get('mnemonic') or ('OP' + str(row.get('opcode', '')))
    ins = split_inputs(row.get('inputs'))
    es = [expr(xs, x, idx, depth + 1, seen) for x in ins]
    if op == 'COPY' and len(es) == 1:
        return es[0]
    if op == 'INT_ADD' and len(es) == 2:
        return f'({es[0]} + {es[1]})'
    if op == 'INT_SUB' and len(es) == 2:
        return f'({es[0]} - {es[1]})'
    if op == 'INT_LEFT' and len(es) == 2:
        return f'({es[0]} << {es[1]})'
    if op in ('INT_RIGHT', 'INT_SRIGHT') and len(es) == 2:
        return f'({es[0]} >> {es[1]})'
    if op == 'INT_SEXT' and len(es) == 1:
        return f'sext({es[0]})'
    if op == 'INT_ZEXT' and len(es) == 1:
        return f'zext({es[0]})'
    if op == 'LOAD' and len(es) >= 2:
        return f'LOAD[{es[-1]}]'
    if op == 'PTRADD' and len(es) >= 3:
        return f'({es[0]} + {es[1]}*{es[2]})'
    if op in ('INT_AND','INT_OR','INT_XOR') and len(es) == 2:
        sym = {'INT_AND':'&','INT_OR':'|','INT_XOR':'^'}[op]
        return f'({es[0]} {sym} {es[1]})'
    return op + '(' + ', '.join(es) + ')'

records = []
outdir = root / 'v5_pcode_slices'
outdir.mkdir(exist_ok=True)
for r in indirect:
    e = canon(r.get('function_entry'))
    addr = canon(r.get('branch_address'))
    xs = by_func.get(e)
    if not xs:
        continue
    a = int(addr, 16)
    branch_idx = None
    branch_row = None
    for i, row in enumerate(xs):
        if row['_addr'] == a and (row.get('mnemonic') or '') == 'BRANCHIND':
            branch_idx, branch_row = i, row
            break
    if branch_idx is None:
        continue
    inputs = split_inputs(branch_row.get('inputs'))
    target_var = inputs[0] if inputs else ''
    expression = expr(xs, target_var, branch_idx)
    lo = max(0, branch_idx - 45)
    evidence = xs[lo:branch_idx + 1]
    validation_row = valid_by_branch.get((e, addr), {})
    classification = validation_row.get('classification', '')
    table_addr = validation_row.get('table_address') or r.get('table_address', '')
    path = outdir / f'{e}_{addr}.md'
    with path.open('w', encoding='utf-8') as w:
        w.write(f'# P-code backward slice `{e}` / `0x{addr}`\n\n')
        w.write(f'- Function: `{r.get("function_name", "")}`\n- Branch register: `{r.get("branch_register", "")}`\n- Pattern: `{r.get("pattern", "")}`\n- Table: `{table_addr}`\n- Static validation: `{classification or "not-applicable"}`\n\n')
        w.write('## Reconstructed target expression\n\n```text\n' + expression + '\n```\n\n')
        w.write('## Raw P-code evidence\n\n```text\n')
        for q in evidence:
            out = pretty_var(q.get('output'))
            ins_pretty = ', '.join(pretty_var(x) for x in split_inputs(q.get('inputs')))
            w.write(f"0x{canon(q.get('instruction_address'))} [{q.get('pcode_index')}] {q.get('mnemonic')} {out} <- {ins_pretty}\n")
        w.write('```\n\n')
        w.write('This is a bounded backward slice over raw instruction P-code. It is evidence for value construction, not a proof of the original source-level expression.\n')
    records.append({
        'function_entry': e,
        'function_name': r.get('function_name', ''),
        'branch_address': addr,
        'branch_register': r.get('branch_register', ''),
        'pattern': r.get('pattern', ''),
        'table_address': table_addr,
        'static_validation': classification,
        'target_pcode_varnode': target_var,
        'target_expression': expression,
        'slice_path': str(path.relative_to(root)),
    })

fields = ['function_entry','function_name','branch_address','branch_register','pattern','table_address','static_validation','target_pcode_varnode','target_expression','slice_path']
with (root / 'v5_pcode_indirect_slices.csv').open('w', encoding='utf-8', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(records)
with (root / 'v5_pcode_indirect_slices.jsonl').open('w', encoding='utf-8') as f:
    for r in records:
        f.write(json.dumps(r, ensure_ascii=False) + '\n')
with (root / 'v5_pcode_slices_report.md').open('w', encoding='utf-8') as w:
    w.write('# V5 P-code indirect-flow slices\n\n')
    w.write(f'- Indirect branches with exported raw P-code: **{len(records)}**\n')
    w.write('- Register varnodes in the normal AArch64 X-register bank are rendered as `Xn/Wn` when the Ghidra register-space offset is unambiguous.\n')
    w.write('- Expressions are bounded backward slices and may stop at prior state, memory loads, calls, or the P-code export limit.\n\n')
    w.write('| Function | Branch | Validation | Target expression |\n|---|---|---|---|\n')
    for r in records[:100]:
        ex = r['target_expression'].replace('|', '\\|')[:220]
        w.write(f"| `{r['function_entry']}` | `{r['branch_address']}` | {r['static_validation']} | `{ex}` |\n")

print(json.dumps({'pcode_indirect_slices': len(records)}))
