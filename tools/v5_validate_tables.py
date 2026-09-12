#!/usr/bin/env python3
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: v5_validate_tables.py <analysis-output-dir>')
root = Path(sys.argv[1])


def rows(name):
    p = root / name
    if not p.exists() or p.stat().st_size == 0:
        return []
    with p.open(encoding='utf-8', errors='replace', newline='') as f:
        return list(csv.DictReader(f))


def hx(x):
    try:
        return int((x or '').strip(), 16)
    except Exception:
        return None

functions = rows('functions.csv')
jump_rows = rows('v5_jump_tables.csv')
branches = rows('v5_indirect_branches.csv')
func_range = {}
for r in functions:
    e = hx(r.get('entry'))
    if e is None:
        continue
    try:
        size = int(r.get('size_bytes') or 0)
    except Exception:
        size = 0
    func_range[(r.get('entry') or '').strip().upper().zfill(8)] = (e, e + max(1, size))

instruction_addresses = set()
dis = root / 'disassembly.txt'
if dis.exists():
    with dis.open(encoding='utf-8', errors='replace') as f:
        for line in f:
            try:
                instruction_addresses.add(int(line.split('\t', 1)[0].strip(), 16))
            except Exception:
                pass

by_branch = defaultdict(list)
validated_targets = []
for r in jump_rows:
    key = ((r.get('function_entry') or '').strip().upper().zfill(8), (r.get('branch_address') or '').strip().upper().zfill(8))
    target = hx(r.get('target_address'))
    aligned = target is not None and target % 4 == 0
    known = target in instruction_addresses if target is not None else False
    fr = func_range.get(key[0])
    same_fn = bool(fr and target is not None and fr[0] <= target < fr[1])
    strong = bool(aligned and known and same_fn)
    plausible = bool(aligned and known)
    rr = dict(r)
    rr.update({
        'target_aligned_4': str(aligned).lower(),
        'target_known_instruction': str(known).lower(),
        'target_same_function': str(same_fn).lower(),
        'plausible_static_target': str(plausible).lower(),
        'strong_static_target': str(strong).lower(),
    })
    by_branch[key].append(rr)
    if plausible:
        validated_targets.append(rr)

branch_meta = {((r.get('function_entry') or '').strip().upper().zfill(8), (r.get('branch_address') or '').strip().upper().zfill(8)): r for r in branches}
validation = []
runtime_candidates = []
for key, xs in sorted(by_branch.items()):
    total = len(xs)
    aligned = sum(r['target_aligned_4'] == 'true' for r in xs)
    known = sum(r['target_known_instruction'] == 'true' for r in xs)
    same = sum(r['target_same_function'] == 'true' for r in xs)
    strong = sum(r['strong_static_target'] == 'true' for r in xs)
    plausible = sum(r['plausible_static_target'] == 'true' for r in xs)
    meta = branch_meta.get(key, {})
    if total >= 2 and strong >= 2 and strong / total >= 0.60:
        classification = 'static-jump-table-high'
        confidence = 'high'
        note = 'Most decoded entries land on aligned known instructions inside the same function.'
    elif total >= 2 and plausible >= 2 and plausible / total >= 0.50:
        classification = 'static-jump-table-medium'
        confidence = 'medium'
        note = 'Many decoded entries land on aligned known instructions, but same-function evidence is incomplete.'
    elif total and known == 0:
        classification = 'table-pattern-static-bytes-invalid'
        confidence = 'low-static/high-runtime-interest'
        note = 'ARM64 looks like a relative jump-table dispatcher, but decoded on-disk entries do not land on any known instruction. The table may be initialized/decrypted at runtime, relocated in a nontrivial way, or this may be a false pattern match.'
    else:
        classification = 'table-candidate-weak'
        confidence = 'low'
        note = 'Some structural evidence exists, but the static targets are not strong enough to claim a recovered table.'
    row = {
        'function_entry': key[0],
        'function_name': meta.get('function_name', ''),
        'branch_address': key[1],
        'pattern': meta.get('pattern', ''),
        'table_address': meta.get('table_address', ''),
        'index_register': meta.get('index_register', ''),
        'max_index': meta.get('max_index', ''),
        'entries_examined': total,
        'aligned_targets': aligned,
        'known_instruction_targets': known,
        'same_function_targets': same,
        'plausible_static_targets': plausible,
        'strong_static_targets': strong,
        'classification': classification,
        'confidence': confidence,
        'note': note,
    }
    validation.append(row)
    if classification == 'table-pattern-static-bytes-invalid':
        runtime_candidates.append(row)

fields = ['function_entry','function_name','branch_address','pattern','table_address','index_register','max_index','entries_examined','aligned_targets','known_instruction_targets','same_function_targets','plausible_static_targets','strong_static_targets','classification','confidence','note']
with (root / 'v5_jump_table_validation.csv').open('w', encoding='utf-8', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(validation)

if jump_rows:
    target_fields = list(jump_rows[0].keys()) + ['target_aligned_4','target_known_instruction','target_same_function','plausible_static_target','strong_static_target']
else:
    target_fields = ['function_entry','branch_address','target_address','target_aligned_4','target_known_instruction','target_same_function','plausible_static_target','strong_static_target']
with (root / 'v5_jump_table_targets_valid.csv').open('w', encoding='utf-8', newline='') as f:
    w = csv.DictWriter(f, fieldnames=target_fields); w.writeheader(); w.writerows(validated_targets)
with (root / 'v5_runtime_table_candidates.csv').open('w', encoding='utf-8', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(runtime_candidates)

summary = {
    'table_candidates': len(validation),
    'high_confidence_static_tables': sum(r['classification'] == 'static-jump-table-high' for r in validation),
    'medium_confidence_static_tables': sum(r['classification'] == 'static-jump-table-medium' for r in validation),
    'runtime_or_transformed_table_candidates': len(runtime_candidates),
    'validated_static_targets': len(validated_targets),
    'known_instruction_addresses': len(instruction_addresses),
}
(root / 'v5_jump_table_validation.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
with (root / 'v5_jump_table_validation.md').open('w', encoding='utf-8') as w:
    w.write('# V5 jump-table validation\n\n')
    w.write('This report deliberately separates an ARM64 **table-shaped pattern** from a **statically recovered jump table**. Merely landing inside an executable segment is not enough. A plausible static target must be 4-byte aligned and correspond to a Ghidra-disassembled instruction; high-confidence tables also land predominantly inside the originating function.\n\n')
    for k, v in summary.items():
        w.write(f'- {k.replace("_", " ").title()}: **{v}**\n')
    w.write('\n## Runtime/transformed table candidates\n\n')
    w.write('| Function | Branch | Table | Index | Entries | Classification |\n|---|---|---|---|---:|---|\n')
    for r in runtime_candidates[:80]:
        w.write(f"| `{r['function_entry']}` | `{r['branch_address']}` | `{r['table_address']}` | `{r['index_register']}` | {r['entries_examined']} | {r['classification']} |\n")
    w.write('\nA `table-pattern-static-bytes-invalid` result is not proof of encryption. It is a useful signal to correlate with constructors, bulk stores, `mprotect`, runtime dumps, or P-code slices before claiming the table is dynamically generated.\n')

print(json.dumps(summary))
