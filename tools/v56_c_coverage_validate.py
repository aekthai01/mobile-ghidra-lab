#!/usr/bin/env python3
import csv
import json
import math
import re
import sys
from collections import defaultdict
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: v56_c_coverage_validate.py <analysis-output-dir>')

root = Path(sys.argv[1])
WINDOW = 180
STEP = 160


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


def expected_windows(instructions):
    n = max(0, instructions)
    if n == 0:
        return 0
    if n <= WINDOW:
        return 1
    return 1 + math.ceil((n - WINDOW) / STEP)


def meaningful_c(path):
    if not path.is_file() or path.stat().st_size < 80:
        return False, ''
    text = path.read_text(encoding='utf-8', errors='replace')
    body = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    body = re.sub(r'//.*', '', body)
    body = body.strip()
    structural = ('{' in body and '}' in body and '(' in body and ')' in body)
    signal = any(tok in body for tok in ('if (', 'if(', 'return', 'FUN_', 'sub_', '=', 'goto '))
    return bool(structural and signal), text


selected = {canon(r.get('entry')): r for r in rows('v52_selected_functions.csv') if canon(r.get('entry'))}
whole_rows = {canon(r.get('entry')): r for r in rows('v4_selected_export.csv') if canon(r.get('entry'))}
region_rows = rows('v56_region_c_index.csv')
by_fn = defaultdict(list)
for r in region_rows:
    e = canon(r.get('function_entry'))
    if e:
        by_fn[e].append(r)

seed_rows = rows('v56_login_seeds.csv')
immediate_seed_functions = {
    canon(r.get('function_entry'))
    for r in seed_rows
    if r.get('kind') == 'imm_0x2712' and canon(r.get('function_entry'))
}
https_functions = {
    canon(r.get('function_entry'))
    for r in seed_rows
    if r.get('kind') == 'https_xref' and canon(r.get('function_entry'))
}
strong_login = immediate_seed_functions & https_functions

errors = []
function_report = []
whole_ok_count = 0
fallback_count = 0
fallback_complete = 0
region_expected_total = 0
region_success_total = 0

for e, s in sorted(selected.items()):
    wr = whole_rows.get(e, {})
    whole_ok = (wr.get('decompile_status') or '').lower() == 'ok'
    instructions = as_int(wr.get('instructions'))
    report = {
        'entry': e,
        'name': s.get('name', ''),
        'mode': s.get('recommended_mode', ''),
        'instructions': instructions,
        'whole_status': wr.get('decompile_status', ''),
        'whole_c_ok': whole_ok,
        'expected_regions': 0,
        'attempted_regions': 0,
        'successful_regions': 0,
        'meaningful_c_regions': 0,
        'seed_region_ok': None,
    }

    if whole_ok:
        whole_ok_count += 1
        function_report.append(report)
        continue

    fallback_count += 1
    expected = expected_windows(instructions)
    report['expected_regions'] = expected
    region_expected_total += expected

    exhaustive = [r for r in by_fn.get(e, []) if 'v56-exhaustive-coverage' in (r.get('reason') or '')]
    report['attempted_regions'] = len(exhaustive)
    successful = [r for r in exhaustive if (r.get('status') or '').lower().startswith('ok') and r.get('c_file')]
    report['successful_regions'] = len(successful)
    region_success_total += len(successful)

    meaningful = 0
    seed_ok = False
    for r in successful:
        p = root / (r.get('c_file') or '')
        ok, text = meaningful_c(p)
        if ok:
            meaningful += 1
        if 'login-seed-0x2712' in (r.get('reason') or '') and ok:
            # Ghidra may render the constant in hex or decimal.
            if ('0x2712' in text.lower()) or ('10002' in text):
                seed_ok = True
    report['meaningful_c_regions'] = meaningful

    if e in immediate_seed_functions:
        report['seed_region_ok'] = seed_ok

    if expected == 0:
        errors.append(f'{e}: fallback required but instruction count/coverage is unavailable')
    if len(exhaustive) != expected:
        errors.append(f'{e}: exhaustive region attempts {len(exhaustive)} != expected {expected}')
    if len(successful) != expected:
        errors.append(f'{e}: successful C regions {len(successful)} != expected {expected}')
    if meaningful != expected:
        errors.append(f'{e}: meaningful C regions {meaningful} != expected {expected}')
    if e in immediate_seed_functions and not seed_ok:
        errors.append(f'{e}: 0x2712 seed region did not produce verified C-like output')

    if expected > 0 and len(exhaustive) == expected and len(successful) == expected and meaningful == expected and (e not in immediate_seed_functions or seed_ok):
        fallback_complete += 1

    function_report.append(report)

report = {
    'status': 'pass' if not errors else 'fail',
    'selected_functions': len(selected),
    'whole_c_functions': whole_ok_count,
    'fallback_functions': fallback_count,
    'fallback_functions_complete': fallback_complete,
    'expected_region_windows': region_expected_total,
    'successful_region_windows': region_success_total,
    'immediate_0x2712_functions': sorted(immediate_seed_functions),
    'strong_0x2712_https_functions': sorted(strong_login),
    'errors': errors,
    'functions': function_report,
}

(root / 'v56_c_coverage_acceptance.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
with (root / 'v56_c_coverage_acceptance.md').open('w', encoding='utf-8') as w:
    w.write('# V5.6 exhaustive C coverage acceptance\n\n')
    w.write(f"- Status: **{report['status']}**\n")
    w.write(f"- Selected functions: **{len(selected)}**\n")
    w.write(f"- Whole-function C: **{whole_ok_count}**\n")
    w.write(f"- Fallback functions: **{fallback_count}**\n")
    w.write(f"- Complete fallback functions: **{fallback_complete}**\n")
    w.write(f"- Expected region windows: **{region_expected_total}**\n")
    w.write(f"- Successful region windows: **{region_success_total}**\n")
    w.write(f"- 0x2712 seed functions: **{len(immediate_seed_functions)}**\n")
    w.write(f"- Strong 0x2712 + HTTPS functions: **{len(strong_login)}**\n")
    if errors:
        w.write('\n## Errors\n\n')
        for e in errors[:500]:
            w.write(f'- {e}\n')

if errors:
    raise SystemExit('V5.6 exhaustive C coverage failed: ' + '; '.join(errors[:40]))

print(json.dumps({k: v for k, v in report.items() if k not in ('functions', 'errors')}))
