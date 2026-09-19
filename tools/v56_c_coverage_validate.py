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


def has_2712(text):
    low = (text or '').lower()
    return '0x2712' in low or re.search(r'(?<!\d)10002(?!\d)', low) is not None


def has_https(text):
    return 'https' in (text or '').lower()


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

# Index native whole-function Ghidra C by the entry marker emitted by ExportV4Selected.
whole_c_files = {}
whole_c_text = {}
whole_dir = root / 'v4_decompiled_selected'
if whole_dir.exists():
    for p in whole_dir.glob('*.c'):
        text = p.read_text(encoding='utf-8', errors='replace')
        m = re.search(r'\bentry=([0-9A-Fa-fx]+)', text)
        if not m:
            continue
        e = canon(m.group(1))
        whole_c_files[e] = p
        whole_c_text[e] = text

errors = []
function_report = []
whole_ok_count = 0
fallback_count = 0
fallback_complete = 0
region_expected_total = 0
region_success_total = 0
verified_2712_functions = 0
verified_strong_login_functions = 0

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
        'https_context_ok': None,
    }

    if whole_ok:
        whole_ok_count += 1
        text = whole_c_text.get(e, '')
        cpath = whole_c_files.get(e)
        meaningful, _ = meaningful_c(cpath) if cpath else (False, '')
        if not meaningful:
            errors.append(f'{e}: whole decompile marked ok but meaningful C file is missing')
        if e in immediate_seed_functions:
            seed_ok = meaningful and has_2712(text)
            report['seed_region_ok'] = seed_ok
            if seed_ok:
                verified_2712_functions += 1
            else:
                errors.append(f'{e}: whole C did not preserve 0x2712/10002 login seed')
        if e in strong_login:
            https_ok = meaningful and has_https(text)
            report['https_context_ok'] = https_ok
            if report['seed_region_ok'] and https_ok:
                verified_strong_login_functions += 1
            if not https_ok:
                errors.append(f'{e}: strong 0x2712 + HTTPS function whole C did not preserve HTTPS context')
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
    strong_https_ok = False
    for r in successful:
        p = root / (r.get('c_file') or '')
        ok, text = meaningful_c(p)
        if ok:
            meaningful += 1
        if 'login-seed-0x2712' in (r.get('reason') or '') and ok:
            if has_2712(text):
                seed_ok = True
            if has_https(text):
                strong_https_ok = True
    report['meaningful_c_regions'] = meaningful

    if e in immediate_seed_functions:
        report['seed_region_ok'] = seed_ok
        if seed_ok:
            verified_2712_functions += 1
    if e in strong_login:
        report['https_context_ok'] = strong_https_ok
        if seed_ok and strong_https_ok:
            verified_strong_login_functions += 1

    if expected == 0:
        errors.append(f'{e}: fallback required but instruction count/coverage is unavailable')
    if len(exhaustive) != expected:
        errors.append(f'{e}: exhaustive region attempts {len(exhaustive)} != expected {expected}')
    if len(successful) != expected:
        errors.append(f'{e}: successful C regions {len(successful)} != expected {expected}')
    if meaningful != expected:
        errors.append(f'{e}: meaningful C regions {meaningful} != expected {expected}')
    if e in immediate_seed_functions and not seed_ok:
        errors.append(f'{e}: 0x2712 seed region did not produce verified C-like output containing 0x2712/10002')
    if e in strong_login and not strong_https_ok:
        errors.append(f'{e}: strong 0x2712 + HTTPS fallback did not preserve HTTPS in seed-region C')

    login_ok = e not in immediate_seed_functions or seed_ok
    strong_ok = e not in strong_login or strong_https_ok
    if expected > 0 and len(exhaustive) == expected and len(successful) == expected and meaningful == expected and login_ok and strong_ok:
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
    'verified_0x2712_c_functions': verified_2712_functions,
    'strong_0x2712_https_functions': sorted(strong_login),
    'verified_strong_login_c_functions': verified_strong_login_functions,
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
    w.write(f"- Verified 0x2712 in C: **{verified_2712_functions}**\n")
    w.write(f"- Strong 0x2712 + HTTPS functions: **{len(strong_login)}**\n")
    w.write(f"- Verified strong login C: **{verified_strong_login_functions}**\n")
    if errors:
        w.write('\n## Errors\n\n')
        for e in errors[:500]:
            w.write(f'- {e}\n')

if errors:
    raise SystemExit('V5.6 exhaustive C coverage failed: ' + '; '.join(errors[:40]))

print(json.dumps({k: v for k, v in report.items() if k not in ('functions', 'errors')}))
