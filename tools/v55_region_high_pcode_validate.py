#!/usr/bin/env python3
import csv, json, sys
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: v55_region_high_pcode_validate.py <analysis-output-dir>')
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
        return f'{int(v,16):08X}'
    except Exception:
        return v.upper()

selected = {canon(r.get('entry')): r for r in rows('v52_selected_functions.csv') if canon(r.get('entry'))}
protected = {canon(r.get('entry')): r for r in rows('v52_protected_functions.csv') if canon(r.get('entry')) and (r.get('complexity_priority') or '').lower() == 'high'}
whole = {canon(r.get('function_entry')): r for r in rows('v51_high_pcode_summary.csv') if canon(r.get('function_entry'))}
region_rows = rows('v55_region_high_pcode_summary.csv')
by_fn = {}
for r in region_rows:
    by_fn.setdefault(canon(r.get('function_entry')), []).append(r)

errors = []
function_report = []
for e, p in sorted(protected.items()):
    w = whole.get(e, {})
    whole_ok = (w.get('status') or '').lower() == 'ok' and int(w.get('high_pcode_ops') or 0) > 0
    mode = (selected.get(e, {}).get('recommended_mode') or '').lower()
    rr = by_fn.get(e, [])
    attempts = len(rr)
    successes = sum(1 for r in rr if (r.get('status') or '').lower().startswith('ok') and int(r.get('high_pcode_ops') or 0) > 0)
    ops = sum(int(r.get('high_pcode_ops') or 0) for r in rr if (r.get('status') or '').lower().startswith('ok'))
    if not whole_ok and mode == 'region' and attempts == 0:
        errors.append(f'{e}: whole High P-code unavailable and no region High-P-code attempt')
    function_report.append({'entry': e, 'name': p.get('name',''), 'mode': mode, 'whole_status': w.get('status',''), 'region_attempts': attempts, 'region_successes': successes, 'region_ops': ops})

stress = {'00267564', '001D3CA4'}
for e, r in selected.items():
    if (r.get('name') or '') == '_INIT_2':
        stress.add(e)
for e in sorted(stress):
    if e not in selected:
        continue
    w = whole.get(e, {})
    whole_ok = (w.get('status') or '').lower() == 'ok' and int(w.get('high_pcode_ops') or 0) > 0
    if not whole_ok:
        rr = by_fn.get(e, [])
        successes = sum(1 for r in rr if (r.get('status') or '').lower().startswith('ok') and int(r.get('high_pcode_ops') or 0) > 0)
        if successes == 0:
            errors.append(f'{e}: stress target has no successful region High-P-code result')

report = {
    'high_protected_functions': len(protected),
    'region_summary_rows': len(region_rows),
    'region_functions_attempted': len(by_fn),
    'region_success_rows': sum(1 for r in region_rows if (r.get('status') or '').lower().startswith('ok') and int(r.get('high_pcode_ops') or 0) > 0),
    'region_high_pcode_ops': sum(int(r.get('high_pcode_ops') or 0) for r in region_rows if (r.get('status') or '').lower().startswith('ok')),
    'functions': function_report,
    'errors': errors,
    'status': 'pass' if not errors else 'fail',
}
(root / 'v55_region_high_pcode_acceptance.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
with (root / 'v55_region_high_pcode_acceptance.md').open('w', encoding='utf-8') as w:
    w.write('# V5.5 region High-P-code acceptance\n\n')
    w.write(f"- High protected functions: **{len(protected)}**\n")
    w.write(f"- Region attempts: **{len(region_rows)}**\n")
    w.write(f"- Successful region rows: **{report['region_success_rows']}**\n")
    w.write(f"- Region High-P-code ops: **{report['region_high_pcode_ops']}**\n")
    w.write(f"- Status: **{report['status']}**\n")
if errors:
    raise SystemExit('V5.5 region High-P-code acceptance failed: ' + '; '.join(errors))
print(json.dumps({k:v for k,v in report.items() if k != 'functions'}))
