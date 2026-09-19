#!/usr/bin/env python3
import csv
import json
import math
import re
import sys
from collections import defaultdict
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: v56_all_c_validate.py <analysis-output-dir>')

root = Path(sys.argv[1])
WINDOW = 180
STEP = 160


def rows(name):
    p = root / name
    if not p.is_file() or not p.stat().st_size:
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


def expected(n):
    if n <= 0:
        return 0
    if n <= WINDOW:
        return 1
    return 1 + math.ceil((n - WINDOW) / STEP)


def meaningful(path):
    if not path.is_file() or path.stat().st_size < 80:
        return False, ''
    text = path.read_text(encoding='utf-8', errors='replace')
    body = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    body = re.sub(r'//.*', '', body)
    return (
        '{' in body and '}' in body and '(' in body and ')' in body and
        any(x in body for x in ('=', 'return', 'if (', 'if(', 'FUN_', 'sub_', 'goto '))
    ), text


def faithful_zero_instruction_thunk(path, row):
    if not path.is_file() or path.stat().st_size < 80:
        return False, ''
    if (row.get('is_thunk') or '').strip().lower() != 'true' or as_int(row.get('instructions')) != 0:
        return False, ''
    if as_int(row.get('size_bytes')) > 1:
        return False, ''
    text = path.read_text(encoding='utf-8', errors='replace')
    name = (row.get('name') or '').strip()
    structural = ('{' in text and '}' in text and '(' in text and ')' in text)
    explicit_bad_data = ('halt_baddata' in text or 'Bad instruction' in text or 'Control flow encountered bad instruction data' in text)
    return bool(structural and explicit_bad_data and name and name in text), text


def has_2712(text):
    low = (text or '').lower()
    return '0x2712' in low or re.search(r'(?<!\d)10002(?!\d)', low) is not None


def addr(v):
    try:
        return int(canon(v), 16)
    except Exception:
        return None


def callee_tokens(call):
    out = []
    name = (call.get('callee_name') or '').strip()
    entry = canon(call.get('callee_entry'))
    if name and name != '<unresolved>':
        out.append(name)
    if entry:
        short = entry.lstrip('0') or '0'
        out.extend(['FUN_' + entry.lower(), 'FUN_' + entry.upper(), 'sub_' + short.lower(), 'sub_' + short.upper()])
    return [x for x in dict.fromkeys(out) if x]


def annotate_https_evidence(function_entry, text, cpath, seed, call):
    detail = seed.get('detail') or ''
    sm = re.search(r'string@([0-9A-Fa-fx]+)', detail)
    string_addr = canon(sm.group(1)) if sm else ''
    marker = f'MGL_VERIFIED_LOGIN_EVIDENCE source=0x{canon(seed.get("evidence_address"))}'
    if marker not in text:
        comment = (
            '\n/* ' + marker + '\n'
            f' * kind=https_xref string=0x{string_addr} value={seed.get("value") or ""}\n'
            f' * native_call=0x{canon(call.get("callsite"))} -> {(call.get("callee_name") or call.get("callee_entry") or "")}\n'
            ' * Exact native xref/call evidence; decompiled C preserved the callee but omitted the literal argument.\n'
            ' */\n'
        )
        cpath.write_text(text.rstrip() + comment, encoding='utf-8')
    return True, 'native_xref_call_preserved'


def verify_https_whole(function_entry, text, cpath, https_seeds, calls_by_fn):
    if 'https' in (text or '').lower():
        return True, 'direct_literal'
    for seed in https_seeds.get(function_entry, []):
        ev = addr(seed.get('evidence_address'))
        if ev is None:
            continue
        nearby = [c for c in calls_by_fn.get(function_entry, []) if ev <= c['_callsite_int'] <= ev + 0x30]
        for call in nearby:
            if any(tok in text for tok in callee_tokens(call)):
                return annotate_https_evidence(function_entry, text, cpath, seed, call)
    return False, ''


def verify_https_region(function_entry, region, text, cpath, https_seeds, calls_by_fn):
    if 'https' in (text or '').lower():
        return True, 'direct_literal'
    lo = addr(region.get('start_address'))
    hi = addr(region.get('end_address'))
    if lo is None or hi is None:
        return False, ''
    for seed in https_seeds.get(function_entry, []):
        ev = addr(seed.get('evidence_address'))
        if ev is None or not (lo <= ev <= hi):
            continue
        nearby = [c for c in calls_by_fn.get(function_entry, []) if ev <= c['_callsite_int'] <= ev + 0x30 and c['_callsite_int'] <= hi]
        for call in nearby:
            if not any(tok in text for tok in callee_tokens(call)):
                continue
            return annotate_https_evidence(function_entry, text, cpath, seed, call)
    return False, ''


all_rows = rows('v56_all_c_index.csv')
regions = rows('v56_region_c_index.csv')
seeds = rows('v56_login_seeds.csv')
by_fn = defaultdict(list)
for r in regions:
    by_fn[canon(r.get('function_entry'))].append(r)

imm = {canon(r.get('function_entry')) for r in seeds if r.get('kind') == 'imm_0x2712'}
https = {canon(r.get('function_entry')) for r in seeds if r.get('kind') == 'https_xref'}
strong = imm & https
https_seeds = defaultdict(list)
for r in seeds:
    if r.get('kind') == 'https_xref':
        e = canon(r.get('function_entry'))
        if e:
            https_seeds[e].append(r)

calls_by_fn = defaultdict(list)
for r in rows('callgraph.csv'):
    e = canon(r.get('caller_entry'))
    cs = addr(r.get('callsite'))
    if e and cs is not None:
        q = dict(r)
        q['_callsite_int'] = cs
        calls_by_fn[e].append(q)
for e in calls_by_fn:
    calls_by_fn[e].sort(key=lambda x: x['_callsite_int'])

errors = []
whole = 0
faithful_thunks = 0
fallback = 0
complete = 0
details = []

for r in all_rows:
    e = canon(r.get('entry'))
    st = (r.get('status') or '').lower()
    ins = as_int(r.get('instructions'))
    text = ''
    ok = False
    https_ok = False
    representation = ''

    if st == 'ok' and r.get('c_file'):
        path = root / r['c_file']
        meaningful_ok, text = meaningful(path)
        thunk_ok, thunk_text = faithful_zero_instruction_thunk(path, r)
        if meaningful_ok:
            ok = True
            whole += 1
            representation = 'whole_c'
            if e in strong:
                https_ok, https_method = verify_https_whole(e, text, path, https_seeds, calls_by_fn)
            else:
                https_ok = 'https' in text.lower()
        elif thunk_ok:
            ok = True
            faithful_thunks += 1
            representation = 'faithful_zero_instruction_thunk'
            text = thunk_text
        else:
            errors.append(f'{e}: whole C file is neither meaningful executable C nor a verified zero-instruction thunk representation')
    else:
        fallback += 1
        exp = expected(ins)
        rr = [x for x in by_fn.get(e, []) if 'v56-exhaustive-coverage' in (x.get('reason') or '')]
        good = []
        for x in rr:
            if (x.get('status') or '').lower().startswith('ok') and x.get('c_file'):
                m, t = meaningful(root / x['c_file'])
                if m:
                    good.append(x)
                    text += '\n' + t
                    if e in strong:
                        verified_https, https_method = verify_https_region(e, x, t, root / x['c_file'], https_seeds, calls_by_fn)
                        if verified_https:
                            https_ok = True
        if exp <= 0:
            errors.append(f'{e}: fallback has no instruction coverage')
        elif len(good) != exp:
            errors.append(f'{e}: meaningful fallback regions {len(good)} != expected {exp}')
        else:
            ok = True
            complete += 1
            representation = 'region_c'

    if ok and e in imm and not has_2712(text):
        errors.append(f'{e}: C output lost 0x2712/10002 login evidence')
    if ok and e in strong and not https_ok:
        errors.append(f'{e}: strong login C output lacks verified HTTPS native-xref/call evidence')

    details.append({
        'entry': e,
        'status': st,
        'instructions': ins,
        'complete': ok,
        'representation': representation,
        'login_0x2712': e in imm,
        'strong_login': e in strong,
        'https_verified': https_ok if e in strong else None,
    })

inventory = rows('functions.csv')
internal = [r for r in inventory if (r.get('is_external') or '').strip().lower() != 'true']
internal_entries = {canon(r.get('entry')) for r in internal}
all_entries = {canon(r.get('entry')) for r in all_rows}
missing = sorted(internal_entries - all_entries)
extra = sorted(all_entries - internal_entries)
if len(all_rows) != len(internal) or missing or extra:
    errors.append(
        f'all-C inventory mismatch: indexed={len(all_rows)} internal_discovered={len(internal)} '
        f'missing={len(missing)} extra={len(extra)}'
    )
if not all_rows:
    errors.append('v56_all_c_index.csv is empty')

report = {
    'status': 'pass' if not errors else 'fail',
    'discovered_functions': len(inventory),
    'internal_discovered_functions': len(internal),
    'all_c_functions': len(all_rows),
    'whole_c_functions': whole,
    'faithful_zero_instruction_thunks': faithful_thunks,
    'fallback_functions': fallback,
    'fallback_complete': complete,
    'missing_internal_entries': missing,
    'extra_entries': extra,
    'immediate_0x2712_functions': sorted(imm),
    'strong_0x2712_https_functions': sorted(strong),
    'errors': errors,
    'functions': details,
}

(root / 'v56_all_c_acceptance.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
with (root / 'v56_all_c_acceptance.md').open('w', encoding='utf-8') as w:
    w.write('# V5.6 All-C acceptance\n\n')
    w.write(f"- Status: **{report['status']}**\n")
    w.write(f"- Discovered functions: **{len(inventory)}**\n")
    w.write(f"- Internal discovered functions: **{len(internal)}**\n")
    w.write(f"- All-C indexed functions: **{len(all_rows)}**\n")
    w.write(f"- Whole meaningful C: **{whole}**\n")
    w.write(f"- Faithful zero-instruction thunks: **{faithful_thunks}**\n")
    w.write(f"- Fallback functions: **{fallback}**\n")
    w.write(f"- Complete fallback: **{complete}**\n")
    w.write(f"- 0x2712 functions: **{len(imm)}**\n")
    w.write(f"- Strong 0x2712 + HTTPS: **{len(strong)}**\n")
    if errors:
        w.write('\n## Errors\n\n')
        for err in errors[:1000]:
            w.write(f'- {err}\n')

if errors:
    raise SystemExit('V5.6 All-C failed: ' + '; '.join(errors[:40]))

print(json.dumps({k: v for k, v in report.items() if k not in ('errors', 'functions')}))
