#!/usr/bin/env python3
import bisect
import csv
import json
import re
import sys
from collections import Counter, defaultdict, deque
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: v4_select_targets.py <analysis-output-dir>')

root = Path(sys.argv[1])


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


functions = rows('functions.csv')
callgraph = rows('callgraph.csv')
string_xrefs = rows('string_xrefs.csv')

if not functions:
    raise SystemExit('functions.csv missing or empty')

func_by_entry = {}
starts = []
for r in functions:
    e = canon(r.get('entry'))
    if not e:
        continue
    r['_entry'] = e
    try:
        r['_start_int'] = int(e, 16)
        r['_size_int'] = int(r.get('size_bytes') or 0)
    except ValueError:
        continue
    func_by_entry[e] = r
    starts.append(r['_start_int'])
starts.sort()
start_to_entry = {r['_start_int']: r['_entry'] for r in func_by_entry.values()}

DEFAULT = re.compile(r'(?i)^(?:FUN|SUB|LAB|thunk_FUN)_[0-9a-f]+$')
# Keep seeds narrow. Generic words like "callback" or "native" occur thousands of times in
# OpenSSL/framework code and caused V4.0 to mistake library plumbing for app entry points.
SEED = re.compile(r'(?i)(^Java_|^JNI_OnLoad$|^JNI_OnUnload$|RegisterNatives|Weave|gvraudio)')
FAMILIES = [
    ('openssl_boringssl', re.compile(r'(?i)^(?:SSL_|SSL3_|TLS_|TLS1_|DTLS_|DTLS1_|X509_|ASN1_|EVP_|BIO_|PEM_|RSA_|DSA_|DH_|EC_|ECDSA_|ECDH_|BN_|HMAC_|SHA(?:1|224|256|384|512)?_|MD5_|CRYPTO_|OPENSSL_|OSSL_|ERR_|OBJ_|PKCS\d*_|CMS_|OCSP_|RAND_|CONF_|ENGINE_)')),
    ('libcxx', re.compile(r'(?i)(?:^std::|^__cxx|^__gnu_cxx|^__cxa_|^operator (?:new|delete)|basic_string|basic_ostream|basic_istream|std::__|std::)')),
    ('zlib', re.compile(r'(?i)^(?:inflate|deflate|crc32|adler32|compress2?|uncompress|gz(?:open|read|write|close)|zlibVersion)')),
    ('xhook', re.compile(r'(?i)(?:^xhook_|com_qiyi_xhook|NativeHandler_)')),
    ('protobuf', re.compile(r'(?i)(?:google::protobuf|protobuf::|MessageLite|CodedInputStream|CodedOutputStream)')),
    ('abseil', re.compile(r'(?i)(?:^absl::|absl::)')),
    ('ffmpeg', re.compile(r'(?i)^(?:avcodec_|avformat_|avutil_|avfilter_|avdevice_|sws_|swr_|av_)')),
    ('opus', re.compile(r'(?i)^(?:opus_|silk_)')),
    ('speex', re.compile(r'(?i)^(?:speex_|speexdsp_)')),
    ('webrtc', re.compile(r'(?i)(?:webrtc::|WebRtc|webrtc_)')),
    ('sqlite', re.compile(r'(?i)^sqlite3_')),
    ('curl', re.compile(r'(?i)^curl_(?:easy|multi|share|global|url|mime|slist|form)')),
]


def family_for(name):
    for family, rx in FAMILIES:
        if rx.search(name or ''):
            return family
    return ''


callees = defaultdict(set)
callers = defaultdict(set)
for edge in callgraph:
    a = canon(edge.get('caller_entry'))
    b = canon(edge.get('callee_entry'))
    if a in func_by_entry and b in func_by_entry:
        callees[a].add(b)
        callers[b].add(a)

seeds = set()
for e, r in func_by_entry.items():
    name = r.get('name') or ''
    if SEED.search(name):
        seeds.add(e)

# Fallback only when a stripped target exposes almost no JNI/app names. Avoid known library families.
if len(seeds) < 2:
    for e, r in func_by_entry.items():
        name = r.get('name') or ''
        if name and not DEFAULT.match(name) and not family_for(name):
            seeds.add(e)
            if len(seeds) >= 12:
                break

distance = {}
q = deque((e, 0) for e in seeds)
while q:
    e, d = q.popleft()
    if e in distance and distance[e] <= d:
        continue
    distance[e] = d
    if d >= 4:
        continue
    for n in callees.get(e, ()):
        q.append((n, d + 1))
    for n in callers.get(e, ()):
        q.append((n, d + 1))

entry_by_name = defaultdict(list)
for e, r in func_by_entry.items():
    entry_by_name[r.get('name') or ''].append(e)
string_hits = Counter()
for row in string_xrefs:
    name = (row.get('from_function') or '').strip()
    value = row.get('value') or ''
    if not name:
        continue
    if re.search(r'(?i)(/data/|/sdcard/|android|package|callback|feature|title|login|token|auth|socket|http|jni|native)', value):
        for e in entry_by_name.get(name, ()): string_hits[e] += 1

metrics = defaultdict(lambda: {
    'instruction_count': 0, 'conditional_branches': 0, 'direct_branches': 0,
    'indirect_jumps': 0, 'indirect_calls': 0, 'calls': 0, 'returns': 0,
    'compare_test': 0, 'loads': 0, 'stores': 0, 'bitwise': 0, 'xor': 0,
    'adrp': 0, 'movk': 0, 'state_regs': Counter(),
})

CMP = {'CMP','CMN','TST','CCMP','CCMN'}
COND = {'CBZ','CBNZ','TBZ','TBNZ'}
LOAD_PREFIX = ('LDR','LDP','LDUR','LDXR','LDAXR','LDAR')
STORE_PREFIX = ('STR','STP','STUR','STXR','STLXR','STLR')
INDIRECT_J = {'BR','BRAA','BRAB','BRAAZ','BRABZ'}
INDIRECT_C = {'BLR','BLRAA','BLRAB','BLRAAZ','BLRABZ'}
RET = {'RET','ERET'}
BITWISE = {'AND','ANDS','ORR','ORN','EOR','EON','BIC','BICS','LSL','LSR','ASR','ROR'}
REG = re.compile(r'\b([WX][0-9]{1,2})\b', re.I)


def containing_entry(addr):
    i = bisect.bisect_right(starts, addr) - 1
    if i < 0:
        return None
    s = starts[i]
    e = start_to_entry[s]
    r = func_by_entry[e]
    size = r['_size_int']
    return e if size <= 0 or addr < s + size else None

p = root / 'disassembly.txt'
if p.exists():
    with p.open(encoding='utf-8', errors='replace') as f:
        for line in f:
            parts = line.rstrip('\n').split('\t', 2)
            if len(parts) < 3:
                continue
            try:
                addr = int(parts[0].strip(), 16)
            except ValueError:
                continue
            entry = containing_entry(addr)
            if not entry:
                continue
            text = parts[2].strip()
            if not text:
                continue
            first = text.split(None, 1)
            mnem = first[0].upper()
            ops = first[1] if len(first) > 1 else ''
            m = metrics[entry]
            m['instruction_count'] += 1
            if mnem in COND or mnem.startswith('B.'):
                m['conditional_branches'] += 1
            elif mnem == 'B':
                m['direct_branches'] += 1
            elif mnem in INDIRECT_J:
                m['indirect_jumps'] += 1
            if mnem in INDIRECT_C:
                m['indirect_calls'] += 1; m['calls'] += 1
            elif mnem == 'BL':
                m['calls'] += 1
            if mnem in RET:
                m['returns'] += 1
            if mnem in CMP or mnem in COND:
                m['compare_test'] += 1
                rr = REG.search(ops)
                if rr:
                    m['state_regs'][rr.group(1).upper().replace('X', 'W')] += 1
            if mnem.startswith(LOAD_PREFIX): m['loads'] += 1
            if mnem.startswith(STORE_PREFIX): m['stores'] += 1
            if mnem in BITWISE: m['bitwise'] += 1
            if mnem in {'EOR','EON'}: m['xor'] += 1
            if mnem == 'ADRP': m['adrp'] += 1
            if mnem == 'MOVK': m['movk'] += 1

metric_rows = []
selected_pool = []
for e, r in func_by_entry.items():
    name = r.get('name') or ''
    size = r['_size_int']
    m = metrics[e]
    est_blocks = 1 + m['conditional_branches'] + m['direct_branches'] + m['indirect_jumps'] + m['returns']
    state_reg, state_hits = ('', 0)
    if m['state_regs']:
        state_reg, state_hits = m['state_regs'].most_common(1)[0]

    family = family_for(name)
    third = bool(family)
    d = distance.get(e)
    seed = e in seeds
    named = bool(name and not DEFAULT.match(name))

    score = 0
    reasons = []
    if seed:
        score += 25000; reasons.append('seed')
    if d is not None:
        score += {0:12000,1:6500,2:3200,3:1200,4:400}.get(d, 0); reasons.append(f'distance:{d}')
    if named:
        score += 500
    if string_hits[e]:
        score += min(3000, string_hits[e] * 200); reasons.append(f'app_strings:{string_hits[e]}')
    score += min(5000, m['indirect_jumps'] * 300)
    score += min(3500, m['conditional_branches'] * 10)
    score += min(2500, state_hits * 12)
    score += min(1800, size // 64)
    if m['indirect_jumps']:
        reasons.append(f'indirect:{m["indirect_jumps"]}')
    if state_hits >= 24:
        reasons.append(f'state_like:{state_reg}:{state_hits}')
    if size >= 12000:
        reasons.append(f'large:{size}')
    if third:
        penalty = 7000
        if d is not None and d <= 1: penalty = 1800
        elif d == 2: penalty = 3500
        score -= penalty
        reasons.append(f'third_party:{family}')

    region_mode = (
        size >= 12000 or m['instruction_count'] >= 3500 or est_blocks >= 280 or
        m['conditional_branches'] >= 160 or m['indirect_jumps'] >= 5 or state_hits >= 140
    )
    mode = 'region' if region_mode else 'full'

    row = {
        'entry': e, 'name': name, 'size_bytes': size,
        'instruction_count': m['instruction_count'], 'estimated_blocks': est_blocks,
        'conditional_branches': m['conditional_branches'], 'direct_branches': m['direct_branches'],
        'indirect_jumps': m['indirect_jumps'], 'indirect_calls': m['indirect_calls'],
        'calls': m['calls'], 'returns': m['returns'], 'compare_test': m['compare_test'],
        'loads': m['loads'], 'stores': m['stores'], 'xor': m['xor'], 'bitwise': m['bitwise'],
        'state_register': state_reg, 'state_compare_hits': state_hits,
        'seed_distance': '' if d is None else d, 'app_string_hits': string_hits[e],
        'third_party_family': family, 'third_party': str(third).lower(),
        'score': score, 'recommended_mode': mode, 'reasons': ';'.join(reasons),
    }
    metric_rows.append(row)

    keep = seed or (d is not None and d <= 2) or score >= 2600
    if third and not seed and (d is None or d > 2) and score < 9000:
        keep = False
    if keep:
        selected_pool.append(row)

metric_rows.sort(key=lambda x: (-int(x['score']), x['entry']))
selected_pool.sort(key=lambda x: (-int(x['score']), x['entry']))

selected = []
seen = set()
for row in selected_pool:
    if 'seed' in row['reasons'] and row['entry'] not in seen:
        selected.append(row); seen.add(row['entry'])
for row in selected_pool:
    if len(selected) >= 320: break
    if row['entry'] in seen: continue
    selected.append(row); seen.add(row['entry'])

region_seen = 0
final = []
for row in selected:
    if row['recommended_mode'] == 'region':
        if region_seen >= 90 and 'seed' not in row['reasons']:
            continue
        region_seen += 1
    final.append(row)
selected = final

fields = list(metric_rows[0].keys())
with (root / 'v4_function_metrics.csv').open('w', encoding='utf-8', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(metric_rows)
with (root / 'v4_selected_functions.csv').open('w', encoding='utf-8', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(selected)

summary = {
    'functions': len(metric_rows), 'seeds': len(seeds), 'selected': len(selected),
    'selected_full': sum(1 for r in selected if r['recommended_mode'] == 'full'),
    'selected_region': sum(1 for r in selected if r['recommended_mode'] == 'region'),
    'third_party_named': sum(1 for r in metric_rows if r['third_party'] == 'true'),
    'max_score': metric_rows[0]['score'] if metric_rows else 0,
}
(root / 'v4_triage.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
with (root / 'v4_triage.md').open('w', encoding='utf-8') as w:
    w.write('# V4 selective native triage\n\n')
    w.write('V4 does not decompile every recovered function. It inventories the whole binary, ranks app/JNI paths, suppresses obvious bundled-library noise, and sends giant/flattened routines to region extraction instead of whole-function decompilation.\n\n')
    for k, v in summary.items(): w.write(f'- {k.replace("_", " ").title()}: **{v}**\n')
    w.write('\n## Highest priority\n\n')
    w.write('| # | Score | Entry | Mode | Function | Size | Blocks~ | Indirect | State | Third-party |\n|---:|---:|---|---|---|---:|---:|---:|---|---|\n')
    for i, r in enumerate(selected[:80], 1):
        name = (r['name'] or '').replace('|', '\\|')
        state = f"{r['state_register']}:{r['state_compare_hits']}" if r['state_register'] else ''
        w.write(f"| {i} | {r['score']} | `{r['entry']}` | {r['recommended_mode']} | `{name}` | {r['size_bytes']} | {r['estimated_blocks']} | {r['indirect_jumps']} | {state} | {r['third_party_family']} |\n")

print(json.dumps(summary))
