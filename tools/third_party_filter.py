#!/usr/bin/env python3
import csv
import json
import re
import sys
from collections import defaultdict, deque
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: third_party_filter.py <analysis-output-dir>')

root = Path(sys.argv[1])


def rows(name):
    p = root / name
    if not p.exists() or p.stat().st_size == 0:
        return []
    with p.open(encoding='utf-8', errors='replace', newline='') as f:
        return list(csv.DictReader(f))

functions = rows('functions.csv')
callgraph = rows('callgraph.csv')
rank_rows = rows('function_rank.csv')
arm64_rows = rows('arm64_function_metrics.csv')
string_xrefs = rows('string_xrefs.csv')

func_by_entry = {(r.get('entry') or '').strip(): r for r in functions if (r.get('entry') or '').strip()}
rank_by_entry = {(r.get('entry') or '').strip().upper(): r for r in rank_rows if (r.get('entry') or '').strip()}
arm_by_entry = {(r.get('entry') or '').strip().upper(): r for r in arm64_rows if (r.get('entry') or '').strip()}

# High-confidence library signatures. These are deliberately conservative: a match lowers
# review priority but never removes the function from the artifact.
FAMILIES = [
    ('openssl_boringssl', re.compile(r'(?i)^(?:SSL_|TLS_|X509_|ASN1_|EVP_|BIO_|PEM_|RSA_|DSA_|DH_|EC_|ECDSA_|ECDH_|BN_|HMAC_|SHA(?:1|224|256|384|512)?_|MD5_|CRYPTO_|OPENSSL_|ERR_|OBJ_|PKCS\d*_|CMS_|OCSP_|RAND_|CONF_|ENGINE_)')),
    ('libcxx', re.compile(r'(?i)(?:^std::|^__cxx|^__gnu_cxx|^__cxa_|^operator (?:new|delete)|basic_string|basic_ostream|basic_istream|std::__|std::)')),
    ('zlib', re.compile(r'(?i)^(?:inflate|deflate|crc32|adler32|compress2?|uncompress|gz(?:open|read|write|close)|zlibVersion)')),
    ('xhook', re.compile(r'(?i)(?:^xhook_|com_qiyi_xhook|NativeHandler_(?:refresh|clear|enableDebug|enableSigSegvProtection))')),
    ('protobuf', re.compile(r'(?i)(?:google::protobuf|protobuf::|MessageLite|CodedInputStream|CodedOutputStream)')),
    ('abseil', re.compile(r'(?i)(?:^absl::|absl::)')),
    ('ffmpeg', re.compile(r'(?i)^(?:avcodec_|avformat_|avutil_|avfilter_|avdevice_|sws_|swr_|av_)')),
    ('opus', re.compile(r'(?i)^(?:opus_|silk_)')),
    ('speex', re.compile(r'(?i)^(?:speex_|speexdsp_)')),
    ('webrtc', re.compile(r'(?i)(?:webrtc::|WebRtc|webrtc_)')),
    ('sqlite', re.compile(r'(?i)^sqlite3_')),
    ('curl', re.compile(r'(?i)^curl_(?:easy|multi|share|global|url|mime|slist|form)')),
]

APP_SEED = re.compile(r'(?i)(^Java_|JNI_OnLoad|JNI_OnUnload|RegisterNatives|Weave|gvraudio)')
DEFAULT_NAME = re.compile(r'(?i)^(?:FUN|SUB|LAB|thunk_FUN)_[0-9a-f]+$')

callees = defaultdict(list)
callers = defaultdict(list)
for edge in callgraph:
    ce = (edge.get('caller_entry') or '').strip()
    te = (edge.get('callee_entry') or '').strip()
    if ce:
        callees[ce].append(edge)
    if te:
        callers[te].append(edge)

seed_entries = set()
for entry, f in func_by_entry.items():
    if APP_SEED.search(f.get('name', '') or ''):
        seed_entries.add(entry)

# Bidirectional graph distance from app/JNI seeds. This protects bundled third-party code that
# sits directly in an app-specific path from being hidden too aggressively.
distance = {}
q = deque((e, 0) for e in seed_entries)
while q:
    entry, depth = q.popleft()
    if entry in distance and distance[entry] <= depth:
        continue
    distance[entry] = depth
    if depth >= 4:
        continue
    for edge in callees.get(entry, []):
        nxt = (edge.get('callee_entry') or '').strip()
        if nxt in func_by_entry:
            q.append((nxt, depth + 1))
    for edge in callers.get(entry, []):
        nxt = (edge.get('caller_entry') or '').strip()
        if nxt in func_by_entry:
            q.append((nxt, depth + 1))

# String evidence that usually indicates app glue rather than pure bundled-library internals.
app_string_hits = defaultdict(int)
for row in string_xrefs:
    fn = (row.get('from_function') or '').strip()
    value = (row.get('value') or '')
    if not fn:
        continue
    if re.search(r'(?i)(Java_|JNI|Weave|gvraudio|/data/|/sdcard/|android|package|callback|feature|title)', value):
        for entry, f in func_by_entry.items():
            if (f.get('name') or '') == fn:
                app_string_hits[entry] += 1

result_rows = []
family_counts = defaultdict(int)
for entry, f in func_by_entry.items():
    name = f.get('name', '') or ''
    family = ''
    confidence = 0
    reason = []
    for fam, rx in FAMILIES:
        if rx.search(name):
            family = fam
            confidence = 95
            reason.append('symbol-pattern')
            break

    d = distance.get(entry)
    app_seed = bool(APP_SEED.search(name))
    if app_seed:
        confidence = 0
        family = ''
        reason = ['app-jni-seed']

    # Internal default names inherit only weak evidence from immediate library-family neighbors.
    if not family and DEFAULT_NAME.match(name):
        neighbor_families = []
        for edge in callees.get(entry, []) + callers.get(entry, []):
            n = (edge.get('callee_name') or edge.get('caller_name') or '')
            for fam, rx in FAMILIES:
                if rx.search(n):
                    neighbor_families.append(fam)
        if neighbor_families:
            dominant = max(set(neighbor_families), key=neighbor_families.count)
            hits = neighbor_families.count(dominant)
            if hits >= 3:
                family = dominant
                confidence = min(75, 45 + hits * 5)
                reason.append(f'neighbor-pattern:{hits}')

    if app_string_hits.get(entry):
        reason.append(f'app-string-hits:{app_string_hits[entry]}')
        confidence = max(0, confidence - min(40, app_string_hits[entry] * 10))

    if d is not None:
        reason.append(f'app-seed-distance:{d}')
        if d <= 1:
            confidence = max(0, confidence - 45)
        elif d == 2:
            confidence = max(0, confidence - 25)
        elif d == 3:
            confidence = max(0, confidence - 10)

    is_third = bool(family and confidence >= 60)
    if is_third:
        family_counts[family] += 1

    base_rank = rank_by_entry.get(entry.upper(), {})
    arm = arm_by_entry.get(entry.upper(), {})
    try:
        base_score = int(base_rank.get('score') or 0)
    except ValueError:
        base_score = 0
    try:
        suspicious = int(arm.get('suspicion_score') or 0)
    except ValueError:
        suspicious = 0

    priority = base_score + suspicious * 20
    priority_reasons = []
    if app_seed:
        priority += 10000
        priority_reasons.append('app-jni-seed')
    if d is not None:
        priority += {0: 5000, 1: 2200, 2: 1000, 3: 400, 4: 100}.get(d, 0)
        priority_reasons.append(f'near-app:d{d}')
    if suspicious:
        priority_reasons.append(f'arm64-suspicion:{suspicious}')
    if app_string_hits.get(entry):
        priority += app_string_hits[entry] * 250
        priority_reasons.append(f'app-strings:{app_string_hits[entry]}')
    if is_third:
        # Do not drop third-party functions. Penalize only when not tightly coupled to app seeds.
        penalty = int(2200 * confidence / 100)
        if d is not None and d <= 2:
            penalty //= 3
        priority -= penalty
        priority_reasons.append(f'third-party-penalty:{family}:{confidence}')

    result_rows.append({
        'entry': entry,
        'name': name,
        'size_bytes': f.get('size_bytes', ''),
        'is_third_party': str(is_third).lower(),
        'third_party_family': family,
        'third_party_confidence': confidence,
        'app_seed_distance': '' if d is None else d,
        'app_string_hits': app_string_hits.get(entry, 0),
        'base_rank_score': base_score,
        'arm64_suspicion_score': suspicious,
        'analysis_priority': priority,
        'classification_reasons': ';'.join(reason),
        'priority_reasons': ';'.join(priority_reasons),
    })

result_rows.sort(key=lambda r: (-int(r['analysis_priority']), r['entry']))
fields = list(result_rows[0].keys()) if result_rows else [
    'entry','name','size_bytes','is_third_party','third_party_family','third_party_confidence',
    'app_seed_distance','app_string_hits','base_rank_score','arm64_suspicion_score',
    'analysis_priority','classification_reasons','priority_reasons'
]

with (root / 'analysis_priority.csv').open('w', encoding='utf-8', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(result_rows)

with (root / 'third_party_functions.csv').open('w', encoding='utf-8', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows([r for r in result_rows if r['is_third_party'] == 'true'])

with (root / 'app_candidate_functions.csv').open('w', encoding='utf-8', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows([r for r in result_rows if r['is_third_party'] != 'true'][:1500])

summary = {
    'functions': len(result_rows),
    'classified_third_party': sum(1 for r in result_rows if r['is_third_party'] == 'true'),
    'app_or_unknown_candidates': sum(1 for r in result_rows if r['is_third_party'] != 'true'),
    'families': dict(sorted(family_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
    'seed_functions': len(seed_entries),
}
(root / 'third_party_report.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')

with (root / 'third_party_report.md').open('w', encoding='utf-8') as w:
    w.write('# Third-party filter / app-code prioritization\n\n')
    w.write('This is a triage filter, not proof of code ownership. Functions are never deleted; likely bundled-library code is only deprioritized.\n\n')
    w.write(f"- Functions: **{summary['functions']}**\n")
    w.write(f"- High-confidence third-party: **{summary['classified_third_party']}**\n")
    w.write(f"- App/unknown candidates: **{summary['app_or_unknown_candidates']}**\n")
    w.write(f"- App/JNI seeds: **{summary['seed_functions']}**\n\n")
    w.write('## Detected families\n\n')
    if family_counts:
        for family, count in sorted(family_counts.items(), key=lambda kv: (-kv[1], kv[0])):
            w.write(f'- `{family}`: **{count}** functions\n')
    else:
        w.write('- No high-confidence family signatures found.\n')
    w.write('\n## Highest-priority functions after filtering\n\n')
    w.write('| # | Priority | Entry | Function | Third party | Distance | ARM64 |\n|---:|---:|---|---|---|---:|---:|\n')
    for i, row in enumerate(result_rows[:80], 1):
        name = row['name'].replace('|', '\\|')
        third = row['third_party_family'] if row['is_third_party'] == 'true' else ''
        w.write(f"| {i} | {row['analysis_priority']} | `{row['entry']}` | `{name}` | {third} | {row['app_seed_distance']} | {row['arm64_suspicion_score']} |\n")
    w.write('\nStart with `analysis_priority.csv`; use `third_party_functions.csv` only to suppress noise, never as a deletion list.\n')

print(json.dumps(summary))
