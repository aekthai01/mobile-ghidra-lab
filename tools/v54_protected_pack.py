#!/usr/bin/env python3
import csv, hashlib, html, json, sys
from pathlib import Path

if len(sys.argv)!=2: raise SystemExit('usage: v54_protected_pack.py <analysis-output-dir>')
root=Path(sys.argv[1]); evid=root/'v54_protected_evidence'; human=root/'human'

def rows(name):
    p=root/name
    if not p.exists() or not p.stat().st_size:return []
    with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))
def canon(x):
    try:return f'{int((x or "").strip(),16):08X}'
    except:return (x or '').strip().upper()
def sha256(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

protected=[r for r in rows('v52_protected_functions.csv') if (r.get('complexity_priority') or '').lower()=='high']
summary=rows('v54_protected_evidence_summary.csv')
by_entry={canon(r.get('entry')):r for r in summary}
missing=[]; bad=[]
for r in protected:
    e=canon(r.get('entry')); s=by_entry.get(e)
    if not s: missing.append(e); continue
    if (s.get('status') or '')!='ok': bad.append((e,s.get('status',''))); continue
    d=root/(s.get('evidence_dir') or '')
    for req in ('full_arm64_strings.asm','raw_pcode.csv.gz','strings.csv','calls.csv','metadata.txt'):
        p=d/req
        if not p.exists() or p.stat().st_size==0: bad.append((e,'missing:'+req))
if missing or bad:
    raise SystemExit('protected evidence validation failed missing=%s bad=%s'%(missing,bad))

# Immutable manifest after validation. This makes accidental loss/corruption visible.
manifest=[]
if evid.exists():
    for p in sorted(x for x in evid.rglob('*') if x.is_file()):
        manifest.append({'path':str(p.relative_to(root)),'bytes':p.stat().st_size,'sha256':sha256(p)})
with (root/'v54_protected_manifest.json').open('w',encoding='utf-8') as f:json.dump(manifest,f,indent=2)
with (root/'v54_protected_manifest.sha256').open('w',encoding='utf-8') as f:
    for r in manifest:f.write(f"{r['sha256']}  {r['path']}\n")

# Human summary only. Full evidence remains untouched in the dedicated artifact.
human.mkdir(exist_ok=True)
css='body{font-family:system-ui,-apple-system,sans-serif;background:#101114;color:#eee;max-width:1100px;margin:auto;padding:16px}a{color:#7db7ff}table{width:100%;border-collapse:collapse}th,td{padding:8px;border-bottom:1px solid #30333a;text-align:left;vertical-align:top}.tag{border:1px solid #555;border-radius:999px;padding:2px 7px}.warn{color:#ffb86c}code{font-family:ui-monospace,monospace}'
parts=[f'<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Protected Evidence V5.4</title><style>{css}</style></head><body>',
'<h1>V5.4 Protected Function Evidence</h1>',
'<p>ฟังก์ชัน protection ระดับสูงทุกตัวถูกเก็บหลักฐานแบบเต็มแยกต่างหาก: ARM64 ทั้งฟังก์ชันพร้อม strings, Raw P-code แบบ gzip, string xrefs, calls และ metadata. Human pack นี้เป็นดัชนีเท่านั้น หลักฐานเต็มอยู่ใน protected artifact จึงไม่ถูกตัดเพื่อทำให้หน้าอ่านง่าย.</p>',
'<p class="warn"><b>หลักการ:</b> protected มาก = ต้องตรวจลึกขึ้น แต่ยังไม่ถือว่าเป็น logic สำคัญจนกว่าจะมี execution/string/call evidence รองรับ.</p>',
'<table><tr><th>#</th><th>Function</th><th>Protection</th><th>Evidence captured</th><th>Strings / Calls</th></tr>']
for i,r in enumerate(protected,1):
    e=canon(r.get('entry')); s=by_entry[e]
    parts.append('<tr><td>%d</td><td><code>%s</code><br><small>0x%s</small></td><td><span class="tag">score %s</span><br>size %s</td><td>%s instructions<br>%s raw P-code ops<br><small>%s</small></td><td>%s string refs<br>%s calls</td></tr>'%(
        i,html.escape(r.get('name','')),e,html.escape(r.get('complexity_priority_score','')),html.escape(r.get('size_bytes','')),
        html.escape(s.get('instructions','')),html.escape(s.get('raw_pcode_ops','')),html.escape(s.get('evidence_dir','')),html.escape(s.get('string_refs','')),html.escape(s.get('calls',''))))
parts+=['</table>',f'<p>High-protection functions validated: <b>{len(protected)}/{len(protected)}</b>. Evidence files hashed: <b>{len(manifest)}</b>.</p>','</body></html>']
(human/'PROTECTED_FUNCTIONS.html').write_text('\n'.join(parts),encoding='utf-8')

stats={'high_protected_functions':len(protected),'validated_high_functions':len(protected),'manifest_files':len(manifest),'manifest_bytes':sum(r['bytes'] for r in manifest)}
(root/'v54_protected_pack_stats.json').write_text(json.dumps(stats,indent=2),encoding='utf-8')
with (root/'v54_protected_pack_report.md').open('w',encoding='utf-8') as f:
    f.write('# V5.4 protected evidence preservation\n\n')
    f.write(f'- High-protection functions: **{len(protected)}**\n- Validated complete evidence: **{len(protected)}**\n- Manifest files: **{len(manifest)}**\n- Protected evidence bytes: **{stats["manifest_bytes"]}**\n\n')
    f.write('Every high-protection function must have full recovered ARM64, unwindowed raw P-code, exact string xrefs, call evidence, and metadata or the workflow fails. Human summaries never replace the full forensic evidence.\n')
print(json.dumps(stats))
