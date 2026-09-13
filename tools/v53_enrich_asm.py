#!/usr/bin/env python3
import csv, json, re, sys
from collections import defaultdict
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: v53_enrich_asm.py <analysis-output-dir>')
root=Path(sys.argv[1])

def rows(name):
    p=root/name
    if not p.exists() or p.stat().st_size==0:return []
    with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))
def canon(x):
    try:return f'{int((x or "").strip(),16):08X}'
    except:return (x or '').strip().upper()
def sval(v):
    s=(v or '').strip()
    if len(s)>=2 and s[0]=='"' and s[-1]=='"':s=s[1:-1]
    return s
def display(v,limit=180):
    s=sval(v).replace('"','\\"').replace('\n','\\n').replace('\r','\\r').replace('\t','\\t')
    return s if len(s)<=limit else s[:limit-3]+'...'
def label(v,addr):
    words=re.findall(r'[A-Za-z0-9]+',sval(v))
    body=''.join(w[:1].upper()+w[1:] for w in words[:5])[:34]
    return ('a'+body) if body else ('str_'+canon(addr))

xref=defaultdict(list)
for r in rows('string_xrefs.csv'):
    a=canon(r.get('from_address'))
    if a:xref[a].append(r)

line_re=re.compile(r'^(\.text:)([0-9A-Fa-f]{16})(\s+.*)$')
def parse(line):
    m=line_re.match(line)
    if not m:return None
    addr=canon(m.group(2));rest=m.group(3)
    mm=re.search(r'\s(?:[0-9A-Fa-f]{2}\s+){4,8}([A-Za-z][A-Za-z0-9.]*)\s*(.*)$',rest)
    return (addr,(mm.group(1).upper() if mm else ''),(mm.group(2).strip() if mm else ''))
def first_reg(ops):
    m=re.match(r'\s*([XW]\d{1,2}|SP)\b',ops or '',re.I)
    return m.group(1).upper() if m else ''
def char_comment(mnem,ops):
    if mnem not in {'MOV','MOVZ'}:return ''
    p=[x.strip() for x in (ops or '').split(',')]
    if len(p)<2:return ''
    m=re.fullmatch(r'#?(0x[0-9A-Fa-f]+|\d+)',p[1])
    if not m:return ''
    try:v=int(m.group(1),0)
    except:return ''
    if 32<=v<=126:return "'"+chr(v).replace("'","\\'")+"'"
    return ''

def enrich(path):
    text=path.read_text(encoding='utf-8',errors='replace')
    if '; V53_STRING_XREF' in text:
        return {'files':0,'direct':0,'propagated':0,'chars':0}
    lines=text.splitlines();info=[parse(x) for x in lines];extra=defaultdict(list)
    d=p=c=0
    for i,q in enumerate(info):
        if not q:continue
        addr,mnem,ops=q;refs=xref.get(addr,[]);seen=set()
        for r in refs:
            key=(canon(r.get('string_address')),sval(r.get('value')))
            if key in seen:continue
            seen.add(key);d+=1
            extra[i].append(f'V53_STRING_XREF {label(r.get("value"),r.get("string_address"))}@0x{canon(r.get("string_address"))} = "{display(r.get("value"))}"')
        if refs and mnem=='ADD':
            reg=first_reg(ops)
            if reg:
                for j in range(i-1,max(-1,i-5),-1):
                    qq=info[j]
                    if not qq:continue
                    _,qm,qops=qq
                    if qm in {'ADRP','ADR'} and first_reg(qops)==reg:
                        for r in refs[:2]:
                            s=f'V53_STRING_XREF {label(r.get("value"),r.get("string_address"))}@0x{canon(r.get("string_address"))} = "{display(r.get("value"))}"'
                            if s not in extra[j]:extra[j].append(s);p+=1
                        break
        cc=char_comment(mnem,ops)
        if cc and not refs:extra[i].append('V53_CHAR '+cc);c+=1
    out=[]
    for i,line in enumerate(lines):
        if extra.get(i):line=line+' ; '+' | '.join(extra[i][:3])
        out.append(line)
    path.write_text('\n'.join(out)+'\n',encoding='utf-8')
    return {'files':1,'direct':d,'propagated':p,'chars':c}

stats={'asm_files_enriched':0,'direct_string_comments':0,'propagated_adrp_adr_comments':0,'printable_immediate_comments':0}
files=[]
for base in ('v4_selected_ida','v4_giant_regions'):
    p=root/base
    if p.exists():files.extend(sorted(p.rglob('*.asm')))
for f in files:
    s=enrich(f)
    stats['asm_files_enriched']+=s['files'];stats['direct_string_comments']+=s['direct'];stats['propagated_adrp_adr_comments']+=s['propagated'];stats['printable_immediate_comments']+=s['chars']
(root/'v53_string_inline_stats.json').write_text(json.dumps(stats,indent=2),encoding='utf-8')
with (root/'v53_string_inline_report.md').open('w',encoding='utf-8') as w:
    w.write('# V5.3 IDA-like inline string evidence\n\n')
    for k,v in stats.items():w.write(f'- {k.replace("_"," ").title()}: **{v}**\n')
    w.write('\nString comments come from Ghidra `string_xrefs.csv` evidence at the exact instruction address. When that xref is on an `ADD Xn, Xn, #pageoff`, the same string is also copied back to a nearby `ADRP/ADR Xn` base construction, matching the way IDA presents useful string context. Printable MOV immediates receive character comments. No string is invented from proximity alone.\n')
print(json.dumps(stats))
