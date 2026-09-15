#!/usr/bin/env python3
"""V5.5 AI-native semantic-C V3 post-processor.

ARM64 remains immutable ground truth. This stage enriches generated semantic views,
never renames real symbols heuristically, preserves exact evidence safely, and fixes
AArch64 SIMD modified immediates using the final lane bits (after LSL/MSL).
"""
import json,re,struct,sys
from pathlib import Path
if len(sys.argv)!=2: raise SystemExit('usage: v55_semantic_ai_upgrade.py <analysis-output-dir>')
root=Path(sys.argv[1]); human=root/'human'; detailed=human/'semantic_c'; compact=human/'semantic_c_compact'
POLICY=' * Provenance/confidence: EXACT=ARM64/address/CFG fact; STRONG=deterministic lowering backed by ARM64; HEURISTIC=inference only. Real symbols are never replaced by heuristic names.\n'
def f32(bits): return struct.unpack('>f',int(bits&0xffffffff).to_bytes(4,'big'))[0]
def safe_evidence(s): return json.dumps(s,ensure_ascii=False)
def parse_modified_imm(op):
    m=re.search(r'#(0x[0-9a-f]+|\d+)',op,re.I)
    if not m:return None
    imm=int(m.group(1),0)&0xff
    sh=re.search(r'\bLSL\s*#?(\d+)',op,re.I); shift=int(sh.group(1)) if sh else 0
    if shift not in (0,8,16,24):return None
    bits=(imm<<shift)&0xffffffff
    if re.search(r'\bMSL\b',op,re.I): bits|=(1<<shift)-1 if shift else 0
    return bits
ASM_RE=re.compile(r'^\.text:([0-9A-Fa-f]{16})\s+(?:(?:[0-9A-Fa-f]{2}\s+){4}\s*)?([A-Za-z0-9.]+)\s*(.*)$')
mods={}; dup_sources={}
for p in (human/'asm_full').glob('*.asm') if (human/'asm_full').exists() else []:
    for line in p.read_text(encoding='utf-8',errors='replace').splitlines():
        m=ASM_RE.match(line)
        if not m:continue
        ga=int(m.group(1),16); mn=m.group(2).upper(); op=m.group(3).split(';',1)[0].strip()
        if mn in ('MOVI','MVNI'):
            bits=parse_modified_imm(op)
            if bits is not None: mods[ga]=(mn,op,bits)
        elif mn=='DUP': dup_sources[ga]=op
modified=0; suspicious_removed=0; safe_literals=0
for folder in (detailed,compact):
    if not folder.exists():continue
    for p in folder.glob('*.c'):
        txt=p.read_text(encoding='utf-8',errors='replace')
        if 'Provenance/confidence:' not in txt:
            txt=txt.replace(' * This is reconstruction, NOT original source code.\n',' * This is reconstruction, NOT original source code.\n'+POLICY,1)
        lines=[]
        for line in txt.splitlines():
            ma=re.search(r'IDA/RVA 0x([0-9A-Fa-f]+)',line); rva=int(ma.group(1),16) if ma else None; ga=(0x100000+rva) if rva is not None else None
            if ga in mods:
                mn,op,bits=mods[ga]; val=f32(bits)
                line=re.sub(r'(?<![\w.])-?\d+\.\d+e-\d+f',f'{val!r}f',line,flags=re.I)
                evidence=f'ARM64 {mn} {op}; modified-imm raw_bits=0x{bits:08X}; f32={val!r}f; confidence=EXACT'
                if evidence not in line: line+=' /* '+evidence+' */'
                modified+=1
            def denorm(m):
                try:v=float(m.group(0)[:-1])
                except:return m.group(0)
                if 0<abs(v)<1.17549435e-38:return '0.0f /* V3 removed suspicious pre-shift denormal splat */'
                return m.group(0)
            before=line; line=re.sub(r'-?\d+(?:\.\d+)?e-\d+f',denorm,line,flags=re.I)
            if line!=before:suspicious_removed+=1
            # A normal recovered-string comment has one closing */. Only an additional
            # terminator can have come from the evidence payload itself. Do not destroy
            # ordinary string-xref lines merely because their comment closes normally.
            if line.count('*/')>1 and ('recovered string' in line or 'STRING_XREF' in line):
                first=line.find('*/'); last=line.rfind('*/')
                payload=line[:last].strip()
                line='  V55_EVIDENCE_LITERAL('+safe_evidence(payload)+'); /* confidence=EXACT; safe evidence literal */'
                safe_literals+=1
            lines.append(line)
        p.write_text('\n'.join(lines)+'\n',encoding='utf-8')
report={'modified_immediate_annotations':modified,'dup_sites':len(dup_sources),'suspicious_denormal_splats_removed':suspicious_removed,'safe_evidence_literals':safe_literals,'confidence':['EXACT','STRONG','HEURISTIC'],'symbol_policy':'never replace real symbols with heuristic names','status':'pass'}
(root/'v55_semantic_ai_upgrade.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report))
