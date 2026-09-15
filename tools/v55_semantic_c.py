#!/usr/bin/env python3
"""V5.5 ARM64-grounded semantic C reconstruction.

This stage deliberately treats ARM64 as ground truth. High/Raw P-code remain evidence
for data-flow, but semantic C is rebuilt from basic blocks and ARM64 instructions so
branches, flags, SIMD/FP operations, ABI arguments, and exact addresses stay visible.

Outputs are analysis views, never claimed to be original source code.
"""
import csv, html, json, re, struct, sys
from bisect import bisect_right
from collections import defaultdict
from pathlib import Path

if len(sys.argv) not in (2,3):
    raise SystemExit('usage: v55_semantic_c.py <analysis-output-dir> [analyzed-elf]')
root=Path(sys.argv[1]); elf_path=Path(sys.argv[2]) if len(sys.argv)==3 else None
human=root/'human'; outdir=human/'semantic_c'; compactdir=human/'semantic_c_compact'; outdir.mkdir(parents=True,exist_ok=True); compactdir.mkdir(parents=True,exist_ok=True)

def rows(name):
    p=root/name
    if not p.exists() or not p.stat().st_size:return []
    with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))
def canon(v):
    v=(v or '').strip();v=v[2:] if v.lower().startswith('0x') else v
    try:return f'{int(v,16):08X}'
    except:return v.upper()
def hx(v):
    try:return int(canon(v),16)
    except:return None
def safe(v):return (re.sub(r'[^A-Za-z0-9._-]+','_',v or 'function').strip('_') or 'function')[:100]
def cstr(s):return json.dumps(s,ensure_ascii=False)

def load_base():
    p=human/'ida'/'metadata.json'
    if p.exists():
        try:return int(json.loads(p.read_text(encoding='utf-8'))['ghidra_image_base'],16)
        except Exception:pass
    return 0
BASE=load_base()
def rva(ga):return ga-BASE
def rh(ga):return f'{rva(ga):08X}'

selected={canon(r.get('entry')):r for r in rows('v52_selected_functions.csv') if canon(r.get('entry'))}
functions={canon(r.get('entry')):r for r in rows('functions.csv') if canon(r.get('entry'))}

# -------- string database: Ghidra strings + optional direct ELF scan --------
str_items=[]
def clean_string(v):
    v=(v or '').strip()
    if v.startswith('u8"') and v.endswith('"'):v=v[2:]
    if len(v)>=2 and v[0]=='"' and v[-1]=='"':v=v[1:-1]
    return v.replace('\\n','\n').replace('\\t','\t')
for q in rows('strings.csv'):
    a=hx(q.get('address'));s=clean_string(q.get('value'))
    if a is not None and s:
        str_items.append((a,a+max(1,len(s.encode('utf-8',errors='ignore'))),s,'GHIDRA_STRING'))

def scan_elf_strings(path):
    result=[]
    if not path or not path.exists():return result
    try:
        from elftools.elf.elffile import ELFFile
        with path.open('rb') as f:
            ef=ELFFile(f)
            segs=[]
            for seg in ef.iter_segments():
                if seg['p_type']=='PT_LOAD':
                    segs.append((int(seg['p_offset']),int(seg['p_offset'])+int(seg['p_filesz']),int(seg['p_vaddr'])))
            f.seek(0); blob=f.read()
        rx=re.compile(rb'[\x20-\x7e]{4,}\x00')
        for m in rx.finditer(blob):
            off=m.start();va=None
            for a,b,v in segs:
                if a<=off<b:
                    va=v+(off-a)+BASE;break
            if va is None:continue
            try:s=m.group()[:-1].decode('utf-8')
            except:s=m.group()[:-1].decode('latin-1','replace')
            result.append((va,va+len(m.group())-1,s,'ELF_ASCII_SCAN'))
    except Exception as ex:
        (root/'v55_semantic_string_scan_warning.txt').write_text(str(ex),encoding='utf-8')
    return result
str_items.extend(scan_elf_strings(elf_path))
# dedupe exact address/value, prefer Ghidra label when same
uniq={}
for it in str_items:
    key=(it[0],it[2]);
    if key not in uniq or it[3]=='GHIDRA_STRING':uniq[key]=it
str_items=sorted(uniq.values(),key=lambda x:(x[0],x[1]-x[0]))
str_starts=[x[0] for x in str_items]
def resolve_string(addr):
    if addr is None:return None
    i=bisect_right(str_starts,addr)-1
    candidates=[]
    for j in range(max(0,i-3),min(len(str_items),i+4)):
        a,b,s,src=str_items[j]
        if a<=addr<b:
            delta=addr-a
            # ARM64 often points into a larger printable run. Slice at interior address.
            ss=s[delta:] if delta < len(s) else ''
            if ss:candidates.append((delta,len(ss),ss,src,a))
    if not candidates:return None
    delta,_,ss,src,a=min(candidates,key=lambda x:(x[0]!=0,x[0],x[1]))
    return {'value':ss,'source':src,'string_start':a,'delta':delta,'exact':delta==0}

# -------- calls/xrefs/CFG --------
calls_at=defaultdict(list)
for q in rows('callgraph.csv'):
    a=canon(q.get('callsite'))
    if a:calls_at[a].append(q.get('callee_name') or q.get('callee_entry') or '')
str_xref=defaultdict(list)
for q in rows('string_xrefs.csv'):
    a=canon(q.get('from_address'));s=clean_string(q.get('value'))
    if a and s and s not in str_xref[a]:str_xref[a].append(s)
blocks=defaultdict(list); blockmeta=defaultdict(dict)
for q in rows('v55_cfg_blocks.csv'):
    e=canon(q.get('function_entry'));b=canon(q.get('block_address'))
    if e and b:
        blocks[e].append(int(b,16));blockmeta[(e,int(b,16))]=q
for e in blocks:blocks[e]=sorted(set(blocks[e]))
edges=defaultdict(list)
for q in rows('v5_clean_edges.csv'):
    e=canon(q.get('function_entry'));a=hx(q.get('from_block'));b=hx(q.get('to_block'))
    if e and a is not None and b is not None:edges[(e,a)].append((b,q.get('edge_type') or ''))

# -------- parse full ARM64 listings --------
ASM_RE=re.compile(r'^\.text:([0-9A-Fa-f]{16})\s+(?:(?:(?:[0-9A-Fa-f]{2}\s+){4})\s*)?([A-Za-z0-9.]+)\s*(.*)$')
asm_by_fn={}
for p in (human/'asm_full').glob('*.asm') if (human/'asm_full').exists() else []:
    # complete-view filename contains ghidra entry as second underscore field
    m=re.match(r'[0-9A-Fa-f]+_([0-9A-Fa-f]+)_',p.name)
    if not m:continue
    e=canon(m.group(1));ins=[]
    for line in p.read_text(encoding='utf-8',errors='replace').splitlines():
        mm=ASM_RE.match(line)
        if not mm:continue
        ga=int(mm.group(1),16);mn=mm.group(2).upper();tail=mm.group(3)
        # Keep original annotation separately, parse operands before ';'.
        op=tail.split(';',1)[0].strip();ann=tail[len(op):].lstrip(' ;') if ';' in tail else ''
        ins.append({'a':ga,'mn':mn,'op':op,'ann':ann,'line':line})
    if ins:asm_by_fn[e]=ins

REG_ALIAS_RE=re.compile(r'^(?:[wx]([0-9]+)|sp|xzr|wzr)$',re.I)
def regkey(s):
    s=s.strip().lower()
    m=REG_ALIAS_RE.match(s)
    if not m:return s
    if s in ('sp','xzr','wzr'):return s
    return 'x'+m.group(1)
def splitops(s):
    out=[];cur='';depth=0
    for ch in s:
        if ch in '[{(':depth+=1
        elif ch in ']})':depth=max(0,depth-1)
        if ch==',' and depth==0:out.append(cur.strip());cur=''
        else:cur+=ch
    if cur.strip():out.append(cur.strip())
    return out
def imm(s):
    s=s.strip().lower().replace('#','')
    aliases={'-1.0':'-1.0','0.5':'0.5','30.0':'30.0'}
    if s in aliases:return aliases[s]
    try:return str(int(s,0))
    except:return None
def memexpr(op,expr):
    m=re.match(r'\[\s*([^,\]]+)(?:,\s*#?([^\]]+))?\]',op)
    if not m:return op
    b=m.group(1).strip();off=m.group(2);base=expr.get(regkey(b),b)
    if not off:return f'({base})'
    try:n=int(off,0);sg='+' if n>=0 else '-';return f'({base} {sg} 0x{abs(n):X})'
    except:return f'({base} + {off})'
def ccond(cond,lhs,rhs):
    mp={'EQ':'==','NE':'!=','LT':'<','LE':'<=','GT':'>','GE':'>=','LO':'<','LS':'<=','HI':'>','HS':'>=','MI':'< 0 /*N*/','PL':'>= 0 /*N*/'}
    c=cond.upper()
    if c in ('MI','PL'):return f'({lhs} {mp[c]})'
    if c in mp:return f'({lhs} {mp[c]} {rhs})'
    return f'condition_{c.lower()} /* flags from CMP {lhs}, {rhs} */'
def target_rva(op):
    m=re.search(r'(?:loc_|sub_|LAB_)?([0-9A-Fa-f]{5,16})',op)
    if not m:return op
    x=int(m.group(1),16)
    # labels in complete ARM64 are Ghidra VA
    if x>=BASE:return f'loc_{x-BASE:08X}'
    return f'loc_{x:08X}'
def varname(r):
    r=r.strip().lower()
    if r=='sp':return 'sp'
    if r in ('xzr','wzr'):return '0'
    return r.replace('.','_').replace('[','_').replace(']','')
def reg_mem_type(r):
    r=(r or '').strip().lower()
    if r.startswith('w'):return 'uint32_t',4
    if r.startswith('x') or r in ('sp','xzr'):return 'uint64_t',8
    if r.startswith('s'):return 'float',4
    if r.startswith('d'):return 'double',8
    if r.startswith(('q','v')):return 'arm64_vec128_t',16
    return 'uintptr_t',8
def simd_expr(r,expr):return expr.get(r.lower(),varname(r))

def fp_imm(reg, token):
    t=(token or '').strip().lower().replace('#','')
    try:
        if t.startswith('0x'):
            n=int(t,16)
            if reg.lower().startswith(('s','v')) and n<=0xffffffff:
                return repr(struct.unpack('>f',n.to_bytes(4,'big'))[0])+'f'
            if reg.lower().startswith('d') and n<=0xffffffffffffffff:
                return repr(struct.unpack('>d',n.to_bytes(8,'big'))[0])
        float(t); return t+('f' if reg.lower().startswith(('s','v')) else '')
    except:return None

def compact_view(detailed):
    out=[]
    for line in detailed.splitlines():
        st=line.strip()
        if st.startswith('/* ARM64-GROUNDED') or st.startswith('* Ground truth') or st.startswith('* P-code') or st.startswith('* This is') or st.startswith('* Function:') or st=='*/' or st.startswith('void semantic_') or st=='}':out.append(line);continue
        if st.startswith('loc_') or st.startswith('/* successors:'):out.append(line);continue
        if any(k in st for k in ('if (','goto loc_','return;','recovered string','recovered interior string','CINC + ASR','ARM64_')):out.append(line);continue
        if st.startswith('*('):out.append(line);continue
        if '(); /* observed ABI args:' in st:
            m=re.match(r'([A-Za-z0-9_.$]+)\(\); /\* observed ABI args: (.*?) \*/(.*)',st)
            if m:out.append('  '+m.group(1)+'(/* '+m.group(2)+' */);'+m.group(3));continue
        if re.match(r'[A-Za-z0-9_]+\(\);',st):out.append(line);continue
        if any(x in st for x in (' / 2;',' + 1.0f',' * 0.5f','STRING_XREF')):out.append(line)
    return '\n'.join(out)+'\n'

def translate_function(e,name,ins):
    starts=blocks.get(e) or [ins[0]['a']]
    starts=sorted(x for x in starts if ins[0]['a']<=x<=ins[-1]['a'])
    if ins[0]['a'] not in starts:starts=[ins[0]['a']]+starts
    byblock=defaultdict(list);si=0
    for q in ins:
        while si+1<len(starts) and q['a']>=starts[si+1]:si+=1
        byblock[starts[si]].append(q)
    out=[];recovered=[];stmt_count=0;branch_count=0;fold_count=0;simd_count=0;call_count=0
    out.append('/* ARM64-GROUNDED SEMANTIC C VIEW')
    out.append(' * Ground truth: human/asm_full listing + CFG edges.')
    out.append(' * P-code is supporting data-flow evidence only.')
    out.append(' * This is reconstruction, NOT original source code.')
    out.append(f' * Function: {name}; IDA/RVA 0x{rh(int(e,16))}; Ghidra VA 0x{e}')
    out.append(' */')
    out.append(f'void semantic_{safe(name)}(void) {{')
    for bs in starts:
        qs=byblock.get(bs,[])
        if not qs:continue
        meta=blockmeta.get((e,bs),{});succ=edges.get((e,bs),[])
        out.append('')
        out.append(f'loc_{rh(bs)}: /* Ghidra 0x{bs:08X}; CFG out={len(succ)} dom_depth={meta.get("dom_depth","")} scc={meta.get("scc_id","")} */')
        if succ:out.append('  /* successors: '+', '.join(f'{typ}->loc_{rh(dst)}' for dst,typ in succ)+' */')
        expr={'sp':'sp'};const={};last_cmp=None;pending_div2={};dirty=set()
        def setreg(r,x,c=None):
            k=regkey(r);expr[k]=x
            if c is None:const.pop(k,None)
            else:const[k]=c
            rr=r.lower();
            if re.match(r'^[xw][0-7]$',rr):dirty.add(regkey(rr))
            elif re.match(r'^[sd][0-7]$',rr):dirty.add(rr)
        def emit(s,a=None):
            nonlocal stmt_count
            if a is not None:s+=f' /* IDA/RVA 0x{rh(a)} */'
            out.append('  '+s);stmt_count+=1
        for q in qs:
            a,mn,op=q['a'],q['mn'],q['op'];o=splitops(op)
            # string-xref annotations from Ghidra are still useful even before address synthesis.
            for s in str_xref.get(f'{a:08X}',[]):emit(f'/* STRING_XREF {cstr(s)} */',a)
            if mn in ('ADRP','ADR') and len(o)>=2:
                d=o[0];iv=imm(o[1])
                if iv is not None:
                    n=int(float(iv));setreg(d,f'0x{n:X}',n);emit(f'{varname(d)} = (uintptr_t)0x{n:X};',a)
                else:emit(f'/* {mn} {op} */',a)
            elif mn in ('MOV','MOVZ') and len(o)>=2:
                d,s=o[0],o[1];sv=0 if s.lower() in ('xzr','wzr') else (int(imm(s)) if imm(s) is not None and '.' not in imm(s) else None)
                x='0' if sv==0 else (f'0x{sv:X}' if sv is not None else expr.get(regkey(s),varname(s)))
                setreg(d,x,sv);emit(f'{varname(d)} = {x};',a)
            elif mn=='MOVK' and len(o)>=2:
                d=o[0];v=int(imm(o[1]) or '0');shift=0
                if len(o)>=3:
                    mm=re.search(r'#?(\d+)',o[2]);shift=int(mm.group(1)) if mm else 0
                k=regkey(d);old=const.get(k)
                if old is not None:
                    mask=0xFFFF<<shift;n=(old & ~mask)|((v&0xFFFF)<<shift);setreg(d,f'0x{n:X}',n);emit(f'{varname(d)} = 0x{n:X};',a)
                else:emit(f'{varname(d)} = movk({varname(d)}, 0x{v:X}, {shift});',a)
            elif mn in ('ORR','EOR','AND') and len(o)>=3:
                d,sr,t=o[0],o[1],o[2];sx='0' if sr.lower() in ('xzr','wzr') else expr.get(regkey(sr),varname(sr));ti=imm(t);tx=(f'0x{int(ti):X}' if ti is not None and '.' not in ti else expr.get(regkey(t),varname(t)));opx={'ORR':'|','EOR':'^','AND':'&'}[mn]
                if sr.lower() in ('xzr','wzr') and mn=='ORR':x=tx
                else:x=f'({sx} {opx} {tx})'
                cv=(int(ti) if sr.lower() in ('xzr','wzr') and mn=='ORR' and ti is not None and '.' not in ti else None);setreg(d,x,cv);emit(f'{varname(d)} = {x};',a)
            elif mn in ('ADDS','SUBS') and len(o)>=3:
                d,sr,t=o[0],o[1],o[2];sx=expr.get(regkey(sr),varname(sr));ti=imm(t);tx=(str(int(ti)) if ti is not None and '.' not in ti else expr.get(regkey(t),varname(t)));opx='+' if mn=='ADDS' else '-';x=f'({sx} {opx} {tx})';setreg(d,x);last_cmp=(sx,tx,regkey(sr));emit(f'{varname(d)} = {x}; /* flags from {mn} */',a)
            elif mn in ('ADD','SUB') and len(o)>=3:
                d,s,t=o[0],o[1],o[2];k=regkey(s);base=expr.get(k,varname(s));ti=imm(t)
                if ti is not None and '.' not in ti:
                    n=int(ti);x=f'({base} {"+" if mn=="ADD" else "-"} {n})';cv=(const.get(k)+(n if mn=='ADD' else -n)) if k in const else None
                    rs=resolve_string(cv)
                    if rs and mn=='ADD':
                        x=cstr(rs['value']);recovered.append({'instruction_address':f'{a:08X}','target_address':f'{cv:08X}','value':rs['value'],'source':rs['source'],'interior_delta':rs['delta']})
                        emit(f'/* recovered {"interior " if rs["delta"] else ""}string @0x{cv:08X}: {cstr(rs["value"])} */',a)
                    setreg(d,x,cv)
                    emit(f'{varname(d)} = {x};',a)
                else:
                    tx=expr.get(regkey(t),varname(t));x=f'({base} {"+" if mn=="ADD" else "-"} {tx})';setreg(d,x);emit(f'{varname(d)} = {x};',a)
            elif mn in ('LDR','LDUR','LDRB','LDRH','LDARB') and len(o)>=2:
                d=o[0];me=memexpr(o[1],expr);ty,sz=reg_mem_type(d)
                if mn in ('LDRB','LDARB'):ty='uint8_t'
                elif mn=='LDRH':ty='uint16_t'
                if d.lower().startswith(('q','v')):simd_count+=1
                x=f'*({ty}*){me}';setreg(d,x);emit(f'{varname(d)} = {x};',a)
            elif mn=='LDP' and len(o)>=3:
                d1,d2=o[0],o[1];me=memexpr(o[2],expr);ty1,sz1=reg_mem_type(d1);ty2,_=reg_mem_type(d2)
                x1=f'*({ty1}*){me}';x2=f'*({ty2}*)((uintptr_t){me} + {sz1})';setreg(d1,x1);setreg(d2,x2);emit(f'{varname(d1)} = {x1}; {varname(d2)} = {x2};',a)
                if d1.lower().startswith(('s','d','q','v')) or d2.lower().startswith(('s','d','q','v')):simd_count+=1
            elif mn in ('STR','STUR','STRB','STRH') and len(o)>=2:
                src=o[0];me=memexpr(o[1],expr);sx='0' if src.lower() in ('xzr','wzr') else expr.get(regkey(src),expr.get(src.lower(),varname(src)))
                ty,_=reg_mem_type(src)
                if mn=='STRB':ty='uint8_t'
                elif mn=='STRH':ty='uint16_t'
                emit(f'*({ty}*){me} = {sx};',a)
            elif mn=='STP' and len(o)>=3 and '!' not in o[2]:
                s1,s2=o[0],o[1];me=memexpr(o[2],expr);ty1,sz1=reg_mem_type(s1);ty2,_=reg_mem_type(s2);x1='0' if s1.lower() in ('xzr','wzr') else expr.get(regkey(s1),expr.get(s1.lower(),varname(s1)));x2='0' if s2.lower() in ('xzr','wzr') else expr.get(regkey(s2),expr.get(s2.lower(),varname(s2)));emit(f'*({ty1}*){me} = {x1}; *({ty2}*)((uintptr_t){me} + {sz1}) = {x2};',a)
            elif mn=='CMP' and len(o)>=2:
                lhs=expr.get(regkey(o[0]),varname(o[0]));rhs=(str(int(imm(o[1]))) if imm(o[1]) is not None and '.' not in imm(o[1]) else expr.get(regkey(o[1]),varname(o[1])));last_cmp=(lhs,rhs,regkey(o[0]));emit(f'/* flags = CMP({lhs}, {rhs}); */',a)
            elif mn=='CINC' and len(o)>=3:
                d,s,cc=o[0],o[1],o[2].lower();k=regkey(d);sx=expr.get(regkey(s),varname(s))
                if cc=='lt' and last_cmp and last_cmp[2]==regkey(s) and last_cmp[1]=='0':
                    # Defer so ASR #1 can fold the canonical signed divide-by-two idiom.
                    pending_div2[k]=(len(out),sx,a);out.append('  /* pending CINC<0 for signed /2 fold */')
                    expr[k]=f'(({sx}) < 0 ? ({sx}) + 1 : ({sx}))'
                else:
                    setreg(d,f'cinc_{cc}({sx})');emit(f'{varname(d)} = cinc_{cc}({sx});',a)
            elif mn=='ASR' and len(o)>=3:
                d,s,sh=o[0],o[1],o[2];k=regkey(d);n=int(imm(sh) or '0');sx=expr.get(regkey(s),varname(s))
                if n==1 and k in pending_div2 and regkey(s)==k:
                    idx,orig,aa=pending_div2.pop(k);out[idx]=f'  {varname(d)} = ((int32_t)({orig})) / 2; /* CINC + ASR => trunc toward zero; IDA/RVA 0x{rh(aa)}..0x{rh(a)} */';expr[k]=f'((int32_t)({orig}) / 2)';fold_count+=1;stmt_count+=1
                else:setreg(d,f'((int32_t)({sx}) >> {n})');emit(f'{varname(d)} = ((int32_t)({sx}) >> {n});',a)
            elif mn=='SCVTF' and len(o)>=2:
                d,s=o[0],o[1];sx=expr.get(regkey(s),varname(s));x=f'(float)(int32_t)({sx})';expr[d.lower()]=x;emit(f'{varname(d)} = {x};',a)
            elif mn=='FCVT' and len(o)>=2:
                d,s=o[0],o[1];sx=expr.get(s.lower(),varname(s));expr[d.lower()]=f'(double)({sx})';emit(f'{varname(d)} = (double)({sx});',a)
            elif mn=='FCMP' and len(o)>=2:
                lhs=expr.get(o[0].lower(),varname(o[0]));rhs=(fp_imm(o[0],o[1]) or expr.get(o[1].lower(),varname(o[1])));last_cmp=(lhs,rhs,o[0].lower());emit(f'/* flags = FCMP({lhs}, {rhs}); */',a)
            elif mn=='DUP' and len(o)>=2:
                d,sr=o[0],o[1];sx=expr.get(regkey(sr),varname(sr));x=f'splat({sx})';expr[d.lower()]=x;emit(f'{varname(d)} = {x};',a);simd_count+=1
            elif mn=='FMOV' and len(o)>=2:
                d,s=o[0],o[1];x=fp_imm(d,s) or expr.get(s.lower(),varname(s));expr[d.lower()]=x;dirty.add(d.lower());emit(f'{varname(d)} = {x};',a)
            elif mn in ('FADD','FSUB','FMUL','FDIV') and len(o)>=3:
                d,s,t=o[0],o[1],o[2];sx=simd_expr(s,expr);tx=simd_expr(t,expr);opx={'FADD':'+','FSUB':'-','FMUL':'*','FDIV':'/'}[mn];x=f'({sx} {opx} {tx})'
                x=x.replace('- -1.0f','+ 1.0f');expr[d.lower()]=x;dirty.add(d.lower());emit(f'{varname(d)} = {x};',a);simd_count+=1 if d.lower().startswith(('v','q')) else 0
            elif mn=='MOVI' and len(o)>=2:
                d=o[0];vv=fp_imm(d,o[1]) or o[1];x=f'splat({vv})';expr[d.lower()]=x;emit(f'{varname(d)} = {x};',a);simd_count+=1
            elif mn in ('CBZ','CBNZ') and len(o)>=2:
                s,t=o[0],o[1];sx=expr.get(regkey(s),varname(s));emit(f'if ({sx} {"==" if mn=="CBZ" else "!="} 0) goto {target_rva(t)};',a);branch_count+=1
            elif mn in ('TBZ','TBNZ') and len(o)>=3:
                s,b,t=o[0],o[1],o[2];sx=expr.get(regkey(s),varname(s));bn=int(imm(b) or '0');test=f'(({sx} >> {bn}) & 1)';emit(f'if ({test} {"==" if mn=="TBZ" else "!="} 0) goto {target_rva(t)};',a);branch_count+=1
            elif mn.startswith('B.') and len(o)>=1:
                cc=mn.split('.',1)[1];lhs,rhs=last_cmp[:2] if last_cmp else ('flags_lhs','flags_rhs');emit(f'if {ccond(cc,lhs,rhs)} goto {target_rva(o[0])};',a);branch_count+=1
            elif mn=='B' and o:
                emit(f'goto {target_rva(o[0])};',a);branch_count+=1
            elif mn in ('BL','BLR'):
                tgt=o[0] if o else '<indirect>';args=[]
                # Only show argument registers written in this block since previous call.
                for ar in ['x0','x1','x2','x3','x4','x5','x6','x7','s0','s1','s2','s3']:
                    if ar in dirty:
                        val=expr.get(ar,varname(ar));args.append(f'{ar}={val}')
                emit(f'{tgt}();'+((' /* observed ABI args: '+', '.join(args)+' */') if args else ''),a);call_count+=1;dirty.clear();
                # Version return values by callsite/target so comparisons never collapse two distinct calls.
                rt=safe(tgt).lower();expr['x0']=f'{rt}_ret_x0_{rh(a)}';expr['s0']=f'{rt}_ret_s0_{rh(a)}';const.pop('x0',None)
            elif mn=='RET':emit('return;',a);branch_count+=1
            elif mn in ('CSET','CSETM') and len(o)>=2:
                d,cc=o[0],o[1];lhs,rhs=last_cmp[:2] if last_cmp else ('flags_lhs','flags_rhs');x=ccond(cc,lhs,rhs);setreg(d,x);emit(f'{varname(d)} = {x};',a)
            elif mn in ('NOP',):emit('/* nop */',a)
            else:
                # Keep unsupported instructions explicit, especially NEON/FP, rather than inventing semantics.
                emit(f'ARM64_{mn}({op}); /* exact instruction preserved; semantic lowering unavailable */',a)
                if any(x in mn for x in ('V','F')) or any(z.lower().startswith(('v','q')) for z in o):simd_count+=1
        # Any deferred CINC not followed by ASR is emitted honestly.
        for k,(idx,orig,aa) in pending_div2.items():
            out[idx]=f'  {k} = ((int32_t)({orig}) < 0) ? ({orig}) + 1 : ({orig}); /* CINC.LT; IDA/RVA 0x{rh(aa)} */';stmt_count+=1
    out.append('}')
    return '\n'.join(out)+'\n',{'statements':stmt_count,'branches':branch_count,'idiom_folds':fold_count,'simd_fp_ops':simd_count,'calls':call_count,'blocks':sum(1 for b in starts if byblock.get(b))},recovered

index=[];reports=[];recovered_all=[]
for e,r in sorted(selected.items(),key=lambda kv:int(kv[0],16)):
    ins=asm_by_fn.get(e,[]);name=r.get('name') or functions.get(e,{}).get('name') or f'sub_{e}'
    if not ins:continue
    body,stat,rec=translate_function(e,name,ins);fn=f'{rh(int(e,16))}_{e}_{safe(name)}.c';(outdir/fn).write_text(body,encoding='utf-8');(compactdir/fn).write_text(compact_view(body),encoding='utf-8')
    cfg_n=len(blocks.get(e,[]));coverage=(100.0*stat['blocks']/cfg_n) if cfg_n else 100.0
    item={'ida_rva':rh(int(e,16)),'ghidra_va':e,'name':name,'semantic_c_path':f'semantic_c/{fn}','compact_c_path':f'semantic_c_compact/{fn}','cfg_blocks':cfg_n,'semantic_blocks':stat['blocks'],'cfg_block_coverage_pct':f'{coverage:.2f}',**stat}
    index.append(item);reports.append(item)
    for x in rec:x.update(function_entry=e,function_name=name);recovered_all.append(x)
fields=list(index[0].keys()) if index else ['ida_rva','ghidra_va','name','semantic_c_path']
with (human/'SEMANTIC_C_INDEX.csv').open('w',encoding='utf-8',newline='') as f:
    w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(index)
with (root/'v55_semantic_string_recovery.csv').open('w',encoding='utf-8',newline='') as f:
    fs=['function_entry','function_name','instruction_address','target_address','value','source','interior_delta'];w=csv.DictWriter(f,fieldnames=fs);w.writeheader();w.writerows(recovered_all)
summary={'selected_functions':len(selected),'semantic_c_files':len(index),'cfg_blocks_total':sum(int(x['cfg_blocks']) for x in index),'semantic_blocks_total':sum(int(x['semantic_blocks']) for x in index),'idiom_folds':sum(int(x['idiom_folds']) for x in index),'simd_fp_ops':sum(int(x['simd_fp_ops']) for x in index),'calls':sum(int(x['calls']) for x in index),'recovered_string_refs':len(recovered_all),'elf_string_scan_enabled':bool(elf_path and elf_path.exists()),'missing_functions':[e for e in selected if e not in asm_by_fn]}
(root/'v55_semantic_c_stats.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
(root/'v55_semantic_c_report.md').write_text('# V5.5 ARM64-grounded semantic C\n\n'+''.join(f'- {k.replace("_"," ").title()}: **{v}**\n' for k,v in summary.items() if k!='missing_functions')+'\nARM64 is authoritative. Semantic C preserves block boundaries and branch conditions; unsupported instructions remain explicit ARM64_* operations instead of guessed C.\n',encoding='utf-8')
trs=[]
for x in index:
    trs.append(f'<tr><td><code>{html.escape(x["ida_rva"])}</code></td><td>{html.escape(x["name"])}</td><td>{x["cfg_block_coverage_pct"]}%</td><td>{x["idiom_folds"]}</td><td><a href="{html.escape(x["semantic_c_path"])}">detailed</a> <a href="{html.escape(x["compact_c_path"])}">compact</a></td></tr>')
(human/'V55_SEMANTIC_C.html').write_text('<!doctype html><meta charset="utf-8"><title>ARM64-grounded semantic C</title><style>body{font:15px system-ui;max-width:1200px;margin:auto;padding:20px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:7px;text-align:left}code{font-family:monospace}</style><h1>ARM64-grounded semantic C</h1><p><b>ARM64 is ground truth.</b> This view reconstructs block/control-flow semantics and folds only evidence-backed idioms. Unsupported instructions stay explicit rather than being guessed.</p><table><tr><th>IDA/RVA</th><th>Function</th><th>CFG block coverage</th><th>Idiom folds</th><th>Open</th></tr>'+''.join(trs)+'</table>',encoding='utf-8')
print(json.dumps(summary))
