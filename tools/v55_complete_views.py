#!/usr/bin/env python3
"""Build complete, dual-address human views for V5.5.

Guarantees:
- Every selected function has one C/C-like file.
- Every selected function has a full ARM64 listing.
- Every disassembled instruction is indexed by both ELF/IDA RVA and Ghidra VA.

The C-like fallback is analysis output, not original source code.
"""
import bisect, csv, html, json, re, sys
from collections import defaultdict
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: v55_complete_views.py <analysis-output-dir>')
root = Path(sys.argv[1]); human=root/'human'; c_root=human/'functions_c'; asm_root=human/'asm_full'; page_root=human/'offset_pages'
for p in (human,c_root,asm_root,page_root): p.mkdir(exist_ok=True)

def canon(v):
    v=(v or '').strip(); v=v[2:] if v.lower().startswith('0x') else v
    try:return f'{int(v,16):08X}'
    except:return v.upper()
def rows(name):
    p=root/name
    if not p.exists() or not p.stat().st_size:return []
    with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))
def safe(v):return (re.sub(r'[^A-Za-z0-9._-]+','_',v or 'function').strip('_') or 'function')[:100]
def load_base():
    p=human/'ida'/'metadata.json'
    if p.exists():
        try:return int(json.loads(p.read_text(encoding='utf-8'))['ghidra_image_base'],16)
        except Exception:pass
    return 0
BASE=load_base()
def rva_i(addr):return int(canon(addr),16)-BASE
def fmt_rva(addr):return f'{rva_i(addr):08X}'

selected_rows=rows('v52_selected_functions.csv'); selected={canon(r.get('entry')):r for r in selected_rows if canon(r.get('entry'))}
functions={canon(r.get('entry')):r for r in rows('functions.csv') if canon(r.get('entry'))}

all_ranges=[]; selected_ranges=[]
for e,fn in functions.items():
    try:size=max(1,int(fn.get('size_bytes') or 1))
    except:size=1
    st=int(e,16); en=st+size-1
    all_ranges.append((st,en,e,fn.get('name') or e))
    if e in selected:selected_ranges.append((st,en,e,selected[e].get('name') or fn.get('name') or e))
all_ranges.sort(); selected_ranges.sort(); sel_starts=[x[0] for x in selected_ranges]
def selected_for_addr(ga):
    i=bisect.bisect_right(sel_starts,ga)-1
    if i>=0 and selected_ranges[i][0]<=ga<=selected_ranges[i][1]:return selected_ranges[i]
    return None

strings=defaultdict(list)
for q in rows('string_xrefs.csv'):
    a=canon(q.get('from_address'));v=q.get('value') or ''
    if a and v and v not in strings[a]:strings[a].append(v)
calls=defaultdict(list)
for q in rows('callgraph.csv'):
    a=canon(q.get('callsite'));v=q.get('callee_name') or q.get('callee_entry') or ''
    if a and v and v not in calls[a]:calls[a].append(v)

v4_asm={}
for p in (root/'v4_selected_ida').glob('*.asm') if (root/'v4_selected_ida').exists() else []:
    m=re.match(r'([0-9A-Fa-f]+)_',p.name)
    if m:v4_asm[canon(m.group(1))]=p

dis=root/'disassembly.txt'; offset_index=human/'OFFSET_MAP.txt'; global_by_selected=defaultdict(list); page_handles={}; instruction_rows=0
if not dis.exists():raise SystemExit('disassembly.txt missing')
with dis.open(encoding='utf-8',errors='replace') as f, offset_index.open('w',encoding='utf-8') as cf:
    cf.write('# IDA_RVA GHIDRA_VA PAGE_FILE\n')
    for line in f:
        parts=line.rstrip('\n').split('\t',2)
        if len(parts)<3:continue
        ga_s=canon(parts[0])
        try:ga=int(ga_s,16)
        except:continue
        ia=ga-BASE; fn=parts[1].strip(); inst=parts[2]
        page_start=(max(0,ia)//0x10000)*0x10000; page_name=f'{page_start:08X}-{page_start+0xFFFF:08X}.txt'
        if page_name not in page_handles:
            ph=(page_root/page_name).open('w',encoding='utf-8');ph.write(f'# IDA/RVA page 0x{page_start:08X}-0x{page_start+0xFFFF:08X}; Ghidra image base 0x{BASE:X}\n');page_handles[page_name]=ph
        page_handles[page_name].write(f'IDA/RVA {ia:08X} | GHIDRA {ga_s} | {fn} | {inst}\n')
        cf.write(f'{ia:08X} {ga_s} {page_name}\n');instruction_rows+=1
        sf=selected_for_addr(ga)
        if sf:global_by_selected[sf[2]].append((ga_s,fn,inst))
for h in page_handles.values():h.close()

addr_re=re.compile(r'^(\.text:)([0-9A-Fa-f]{16})(.*)$');asm_files={};asm_line_maps={}
for e,r in sorted(selected.items(),key=lambda kv:int(kv[0],16)):
    name=r.get('name') or functions.get(e,{}).get('name') or e; dest=asm_root/f'{fmt_rva(e)}_{e}_{safe(name)}.asm'; lines=[]; amap={}
    lines += [f'; V5.5 full dual-address ARM64: {name}',f'; IDA/RVA entry=0x{fmt_rva(e)} | Ghidra VA entry=0x{e} | image base=0x{BASE:X}','; Search either address form.']
    src=v4_asm.get(e)
    if src:
        for line in src.read_text(encoding='utf-8',errors='replace').splitlines():
            m=addr_re.match(line)
            if m:
                ga=canon(m.group(2));ia=fmt_rva(ga);out=f'{line} ; IDA_RVA=0x{ia} GHIDRA_VA=0x{ga}';lines.append(out);amap[ga]=out
            else:lines.append(line)
    else:
        for ga,fn,inst in global_by_selected.get(e,[]):
            ia=fmt_rva(ga); extras=[]
            for s in strings.get(ga,[]):extras.append('STRING='+s)
            for c in calls.get(ga,[]):extras.append('CALL='+c)
            out=f'.text:{int(ga,16):016X}  {inst} ; IDA_RVA=0x{ia} GHIDRA_VA=0x{ga}'+((' ; '+' ; '.join(extras)) if extras else '')
            lines.append(out);amap[ga]=out
    dest.write_text('\n'.join(lines)+'\n',encoding='utf-8');asm_files[e]=dest;asm_line_maps[e]=amap

decompiled={}
for p in (root/'v4_decompiled_selected').glob('*') if (root/'v4_decompiled_selected').exists() else []:
    if not p.is_file():continue
    txt=p.read_text(encoding='utf-8',errors='replace');m=re.search(r'entry=([0-9A-Fa-f]+)',txt[:1000])
    if m:decompiled[canon(m.group(1))]=(p,txt)
recon_root=human/'reconstructed_c';reconstructed={p.name.upper():p for p in recon_root.iterdir() if p.is_dir()} if recon_root.exists() else {}
missing=[e for e in selected if e not in decompiled and e not in reconstructed]
raw=defaultdict(list);rp=root/'v51_raw_pcode.csv'
if missing and rp.exists():
    need=set(missing)
    with rp.open(encoding='utf-8',errors='replace',newline='') as f:
        for q in csv.DictReader(f):
            e=canon(q.get('function_entry'))
            if e in need:raw[e].append(q)
OPS={'INT_ADD':'+','INT_SUB':'-','INT_MULT':'*','INT_DIV':'/','INT_SDIV':'/','INT_REM':'%','INT_SREM':'%','INT_AND':'&','INT_OR':'|','INT_XOR':'^','INT_LEFT':'<<','INT_RIGHT':'>>','INT_SRIGHT':'>>','INT_EQUAL':'==','INT_NOTEQUAL':'!=','INT_LESS':'<','INT_SLESS':'<','INT_LESSEQUAL':'<=','INT_SLESSEQUAL':'<=','BOOL_AND':'&&','BOOL_OR':'||','BOOL_XOR':'^'}
VN=re.compile(r'\((register|unique|const|ram),\s*(0x[0-9A-Fa-f]+|[0-9]+),\s*([0-9]+)\)')
def _vn(m):
    sp,off,size=m.group(1),m.group(2),m.group(3)
    if sp=='const':return off
    n=int(off,0)
    if sp=='register' and 0x4000<=n<=0x40F0 and (n-0x4000)%8==0 and (n-0x4000)//8<=30:return f'x{(n-0x4000)//8}'
    if sp=='register':return f'reg_{n:X}_{size}'
    if sp=='unique':return f'tmp_{n:X}_{size}'
    return f'mem_{n:X}_{size}'
def cv(v):
    s=((v or '').strip().replace('\n',' ')[:220] or '/*void*/')
    return VN.sub(_vn,s)
def ins(v):return [cv(x) for x in (v or '').split(' | ') if x.strip()]
def pseudo(q):
    m=(q.get('mnemonic') or '').upper();o=cv(q.get('output'));a=ins(q.get('inputs'))
    if m=='COPY' and a:return f'{o} = {a[0]};'
    if m in OPS and len(a)>=2:return f'{o} = {a[0]} {OPS[m]} {a[1]};'
    if m in {'INT_ZEXT','INT_SEXT','CAST'} and a:return f'{o} = {m.lower()}({a[0]});'
    if m=='LOAD' and a:return f'{o} = MEM[{a[-1]}];'
    if m=='STORE' and len(a)>=2:return f'MEM[{a[-2]}] = {a[-1]};'
    if m=='CALL':return f"call({', '.join(a)});"
    if m=='CALLIND':return f"call_indirect({', '.join(a)});"
    if m=='BRANCH' and a:return f'goto {a[0]};'
    if m=='CBRANCH' and a:return f"if ({a[1] if len(a)>1 else 'condition'}) goto {a[0]};"
    if m=='BRANCHIND' and a:return f'goto *({a[0]});'
    if m=='RETURN':return f"return /* {', '.join(a)} */;"
    if m=='MULTIEQUAL':return f"{o} = phi({', '.join(a)});"
    return f"{o} = {m.lower()}({', '.join(a)});" if o!='/*void*/' else f"{m.lower()}({', '.join(a)});"

index=[]
for e,r in sorted(selected.items(),key=lambda kv:int(kv[0],16)):
    name=r.get('name') or functions.get(e,{}).get('name') or f'sub_{e}';dest=c_root/f'{fmt_rva(e)}_{e}_{safe(name)}.c'
    header='/* Mobile Ghidra Lab V5.5 complete function view.\n * Analysis output, NOT original source code.\n'+f' * Function: {name}\n * IDA/RVA entry: 0x{fmt_rva(e)}\n * Ghidra VA entry: 0x{e}\n * Ghidra image base: 0x{BASE:X}\n * Full ARM64: ../asm_full/{asm_files[e].name}\n */\n\n'
    if e in decompiled:
        source='GHIDRA_DECOMPILE';body=decompiled[e][1]
    elif e in reconstructed:
        source='REGION_RECONSTRUCTION';p=reconstructed[e];pieces=[];ov=p/'overview.c'
        if ov.exists():pieces.append(ov.read_text(encoding='utf-8',errors='replace'))
        for q in sorted(p.glob('region_*.c')):pieces.append('\n/* ===== '+q.name+' ===== */\n'+q.read_text(encoding='utf-8',errors='replace'))
        body='\n'.join(pieces)
    else:
        source='RAW_PCODE_FULL_FUNCTION_FALLBACK';by_addr=defaultdict(list)
        for q in raw.get(e,[]):by_addr[canon(q.get('instruction_address'))].append(q)
        amap=asm_line_maps.get(e,{});addrs=sorted(set(amap)|set(by_addr),key=lambda x:int(x,16));out=[f'void reconstructed_{safe(name)}(void) {{']
        for a in addrs:
            out.append(f'  /* IDA/RVA 0x{fmt_rva(a)} | Ghidra VA 0x{a} */')
            if a in amap:out.append('  /* ARM64: '+amap[a].replace('*/','* /')+' */')
            for s in strings.get(a,[]):out.append('  /* STRING: '+s.replace('*/','* /')+' */')
            for c in calls.get(a,[]):out.append('  /* CALL: '+c.replace('*/','* /')+' */')
            for q in by_addr.get(a,[]):out.append('  '+pseudo(q))
        out.append('}');body='\n'.join(out)+'\n'
    dest.write_text(header+f'/* Representation: {source} */\n\n'+body,encoding='utf-8')
    index.append({'ida_rva':fmt_rva(e),'ghidra_va':e,'name':name,'representation':source,'c_path':f'functions_c/{dest.name}','asm_path':f'asm_full/{asm_files[e].name}'})
with (human/'FUNCTION_C_INDEX.csv').open('w',encoding='utf-8',newline='') as f:
    w=csv.DictWriter(f,fieldnames=index[0].keys());w.writeheader();w.writerows(index)

ranges=[];idxmap={x['ghidra_va']:x for x in index}
for st,en,e,name in all_ranges:
    item={'s':st-BASE,'e':en-BASE,'g':st,'n':name,'sel':e in selected}
    if e in idxmap:item.update({'c':idxmap[e]['c_path'],'a':idxmap[e]['asm_path']})
    ranges.append(item)
lookup=human/'OFFSET_LOOKUP.html';lookup.write_text('''<!doctype html><meta charset="utf-8"><title>V5.5 Offset Lookup</title><style>body{font:16px system-ui;max-width:980px;margin:auto;padding:20px}input{font:20px monospace;padding:12px;width:min(90%,520px)}pre{white-space:pre-wrap;background:#f4f4f4;padding:14px}a{margin-right:16px}</style><h1>V5.5 Offset Lookup</h1><p>Paste IDA/RVA such as <code>19C56C</code>. Prefix <code>g:</code> for Ghidra VA, e.g. <code>g:29C56C</code>.</p><input id="q" placeholder="19C56C"><button onclick="go()">Find</button><pre id="o"></pre><div id="links"></div><script>const BASE='''+str(BASE)+''',R='''+json.dumps(ranges,separators=(',',':'))+''';function n(s){return parseInt(s.trim().replace(/^0x/i,''),16)}function go(){let s=q.value.trim(),g=s.toLowerCase().startsWith('g:');if(g)s=s.slice(2);let x=n(s);if(!Number.isFinite(x)){o.textContent='Invalid hex';return}let rv=g?x-BASE:x,gv=rv+BASE,f=R.find(z=>rv>=z.s&&rv<=z.e),pg=(Math.floor(Math.max(0,rv)/65536)*65536).toString(16).toUpperCase().padStart(8,'0');o.textContent=`IDA/RVA: 0x${rv.toString(16).toUpperCase().padStart(8,'0')}\nGhidra VA: 0x${gv.toString(16).toUpperCase().padStart(8,'0')}\nFunction: ${f?f.n:'not found'}\nOffset page: ${pg}-${(parseInt(pg,16)+65535).toString(16).toUpperCase().padStart(8,'0')}.txt`;links.innerHTML=`<a href="offset_pages/${pg}-${(parseInt(pg,16)+65535).toString(16).toUpperCase().padStart(8,'0')}.txt">Exact offset page</a>`+(f&&f.sel?`<a href="${f.c}">C/C-like</a><a href="${f.a}">Full ARM64</a>`:'')}q.addEventListener('keydown',e=>{if(e.key==='Enter')go()});</script>''',encoding='utf-8')

rows_html=[f"<tr><td>{x['ida_rva']}</td><td>{x['ghidra_va']}</td><td>{html.escape(x['name'])}</td><td>{x['representation']}</td><td><a href='{x['c_path']}'>C</a></td><td><a href='{x['asm_path']}'>ASM</a></td></tr>" for x in index]
(human/'FUNCTIONS_C.html').write_text("<!doctype html><meta charset='utf-8'><title>Complete C coverage</title><style>body{font:14px system-ui;margin:20px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #bbb;padding:6px;text-align:left}</style><h1>Complete selected-function C/C-like coverage</h1><p>Every selected function has C/C-like and full ARM64 views. Addresses are dual IDA/RVA + Ghidra VA.</p><table><tr><th>IDA/RVA</th><th>Ghidra VA</th><th>Function</th><th>Representation</th><th>C</th><th>ARM64</th></tr>"+''.join(rows_html)+"</table>",encoding='utf-8')

stats={'ghidra_image_base':f'{BASE:08X}','selected_functions':len(selected),'c_views':len(index),'decompiler_views':sum(x['representation']=='GHIDRA_DECOMPILE' for x in index),'region_reconstruction_views':sum(x['representation']=='REGION_RECONSTRUCTION' for x in index),'raw_pcode_full_function_fallback_views':sum(x['representation']=='RAW_PCODE_FULL_FUNCTION_FALLBACK' for x in index),'selected_asm_views':len(asm_files),'offset_index_rows':instruction_rows,'offset_page_files':len(list(page_root.glob('*.txt'))),'missing_selected_c_views':[e for e in selected if e not in idxmap],'missing_selected_asm_views':[e for e in selected if e not in asm_files]}
(root/'v55_complete_views_stats.json').write_text(json.dumps(stats,indent=2),encoding='utf-8')
(root/'v55_complete_views_report.md').write_text('# V5.5 complete human views\n\n'+f"- Ghidra image base: **0x{BASE:X}**\n- Selected functions: **{len(selected)}**\n- C/C-like views: **{len(index)}**\n- Ghidra decompiler: **{stats['decompiler_views']}**\n- Region reconstruction: **{stats['region_reconstruction_views']}**\n- Full-function Raw P-code fallback: **{stats['raw_pcode_full_function_fallback_views']}**\n- Full selected ARM64 views: **{len(asm_files)}**\n- Exact dual-address offset rows: **{instruction_rows}**\n- Offset page files: **{stats['offset_page_files']}**\n",encoding='utf-8')
if len(index)!=len(selected) or stats['missing_selected_c_views']:raise SystemExit('selected C coverage incomplete')
if len(asm_files)!=len(selected) or stats['missing_selected_asm_views']:raise SystemExit('selected ARM64 coverage incomplete')
if instruction_rows==0:raise SystemExit('offset index empty')
print(json.dumps(stats))
