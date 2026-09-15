#!/usr/bin/env python3
import csv,hashlib,json,re,sys
from pathlib import Path
if len(sys.argv)!=2:raise SystemExit('usage: v55_ai_quality_v3.py <analysis-output-dir>')
root=Path(sys.argv[1]);human=root/'human';sem=human/'semantic_c';compact=human/'semantic_c_compact';errors=[]
def rows(name):
 p=root/name
 if not p.exists():return []
 with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))
def texts(folder):return [p.read_text(encoding='utf-8',errors='replace') for p in folder.glob('*.c')] if folder.exists() else []
idx=rows('human/SEMANTIC_C_INDEX.csv');selected=rows('v52_selected_functions.csv');semtxt=texts(sem);comptxt=texts(compact);joined='\n'.join(semtxt+comptxt)
if len(idx)!=len(selected):errors.append(f'selected/semantic coverage {len(idx)}/{len(selected)}')
prov=sum('Provenance/confidence:' in t for t in semtxt);conf=sum(all(x in t for x in ('EXACT','STRONG','HEURISTIC')) for t in semtxt)
if prov!=len(semtxt):errors.append(f'provenance policy {prov}/{len(semtxt)}')
if conf!=len(semtxt):errors.append(f'confidence policy {conf}/{len(semtxt)}')
asm=list((human/'asm_full').glob('*.asm')) if (human/'asm_full').exists() else []
if len(asm)!=len(selected):errors.append(f'ARM64 ground truth {len(asm)}/{len(selected)}')
noise={k:len(re.findall(rx,joined)) for k,rx in {'int_carry':r'\bint_carry\s*\(','int_scarry':r'\bint_scarry\s*\(','bool_negate':r'\bbool_negate\s*\(','tmp_vars':r'\btmp_[A-Za-z0-9_]+\b','reg_pcode_vars':r'\breg_[0-9]+_[0-9]+\b','raw_call_mem':r'call\s*\(\s*mem_','raw_goto_mem':r'goto\s+mem_'}.items()}
if any(noise.values()):errors.append('P-code noise '+json.dumps(noise,sort_keys=True))
addr_lines={};mod_evidence={}
for t in comptxt:
 for line in t.splitlines():
  m=re.search(r'IDA/RVA 0x([0-9A-Fa-f]+)',line)
  if m:addr_lines.setdefault(int(m.group(1),16),[]).append(line)
  e=re.search(r'V55_ARM64_MODIMM_EVIDENCE\(0x([0-9A-Fa-f]+),\s*0x([0-9A-Fa-f]{8}),',line)
  if e and 'confidence=EXACT' in line:mod_evidence.setdefault(int(e.group(1),16),[]).append(line)
BASE=0x100000;branch_total=branch_ok=call_total=call_ok=mod_total=mod_ok=0
asm_re=re.compile(r'^\.text:[0-9A-Fa-f]{16}\s+(?:(?:[0-9A-Fa-f]{2}\s+){4}\s*)?([A-Za-z0-9.]+)\s*(.*)$',re.I)
for p in asm:
 for line in p.read_text(encoding='utf-8',errors='replace').splitlines():
  m=asm_re.match(line)
  if not m:continue
  mn=m.group(1).upper();op=m.group(2).split(';',1)[0].strip();am=re.search(r'IDA_RVA=0x([0-9A-Fa-f]+)',line,re.I)
  if not am:continue
  a=int(am.group(1),16);ls=addr_lines.get(a,[])
  if mn=='B' or mn.startswith('B.') or mn in ('CBZ','CBNZ','TBZ','TBNZ'):
   mt=re.search(r'(?:loc_)?([0-9A-Fa-f]{5,16})',op,re.I)
   if mt:
    branch_total+=1;x=int(mt.group(1),16);target=x-BASE if x>=BASE else x
    if any(f'loc_{target:08X}' in q for q in ls):branch_ok+=1
  elif mn=='BL':
   call_total+=1;tgt=op.split(',',1)[0].strip()
   if any((tgt+'(').lower() in q.lower() for q in ls):call_ok+=1
  if mn in ('MOVI','MVNI') and re.search(r'\b(?:LSL|MSL)\s*#?(?:8|16|24)\b',op,re.I):
   mod_total+=1
   if mod_evidence.get(a):mod_ok+=1
branch_pct=100*branch_ok/branch_total if branch_total else 100;call_pct=100*call_ok/call_total if call_total else 100
if branch_pct<99.9:errors.append(f'direct branch targets {branch_ok}/{branch_total}={branch_pct:.3f}%')
if call_pct<99.0:errors.append(f'direct calls {call_ok}/{call_total}={call_pct:.3f}%')
if mod_ok!=mod_total:errors.append(f'modified F32 immediates {mod_ok}/{mod_total} exact')
denorm=[]
for m in re.finditer(r'(-?\d+(?:\.\d+)?e-\d+)f',joined,re.I):
 try:v=float(m.group(1))
 except:continue
 if 0<abs(v)<1.17549435e-38:denorm.append(m.group(0))
if denorm:errors.append(f'suspicious denormal splats {len(denorm)}')
stress=next(compact.glob('0019C094_0029C094_*.c'),None);st=stress.read_text(encoding='utf-8',errors='replace') if stress else ''
stress_checks={'raw_0x41000000':'0x41000000' in st,'f32_8':'8.0f' in st,'not_denormal':'9.10844001811131e-44f' not in st,'telegram':'Telegram:' in st and 't.me/VVIPMODS_OFFICIAL' in st,'exit':'Exit' in st,'signed_div2':'CINC + ASR => trunc toward zero' in st,'175_85':' - 175' in st and ' - 85' in st}
if not all(stress_checks.values()):errors.append('stress 0029C094 '+json.dumps(stress_checks,sort_keys=True))
four={'asm_full':(human/'asm_full').is_dir(),'semantic_c':sem.is_dir(),'semantic_c_compact':compact.is_dir(),'raw_ir':(human/'raw_ir').is_dir() or (root/'v51_raw_pcode.csv').exists()}
if not all(four.values()):errors.append('four layers '+json.dumps(four,sort_keys=True))
manifest=[]
try:manifest=json.loads((root/'v54_protected_manifest.json').read_text(encoding='utf-8'))
except:errors.append('V5.4 protected manifest missing/invalid')
verified=0
for e in manifest if isinstance(manifest,list) else []:
 p=root/e.get('path','')
 if p.is_file() and p.stat().st_size==int(e.get('bytes',-1)) and hashlib.sha256(p.read_bytes()).hexdigest()==e.get('sha256'):verified+=1
if len(manifest)!=115 or verified!=115:errors.append(f'V5.4 protected manifest {verified}/{len(manifest)}')
report={'selected':len(selected),'semantic_c':len(idx),'cfg_blocks':len(rows('v55_cfg_blocks.csv')),'provenance':f'{prov}/{len(semtxt)}','confidence_policy':f'{conf}/{len(semtxt)}','arm64_ground_truth':f'{len(asm)}/{len(selected)}','pcode_noise':noise,'direct_branch_targets':f'{branch_ok}/{branch_total}','direct_calls':f'{call_ok}/{call_total}','modified_f32_immediates':f'{mod_ok}/{mod_total}','suspicious_denormal_splats':len(denorm),'stress_0029C094':stress_checks,'four_layers':four,'protected_manifest':f'{verified}/{len(manifest)}','errors':errors,'status':'pass' if not errors else 'fail'}
(root/'v55_ai_quality_v3.json').write_text(json.dumps(report,indent=2),encoding='utf-8');(root/'v55_ai_quality_v3.md').write_text('# V5.5 AI Quality Gate V3\n\n```json\n'+json.dumps(report,indent=2)+'\n```\n',encoding='utf-8');print(json.dumps(report))
if errors:raise SystemExit('V3 quality gate failed: '+'; '.join(errors[:12]))
