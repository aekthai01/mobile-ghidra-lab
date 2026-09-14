#!/usr/bin/env python3
import csv,html,json,math,struct,sys
from collections import Counter
from pathlib import Path
if len(sys.argv)!=3:raise SystemExit('usage: v55_native_data.py <analyzed-elf> <analysis-output-dir>')
elf_path=Path(sys.argv[1]);root=Path(sys.argv[2]);human=root/'human';human.mkdir(exist_ok=True)
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
def entropy(data):
 if not data:return 0.0
 c=Counter(data);n=len(data);return -sum((v/n)*math.log2(v/n) for v in c.values())
def flags(sec):
 f=int(sec['sh_flags']);return ('W' if f&1 else '')+('A' if f&2 else '')+('X' if f&4 else '')
def write_csv(name,data,fields):
 with (root/name).open('w',encoding='utf-8',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(data)
with elf_path.open('rb') as f:
 elf=ELFFile(f);little=elf.little_endian;ptr_size=8 if elf.elfclass==64 else 4;fmt=('<' if little else '>')+('Q' if ptr_size==8 else 'I')
 secs=[];alloc=[]
 for i,s in enumerate(elf.iter_sections()):
  name=s.name or f'<section-{i}>';addr=int(s['sh_addr']);size=int(s['sh_size']);off=int(s['sh_offset']);fl=flags(s);data=b''
  if s['sh_type']!='SHT_NOBITS':
   try:data=s.data()
   except:data=b''
  ent=entropy(data[:min(len(data),4*1024*1024)]) if data else 0.0
  secs.append({'index':i,'name':name,'type':str(s['sh_type']),'address':f'{addr:08X}','offset':off,'size':size,'flags':fl,'entropy':f'{ent:.3f}','sampled_bytes':min(len(data),4*1024*1024)})
  if 'A' in fl and size>0:alloc.append((addr,addr+size,name,fl))
 def target(va):
  for lo,hi,n,fl in alloc:
   if lo<=va<hi:return n,fl
  return '',''
 ptrs=[];runs=[];init=[];interesting={'.rodata','.data','.data.rel.ro','.got','.got.plt','.init_array','.fini_array'}
 for s in elf.iter_sections():
  if s.name not in interesting and not (int(s['sh_flags'])&2 and not int(s['sh_flags'])&4 and int(s['sh_size'])<=2*1024*1024):continue
  if s['sh_type']=='SHT_NOBITS':continue
  try:data=s.data()
  except:continue
  base=int(s['sh_addr']);valid=[]
  for off in range(0,len(data)-ptr_size+1,ptr_size):
   va=struct.unpack_from(fmt,data,off)[0];tn,tfl=target(va)
   if not tn:valid.append(None);continue
   rec={'section':s.name,'slot_address':f'{base+off:08X}','slot_offset':off,'value':f'{va:08X}','target_section':tn,'target_exec':str('X' in tfl).lower(),'target_writable':str('W' in tfl).lower()};ptrs.append(rec);valid.append(rec)
   if s.name in {'.init_array','.fini_array'}:init.append(rec)
  i=0
  while i<len(valid):
   if valid[i] is None:i+=1;continue
   j=i
   while j<len(valid) and valid[j] is not None:j+=1
   if j-i>=3:
    chunk=valid[i:j];ec=sum(1 for x in chunk if x['target_exec']=='true');runs.append({'section':s.name,'start_slot':chunk[0]['slot_address'],'end_slot':chunk[-1]['slot_address'],'entries':len(chunk),'exec_targets':ec,'data_targets':len(chunk)-ec,'classification':'function_pointer_table_candidate' if ec>=max(2,len(chunk)//2) else 'pointer_table_candidate','confidence':'PROBABLE' if len(chunk)>=4 else 'CANDIDATE'})
   i=j
 rels=[]
 for s in elf.iter_sections():
  if not isinstance(s,RelocationSection):continue
  symtab=elf.get_section(s['sh_link']) if int(s['sh_link']) else None
  for r in s.iter_relocations():
   sym='';sv=''
   if symtab is not None and r['r_info_sym']:
    try:z=symtab.get_symbol(r['r_info_sym']);sym=z.name;sv=f'{int(z["st_value"]):08X}'
    except:pass
   rels.append({'reloc_section':s.name,'offset':f'{int(r["r_offset"]):08X}','type':str(r['r_info_type']),'symbol':sym,'symbol_value':sv,'addend':str(r['r_addend']) if s.is_RELA() else ''})
write_csv('v55_native_sections.csv',secs,['index','name','type','address','offset','size','flags','entropy','sampled_bytes'])
write_csv('v55_native_pointers.csv',ptrs,['section','slot_address','slot_offset','value','target_section','target_exec','target_writable'])
write_csv('v55_native_pointer_runs.csv',runs,['section','start_slot','end_slot','entries','exec_targets','data_targets','classification','confidence'])
write_csv('v55_native_init_array.csv',init,['section','slot_address','slot_offset','value','target_section','target_exec','target_writable'])
write_csv('v55_native_relocations.csv',rels,['reloc_section','offset','type','symbol','symbol_value','addend'])
summary={'elf_class':elf.elfclass,'little_endian':little,'sections':len(secs),'alloc_sections':len(alloc),'mapped_pointers':len(ptrs),'pointer_table_candidates':len(runs),'init_fini_entries':len(init),'relocations':len(rels)}
(root/'v55_native_data_report.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
(root/'v55_native_data_report.md').write_text('# V5.5 native data intelligence\n\n'+''.join(f'- {k.replace("_"," ").title()}: **{v}**\n' for k,v in summary.items()),encoding='utf-8')
(human/'V55_NATIVE_DATA.html').write_text(f'<!doctype html><meta charset="utf-8"><h1>V5.5 Native Data Intelligence</h1><p>Mapped pointers: <b>{summary["mapped_pointers"]}</b>; pointer-table candidates: <b>{summary["pointer_table_candidates"]}</b>; relocations: <b>{summary["relocations"]}</b>.</p>',encoding='utf-8')
print(json.dumps(summary))
