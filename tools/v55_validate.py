#!/usr/bin/env python3
import csv,json,sys
from pathlib import Path
if len(sys.argv)!=2:raise SystemExit('usage: v55_validate.py <analysis-output-dir>')
root=Path(sys.argv[1])
def rows(n):
 p=root/n
 if not p.exists() or not p.stat().st_size:return []
 with p.open(encoding='utf-8',errors='replace',newline='') as f:return list(csv.DictReader(f))
def canon(v):
 v=(v or '').strip();v=v[2:] if v.lower().startswith('0x') else v
 try:return f'{int(v,16):08X}'
 except:return v.upper()
pro=[r for r in rows('v52_protected_functions.csv') if (r.get('complexity_priority') or '').lower()=='high'];high={canon(r.get('entry')) for r in pro if canon(r.get('entry'))};v54={canon(r.get('entry')):r for r in rows('v54_protected_evidence_summary.csv') if canon(r.get('entry'))};highp=rows('v51_high_pcode_summary.csv');hp_fn={canon(r.get('function_entry')) for r in highp};cfg={canon(r.get('entry')):r for r in rows('v55_cfg_function_metrics.csv') if canon(r.get('entry'))};recon={canon(r.get('entry')):r for r in rows('v55_reconstruction_summary.csv') if canon(r.get('entry'))};native=rows('v55_native_sections.csv');selected=rows('v52_selected_functions.csv');errors=[]
for e in sorted(high):
 if e not in v54 or (v54[e].get('status') or '')!='ok':errors.append(f'{e}: V5.4 protected evidence missing/not ok')
 if e not in hp_fn:errors.append(f'{e}: High-P-code pass did not report function')
 if e not in cfg:errors.append(f'{e}: CFG metrics missing')
 if e not in recon:errors.append(f'{e}: reconstruction summary missing')
 elif int(recon[e].get('region_count') or 0)<=0:errors.append(f'{e}: zero reconstructed regions')
if not native:errors.append('native data section inventory missing')
if not highp:errors.append('High-P-code summary missing')
complete={};cp=root/'v55_complete_views_stats.json'
if cp.exists():
 try:complete=json.loads(cp.read_text(encoding='utf-8'))
 except Exception as ex:errors.append(f'complete human views stats invalid: {ex}')
else:errors.append('complete human views stats missing')
if complete:
 n=len(selected)
 if int(complete.get('selected_functions') or -1)!=n:errors.append('complete views selected-function count mismatch')
 if int(complete.get('c_views') or -1)!=n:errors.append('C/C-like coverage is not 100% of selected functions')
 if int(complete.get('selected_asm_views') or -1)!=n:errors.append('full ARM64 coverage is not 100% of selected functions')
 if int(complete.get('offset_index_rows') or 0)<=0:errors.append('dual-address offset index is empty')
 if complete.get('missing_selected_c_views'):errors.append('complete views reports missing selected C files')
 if complete.get('missing_selected_asm_views'):errors.append('complete views reports missing selected ARM64 files')
report={'high_protected_functions':len(high),'protected_evidence_ok':sum(1 for e in high if e in v54 and (v54[e].get('status') or '')=='ok'),'high_pcode_rows':len(highp),'cfg_functions':len(cfg),'reconstructed_functions':len(recon),'native_sections':len(native),'selected_functions':len(selected),'complete_c_views':complete.get('c_views',0),'complete_asm_views':complete.get('selected_asm_views',0),'dual_address_offset_rows':complete.get('offset_index_rows',0),'errors':errors,'status':'pass' if not errors else 'fail'}
(root/'v55_acceptance.json').write_text(json.dumps(report,indent=2),encoding='utf-8');(root/'v55_acceptance.md').write_text('# V5.5 acceptance\n\n'+''.join(f'- {k.replace("_"," ").title()}: **{v}**\n' for k,v in report.items() if k!='errors'),encoding='utf-8')
if errors:raise SystemExit('V5.5 acceptance failed: '+'; '.join(errors))
print(json.dumps(report))
