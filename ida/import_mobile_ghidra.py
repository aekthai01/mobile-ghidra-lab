# Mobile Ghidra Lab V5.5 - IDA Pro annotation bridge
# Run inside IDA Pro after opening the same ELF that produced this artifact.
# Safe policy: comments are imported automatically. Heuristic renames are OFF by default.
# This script does not patch bytes, create functions, or change function boundaries.

import csv
import json
import re
from pathlib import Path
import idaapi
import idc

PACK_DIR = Path(__file__).resolve().parent
APPLY_STRONG_RENAMES = False
IMPORT_COMMENTS = True
CONF_RANK = {"UNKNOWN": 0, "CANDIDATE": 1, "PROBABLE": 2, "STRONG": 3, "PROVEN": 4}

def read_csv(name):
    p = PACK_DIR / name
    if not p.exists(): return []
    with p.open(encoding="utf-8", errors="replace", newline="") as f: return list(csv.DictReader(f))
def read_json(name):
    p = PACK_DIR / name
    return json.loads(p.read_text(encoding="utf-8", errors="replace")) if p.exists() else {}
def parse_hex(value):
    value=(value or '').strip(); value=value[2:] if value.lower().startswith('0x') else value
    try:return int(value,16)
    except:return None
meta=read_json('metadata.json'); ghidra_base=parse_hex(meta.get('ghidra_image_base')) or 0; ida_base=int(idaapi.get_imagebase()); delta=ida_base-ghidra_base
def ea(value):
    x=parse_hex(value); return None if x is None else x+delta
def valid_ea(x):return x is not None and x!=idaapi.BADADDR
def safe_name(value):return re.sub(r'[^A-Za-z0-9_@$?]+','_',value or '')[:180]
def add_comment(address,text,repeatable=False):
    if not IMPORT_COMMENTS or not valid_ea(address) or not text:return False
    old=idc.get_cmt(address,1 if repeatable else 0) or '';line='[MobileGhidraLab] '+text
    if line in old:return False
    return bool(idc.set_cmt(address,(old+'\n'+line).strip() if old else line,1 if repeatable else 0))
def set_safe_name(address,name,confidence):
    if not APPLY_STRONG_RENAMES or CONF_RANK.get((confidence or '').upper(),0)<CONF_RANK['STRONG'] or not valid_ea(address):return False
    name=safe_name(name)
    if not name:return False
    current=idc.get_name(address) or ''
    if current and not re.match(r'^(sub_|loc_|unk_|byte_|word_|dword_|qword_|off_|FUN_)',current,re.I):return False
    return bool(idc.set_name(address,name,idc.SN_CHECK))
comments=read_csv('comments.csv');names=read_csv('suggested_names.csv');important=read_csv('important_addresses.csv');regions=read_csv('regions.csv');stats={'comments':0,'renames':0,'important':len(important),'regions':len(regions)}
for r in comments:
    if add_comment(ea(r.get('address')),f"[{(r.get('confidence') or 'UNKNOWN').upper()}] {r.get('comment') or ''}",r.get('repeatable')=='true'):stats['comments']+=1
for r in names:
    if set_safe_name(ea(r.get('address')),r.get('suggested_name') or '',r.get('confidence') or ''):stats['renames']+=1
print('[Mobile Ghidra Lab V5.5] import complete')
print('  Ghidra image base: 0x%X' % ghidra_base)
print('  IDA image base:    0x%X' % ida_base)
print('  Rebase delta:      %+d' % delta)
print('  Comments added:    %d' % stats['comments'])
print('  Strong renames:    %d (APPLY_STRONG_RENAMES=%s)' % (stats['renames'],APPLY_STRONG_RENAMES))
print('  Important addrs:   %d' % stats['important'])
print('  Regions:           %d' % stats['regions'])
