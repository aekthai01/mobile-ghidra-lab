#!/usr/bin/env bash
# Fast triage (seconds, no Ghidra): what is in this .so and what do these addresses do.
# usage: triage_r2.sh <elf> [outdir] [addr ...]
set -euo pipefail
ELF="${1:?elf required}"; shift
OUT="${1:-triage_out}"; shift || true
mkdir -p "$OUT"
T0=$(date +%s)

{
  echo "## file"; file "$ELF"
  echo; echo "## elf header"; readelf -h "$ELF" 2>/dev/null | sed -n '1,20p'
  echo; echo "## segments"; readelf -lW "$ELF" 2>/dev/null
  echo; echo "## sections"; readelf -SW "$ELF" 2>/dev/null
  echo; echo "## dynamic"; readelf -dW "$ELF" 2>/dev/null | head -40
  echo; echo "## exports"; nm -D --defined-only "$ELF" 2>/dev/null | head -60
} > "$OUT/elf.txt" 2>&1

# prologue census = cheap function-count estimate without full analysis
python3 - "$ELF" > "$OUT/prologue_count.txt" 2>&1 <<'PY'
import sys, io
import numpy as np
from elftools.elf.elffile import ELFFile
raw = open(sys.argv[1], 'rb').read()
e = ELFFile(io.BytesIO(raw))
s = e.get_section_by_name('.text')
if s is None:
    print('no .text'); raise SystemExit
w = np.frombuffer(raw[s['sh_offset']:s['sh_offset'] + s['sh_size']], dtype='<u4')
pre = int(((w & np.uint32(0xFFC07FFF)) == np.uint32(0xA9807BFD)).sum())
off = int(((w & np.uint32(0xFFC07FFF)) == np.uint32(0xA9007BFD)).sum())
print(f'text_bytes={s["sh_size"]}')
print(f'stp_x29_x30_preindex={pre}')
print(f'stp_x29_x30_offset={off}')
print(f'approx_functions={pre + off}')
PY

: > "$OUT/disasm.txt"
for A in "$@"; do
  echo "=== $A" >> "$OUT/disasm.txt"
  r2 -2 -q -c "pd 16 @ $A" "$ELF" >> "$OUT/disasm.txt" 2>&1 || true
done

echo "elapsed_sec=$(( $(date +%s) - T0 ))" | tee "$OUT/triage_time.txt"
cat "$OUT/prologue_count.txt"
