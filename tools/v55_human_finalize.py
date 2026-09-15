#!/usr/bin/env python3
import sys
from pathlib import Path
if len(sys.argv)!=2:raise SystemExit('usage: v55_human_finalize.py <analysis-output-dir>')
root=Path(sys.argv[1]);human=root/'human';p=human/'START_HERE.html'
if not p.exists():raise SystemExit('START_HERE.html missing')
text=p.read_text(encoding='utf-8',errors='replace');marker='<!-- V55_INTELLIGENCE_LINKS -->'
block=marker+'''\n<section id="v55-intelligence"><h2>V5.5 AI-native intelligence</h2><ul>
<li><a href="V55_SEMANTIC_C.html"><strong>semantic_c: ARM64-grounded core (preferred analysis view)</strong></a></li>
<li><code>semantic_c_compact/</code>: compact high-signal AI prompt view</li>
<li><code>asm_full/</code>: immutable ARM64 ground truth</li>
<li><code>raw_ir/</code> / forensic artifact: Raw P-code + SSA evidence vault</li>
<li><a href="FUNCTIONS_C.html">functions_c: legacy evidence-oriented raw P-code C-like view, not the preferred analysis view</a></li>
<li><a href="OFFSET_LOOKUP.html">Offset lookup (IDA/RVA ↔ Ghidra VA)</a></li>
<li><a href="V55_RECONSTRUCTION.html">Protected/giant region reconstructed C</a></li>
<li><a href="V55_CFG.html">CFG / SCC / dominator intelligence</a></li>
<li><a href="V55_NATIVE_DATA.html">Native data / pointer-table intelligence</a></li>
<li><a href="ida/README.html">IDA Pro annotation bridge</a></li></ul>
<p><strong>Four-layer contract:</strong> <code>asm_full</code> is immutable ARM64 ground truth; <code>semantic_c</code> is the ARM64-grounded semantic core; <code>semantic_c_compact</code> is the AI prompt view; <code>raw_ir</code> is the forensic P-code/SSA vault. <code>functions_c</code> is retained only as legacy evidence-oriented C-like context.</p>
<p><strong>Confidence/provenance:</strong> EXACT means direct instruction/address/CFG evidence; STRONG means deterministic lowering backed by ARM64/data-flow evidence; HEURISTIC means inference only. A real symbol is never replaced by a heuristic name.</p>
<p>SIMD/NEON modified immediates preserve final raw lane bits before floating-point interpretation. Unsupported ARM64 remains explicit rather than guessed. Evidence strings are emitted safely even when their bytes contain a C comment terminator.</p>
<p><strong>Address note:</strong> Human views show both ELF/IDA RVA and Ghidra VA. Paste an IDA offset such as <code>19C56C</code> into Offset Lookup; no manual image-base arithmetic is required.</p>
<p>Forensic V5.4 protected evidence remains authoritative and untruncated.</p></section>\n'''
if marker in text:
 start=text.index(marker);end=text.find('</section>',start)
 if end>=0:text=text[:start]+block+text[end+len('</section>'):]
 else:text=text[:start]+block
else:text=text.replace('</body>',block+'</body>') if '</body>' in text else text+block
p.write_text(text,encoding='utf-8');print('V5.5 human index finalized')
