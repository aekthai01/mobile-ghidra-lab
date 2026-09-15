#!/usr/bin/env python3
import sys
from pathlib import Path
if len(sys.argv)!=2:raise SystemExit('usage: v55_human_finalize.py <analysis-output-dir>')
root=Path(sys.argv[1]);human=root/'human';p=human/'START_HERE.html'
if not p.exists():raise SystemExit('START_HERE.html missing')
text=p.read_text(encoding='utf-8',errors='replace');marker='<!-- V55_INTELLIGENCE_LINKS -->'
block=marker+'''\n<section id="v55-intelligence"><h2>V5.5 intelligence</h2><ul>
<li><a href="V55_SEMANTIC_C.html"><strong>ARM64-grounded semantic C (preferred analysis view)</strong></a></li>
<li><a href="OFFSET_LOOKUP.html">Offset lookup (IDA/RVA ↔ Ghidra VA)</a></li>
<li><a href="FUNCTIONS_C.html">Complete selected-function C/C-like evidence coverage</a></li>
<li><a href="OFFSET_MAP.txt">Exact searchable offset map</a></li>
<li><a href="V55_RECONSTRUCTION.html">Protected/giant region reconstructed C</a></li>
<li><a href="V55_CFG.html">CFG / SCC / dominator intelligence</a></li>
<li><a href="V55_NATIVE_DATA.html">Native data / pointer-table intelligence</a></li>
<li><a href="ida/README.html">IDA Pro annotation bridge</a></li></ul>
<p><strong>Analysis hierarchy:</strong> ARM64 is ground truth. The semantic-C view rebuilds basic-block/control-flow structure from ARM64 + CFG, folds only evidence-backed idioms, recovers call arguments and strings, and keeps unsupported instructions explicit. High/Raw P-code remain supporting data-flow evidence, not the source of truth.</p>
<p><strong>Address note:</strong> Human views show both ELF/IDA RVA and Ghidra VA. Paste an IDA offset such as <code>19C56C</code> into Offset Lookup; no manual image-base arithmetic is required.</p>
<p>Every selected function has a full ARM64 view under <code>asm_full/</code>, an ARM64-grounded semantic view under <code>semantic_c/</code> (plus high-signal <code>semantic_c_compact/</code>), and one legacy evidence-oriented C/C-like view under <code>functions_c/</code>. These are analysis products, not original source.</p>
<p>Forensic V5.4 protected evidence remains authoritative and untruncated.</p></section>\n'''
if marker in text:
 start=text.index(marker);end=text.find('</section>',start)
 if end>=0:text=text[:start]+block+text[end+len('</section>'):]
 else:text=text[:start]+block
else:
 text=text.replace('</body>',block+'</body>') if '</body>' in text else text+block
p.write_text(text,encoding='utf-8')
print('V5.5 human index finalized')
