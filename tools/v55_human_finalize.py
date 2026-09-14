#!/usr/bin/env python3
import sys
from pathlib import Path
if len(sys.argv)!=2:raise SystemExit('usage: v55_human_finalize.py <analysis-output-dir>')
root=Path(sys.argv[1]);human=root/'human';p=human/'START_HERE.html'
if not p.exists():raise SystemExit('START_HERE.html missing')
text=p.read_text(encoding='utf-8',errors='replace');marker='<!-- V55_INTELLIGENCE_LINKS -->';block=marker+'\n<section id="v55-intelligence"><h2>V5.5 intelligence</h2><ul><li><a href="V55_RECONSTRUCTION.html">Region reconstructed C</a></li><li><a href="V55_CFG.html">CFG / SCC / dominator intelligence</a></li><li><a href="V55_NATIVE_DATA.html">Native data / pointer-table intelligence</a></li><li><a href="ida/README.html">IDA Pro annotation bridge</a></li></ul><p>These views are confidence-tagged analysis products. Forensic V5.4 evidence remains authoritative and untruncated.</p></section>\n'
if marker not in text:
 text=text.replace('</body>',block+'</body>') if '</body>' in text else text+block;p.write_text(text,encoding='utf-8')
print('V5.5 human index finalized')
