#!/usr/bin/env python3
import json
import sys
from pathlib import Path

if len(sys.argv) not in (2, 3):
    raise SystemExit('usage: stitch_ranges.py <manifest.json> [output.bin]')

manifest_path = Path(sys.argv[1])
manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
module_size = int(manifest.get('size') or 0)
if module_size <= 0:
    raise SystemExit('manifest has no valid module size')
if module_size > 1024 * 1024 * 1024:
    raise SystemExit('refusing to allocate a module image larger than 1 GiB')

output = Path(sys.argv[2]) if len(sys.argv) == 3 else manifest_path.with_name(manifest_path.stem + '-stitched.bin')
image = bytearray(module_size)
coverage = []
base = int(str(manifest['base']), 16)

for r in manifest.get('ranges', []):
    if r.get('status') != 'ok':
        continue
    file_name = r.get('file')
    if not file_name:
        continue
    src = manifest_path.parent / file_name
    if not src.exists():
        coverage.append({'file': file_name, 'status': 'missing'})
        continue
    range_base = int(str(r['base']), 16)
    relative = range_base - base
    size = int(r['size'])
    if relative < 0 or relative >= module_size:
        coverage.append({'file': file_name, 'status': 'outside-module', 'relative': relative})
        continue
    data = src.read_bytes()
    use = min(len(data), size, module_size - relative)
    image[relative:relative + use] = data[:use]
    coverage.append({
        'file': file_name,
        'status': 'stitched',
        'relative_offset': relative,
        'declared_size': size,
        'bytes_written': use,
        'protection': r.get('protection'),
    })

output.write_bytes(image)
covered = sum(x.get('bytes_written', 0) for x in coverage)
report = {
    'module': manifest.get('module'),
    'base': manifest.get('base'),
    'module_size': module_size,
    'output': str(output),
    'bytes_covered_sum': covered,
    'coverage_ratio_sum': covered / module_size if module_size else 0,
    'ranges': coverage,
    'warning': 'This is a memory image, not automatically a valid repaired ELF. Relocations, gaps and headers may still require reconstruction.',
}
report_path = output.with_suffix(output.suffix + '.json')
report_path.write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps({'output': str(output), 'report': str(report_path), 'coverage_ratio_sum': report['coverage_ratio_sum']}))
