#!/usr/bin/env python3
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: arm64_obfuscation_report.py <analysis-output-dir>')

root = Path(sys.argv[1])
asm_dir = root / 'ida_like_functions'
if not asm_dir.is_dir():
    print('ida_like_functions/ not found; skipping ARM64 obstruction analysis')
    raise SystemExit(0)

INS_RE = re.compile(
    r'^\.text:([0-9A-Fa-f]{16})\s+'
    r'((?:[0-9A-Fa-f]{2}\s+){3}[0-9A-Fa-f]{2})\s+'
    r'([A-Za-z0-9_.]+)\s*(.*?)(?:\s+;.*)?$'
)
FUNC_RE = re.compile(r'^; FUNCTION\s+(.+)$')
START_RE = re.compile(r'^; start=([0-9A-Fa-f]+)\s+size=0x([0-9A-Fa-f]+)')
TARGET_RE = re.compile(r'\b(?:loc|sub)_([0-9A-Fa-f]+)\b')

COND_MNEMS = {'CBZ', 'CBNZ', 'TBZ', 'TBNZ'}
TERMINAL_MNEMS = {'RET', 'ERET', 'BRK', 'HLT'}
BITWISE = {
    'EOR', 'EON', 'AND', 'ANDS', 'ORR', 'ORN', 'BIC', 'BICS',
    'LSL', 'LSR', 'ASR', 'ROR', 'UBFX', 'SBFX', 'BFI', 'BFXIL'
}
CONSTISH = {'MOV', 'MOVK', 'MOVZ', 'MOVN', 'ADRP', 'ADR'}
SELECTISH = {'CSEL', 'CSINC', 'CSINV', 'CSNEG', 'CSET', 'CSETM', 'CCMP', 'CCMN'}


def sanitize(value: str) -> str:
    value = re.sub(r'[^A-Za-z0-9._-]+', '_', value)[:90]
    return value or 'function'


def parse_file(path: Path):
    name = path.stem
    start = None
    size = None
    instructions = []
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
        match = FUNC_RE.match(line)
        if match:
            name = match.group(1).strip()
            continue
        match = START_RE.match(line)
        if match:
            start = int(match.group(1), 16)
            size = int(match.group(2), 16)
            continue
        match = INS_RE.match(line)
        if not match:
            continue
        instructions.append({
            'addr': int(match.group(1), 16),
            'mnem': match.group(3).upper(),
            'ops': match.group(4).strip(),
            'line': line,
        })

    if not instructions:
        return None
    if start is None:
        start = instructions[0]['addr']
    if size is None:
        size = instructions[-1]['addr'] - start + 4
    return {
        'path': path,
        'name': name,
        'start': start,
        'size': size,
        'instructions': instructions,
    }


def is_conditional(mnemonic: str) -> bool:
    return mnemonic in COND_MNEMS or mnemonic.startswith('B.')


def is_unconditional_direct(mnemonic: str) -> bool:
    return mnemonic == 'B'


def is_indirect_jump(mnemonic: str) -> bool:
    return mnemonic in {'BR', 'BRAA', 'BRAB', 'BRAAZ', 'BRABZ'}


def is_call(mnemonic: str) -> bool:
    return mnemonic in {'BL', 'BLR', 'BLRAA', 'BLRAB', 'BLRAAZ', 'BLRABZ'}


def target_addr(operands: str):
    match = TARGET_RE.search(operands)
    return int(match.group(1), 16) if match else None


def analyze(function):
    instructions = function['instructions']
    addresses = [item['addr'] for item in instructions]
    address_index = {address: index for index, address in enumerate(addresses)}

    block_starts = {instructions[0]['addr']}
    for index, item in enumerate(instructions):
        target = target_addr(item['ops'])
        if target in address_index and (is_conditional(item['mnem']) or is_unconditional_direct(item['mnem'])):
            block_starts.add(target)
        if (
            is_conditional(item['mnem'])
            or is_unconditional_direct(item['mnem'])
            or is_indirect_jump(item['mnem'])
            or item['mnem'] in TERMINAL_MNEMS
        ) and index + 1 < len(instructions):
            block_starts.add(instructions[index + 1]['addr'])

    block_starts = sorted(block_starts)
    block_start_set = set(block_starts)
    blocks = []
    current = []
    for item in instructions:
        if current and item['addr'] in block_start_set:
            blocks.append(current)
            current = []
        current.append(item)
    if current:
        blocks.append(current)

    block_by_start = {block[0]['addr']: block for block in blocks}
    ordered_starts = sorted(block_by_start)
    next_block = {
        ordered_starts[index]: (
            ordered_starts[index + 1] if index + 1 < len(ordered_starts) else None
        )
        for index in range(len(ordered_starts))
    }

    edges = []
    for block in blocks:
        start = block[0]['addr']
        last = block[-1]
        mnemonic = last['mnem']
        target = target_addr(last['ops'])
        if is_conditional(mnemonic):
            if target in block_by_start:
                edges.append((start, target, 'branch'))
            fallthrough = next_block[start]
            if fallthrough is not None:
                edges.append((start, fallthrough, 'fallthrough'))
        elif is_unconditional_direct(mnemonic):
            if target in block_by_start:
                edges.append((start, target, 'branch'))
        elif is_indirect_jump(mnemonic) or mnemonic in TERMINAL_MNEMS:
            pass
        else:
            fallthrough = next_block[start]
            if fallthrough is not None:
                edges.append((start, fallthrough, 'fallthrough'))

    predecessors = defaultdict(list)
    successors = defaultdict(list)
    for source, destination, kind in edges:
        successors[source].append((destination, kind))
        predecessors[destination].append((source, kind))

    mnemonics = [item['mnem'] for item in instructions]
    instruction_count = len(mnemonics)
    branch_count = sum(
        1 for mnemonic in mnemonics
        if is_conditional(mnemonic) or is_unconditional_direct(mnemonic) or is_indirect_jump(mnemonic)
    )
    conditional_count = sum(1 for mnemonic in mnemonics if is_conditional(mnemonic))
    indirect_jumps = sum(1 for mnemonic in mnemonics if is_indirect_jump(mnemonic))
    calls = sum(1 for mnemonic in mnemonics if is_call(mnemonic))
    indirect_calls = sum(1 for mnemonic in mnemonics if mnemonic.startswith('BLR'))
    bitwise_count = sum(1 for mnemonic in mnemonics if mnemonic in BITWISE)
    constant_count = sum(1 for mnemonic in mnemonics if mnemonic in CONSTISH)
    select_count = sum(1 for mnemonic in mnemonics if mnemonic in SELECTISH)
    nop_count = sum(1 for mnemonic in mnemonics if mnemonic in {'NOP', 'HINT'})
    xor_count = sum(1 for mnemonic in mnemonics if mnemonic in {'EOR', 'EON'})

    grams = [tuple(mnemonics[i:i + 4]) for i in range(max(0, instruction_count - 3))]
    repetitive_ratio = 0.0
    if grams:
        repetitive_ratio = 1.0 - len(set(grams)) / len(grams)

    max_block = max((len(block) for block in blocks), default=0)
    edge_count = len(edges)
    cyclomatic = max(1, edge_count - len(blocks) + 2) if blocks else 0
    back_edges = sum(1 for source, destination, _ in edges if destination <= source)

    score = 0
    reasons = []
    if function['size'] >= 8192:
        score += min(35, function['size'] // 2048)
        reasons.append(f"huge:{function['size']}B")
    if len(blocks) >= 100:
        score += min(30, len(blocks) // 10)
        reasons.append(f'many-blocks:{len(blocks)}')
    if cyclomatic >= 50:
        score += min(25, cyclomatic // 5)
        reasons.append(f'high-cyclomatic:{cyclomatic}')
    if indirect_jumps >= 2:
        score += min(20, indirect_jumps * 3)
        reasons.append(f'indirect-jumps:{indirect_jumps}')
    if back_edges >= 20:
        score += min(15, back_edges // 4)
        reasons.append(f'back-edges:{back_edges}')
    if repetitive_ratio >= 0.45 and instruction_count >= 500:
        score += min(20, int(repetitive_ratio * 20))
        reasons.append(f'repetitive-4gram:{repetitive_ratio:.2f}')

    bitwise_ratio = bitwise_count / max(1, instruction_count)
    constant_ratio = constant_count / max(1, instruction_count)
    select_ratio = select_count / max(1, instruction_count)
    if bitwise_ratio >= 0.16 and instruction_count >= 300:
        score += min(15, int(bitwise_ratio * 50))
        reasons.append(f'bitwise-heavy:{bitwise_ratio:.2f}')
    if constant_ratio >= 0.18 and instruction_count >= 300:
        score += min(15, int(constant_ratio * 45))
        reasons.append(f'constant-build-heavy:{constant_ratio:.2f}')
    if select_ratio >= 0.05 and conditional_count >= 20:
        score += 10
        reasons.append(f'predicate-heavy:{select_ratio:.2f}')
    if indirect_jumps and len(blocks) >= 40 and cyclomatic >= 20:
        score += 20
        reasons.append('possible-control-flow-flattening')
    if xor_count >= 32 and bitwise_ratio >= 0.12:
        score += 8
        reasons.append(f'xor-heavy:{xor_count}')

    return {
        'function': function,
        'blocks': blocks,
        'edges': edges,
        'predecessors': predecessors,
        'successors': successors,
        'metrics': {
            'entry': f"{function['start']:08X}",
            'name': function['name'],
            'size_bytes': function['size'],
            'instructions': instruction_count,
            'basic_blocks': len(blocks),
            'cfg_edges': edge_count,
            'cyclomatic': cyclomatic,
            'back_edges': back_edges,
            'branches': branch_count,
            'conditional_branches': conditional_count,
            'indirect_jumps': indirect_jumps,
            'calls': calls,
            'indirect_calls': indirect_calls,
            'max_block_instructions': max_block,
            'bitwise_instructions': bitwise_count,
            'xor_instructions': xor_count,
            'constant_build_instructions': constant_count,
            'conditional_select_instructions': select_count,
            'nop_hint_instructions': nop_count,
            'repetitive_4gram_ratio': f'{repetitive_ratio:.4f}',
            'suspicion_score': score,
            'reasons': ';'.join(reasons),
        },
    }


analyses = []
for path in sorted(asm_dir.glob('*.asm')):
    function = parse_file(path)
    if function:
        analyses.append(analyze(function))

metrics = [analysis['metrics'] for analysis in analyses]
metrics.sort(key=lambda row: (-int(row['suspicion_score']), -int(row['size_bytes']), row['entry']))
fields = list(metrics[0].keys()) if metrics else []

with (root / 'arm64_function_metrics.csv').open('w', encoding='utf-8', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(metrics)

with (root / 'arm64_suspicious_functions.csv').open('w', encoding='utf-8', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows([row for row in metrics if int(row['suspicion_score']) > 0][:500])

analysis_by_entry = {analysis['metrics']['entry']: analysis for analysis in analyses}
focus_dir = root / 'arm64_cfg_focus'
focus_dir.mkdir(exist_ok=True)

for row in metrics[:80]:
    if int(row['suspicion_score']) <= 0:
        break
    analysis = analysis_by_entry[row['entry']]
    function = analysis['function']
    output = focus_dir / f"{row['entry']}_{sanitize(function['name'])}.asm"
    with output.open('w', encoding='utf-8') as w:
        w.write('; ARM64 CFG-focused listing\n')
        w.write(
            f"; FUNCTION {function['name']} entry=0x{function['start']:X} size=0x{function['size']:X}\n"
        )
        w.write('; METRICS ' + json.dumps(row, ensure_ascii=False) + '\n\n')
        for block in analysis['blocks']:
            start = block[0]['addr']
            preds = ', '.join(
                f'loc_{source:X}' for source, _ in analysis['predecessors'].get(start, [])
            ) or '-'
            succs = ', '.join(
                f'loc_{destination:X}[{kind}]'
                for destination, kind in analysis['successors'].get(start, [])
            ) or '-'
            w.write('; ---------------------------------------------------------------------------\n')
            w.write(f'loc_{start:X}: ; PREDS: {preds} ; SUCCS: {succs}\n')
            for instruction in block:
                w.write(instruction['line'] + '\n')
            w.write('\n')

summary = {
    'functions_analyzed': len(metrics),
    'suspicious_functions': sum(1 for row in metrics if int(row['suspicion_score']) > 0),
    'very_large_functions_ge_8k': sum(1 for row in metrics if int(row['size_bytes']) >= 8192),
    'functions_with_indirect_jumps': sum(1 for row in metrics if int(row['indirect_jumps']) > 0),
    'possible_flattened_functions': sum(
        1 for row in metrics if 'possible-control-flow-flattening' in row['reasons']
    ),
    'focus_cfg_files': len(list(focus_dir.glob('*.asm'))),
}

(root / 'arm64_obfuscation_report.json').write_text(
    json.dumps(summary, indent=2), encoding='utf-8'
)
with (root / 'arm64_obfuscation_report.md').open('w', encoding='utf-8') as w:
    w.write('# ARM64 obfuscation / huge-function triage\n\n')
    w.write(
        'Heuristic triage only. High scores point to functions worth inspecting; they do not prove obfuscation.\n\n'
    )
    for key, value in summary.items():
        w.write(f"- {key.replace('_', ' ').title()}: **{value}**\n")
    w.write('\n## Top suspicious / complex functions\n\n')
    w.write(
        '| Score | Entry | Size | Blocks | Cyclomatic | Indirect | Function | Reasons |\n'
        '|---:|---|---:|---:|---:|---:|---|---|\n'
    )
    for row in metrics[:60]:
        if int(row['suspicion_score']) <= 0:
            break
        name = row['name'].replace('|', '\\|')
        reasons = row['reasons'].replace('|', '\\|')
        w.write(
            f"| {row['suspicion_score']} | `{row['entry']}` | {row['size_bytes']} | "
            f"{row['basic_blocks']} | {row['cyclomatic']} | {row['indirect_jumps']} | "
            f"`{name}` | {reasons} |\n"
        )
    w.write('\n## Files\n\n')
    w.write('- `arm64_function_metrics.csv`: metrics for every recovered function.\n')
    w.write('- `arm64_suspicious_functions.csv`: ranked suspicious / unusually complex functions.\n')
    w.write(
        '- `arm64_cfg_focus/`: block-split listings with predecessor/successor labels for the top candidates.\n'
    )
    w.write(
        '\nFor control-flow flattening or ARM64 junk spam, inspect `arm64_cfg_focus/` before the monolithic IDA-like function file.\n'
    )

print(json.dumps(summary))
