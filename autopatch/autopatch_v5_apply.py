#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, stat, sys, tempfile
from pathlib import Path


def load_core(path: Path):
    spec = importlib.util.spec_from_file_location("autopatch_core", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import resolver core: {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def default_output(src: Path) -> Path:
    return src.with_name(f"{src.stem}.patched{src.suffix}") if src.suffix else src.with_name(src.name + ".patched")


def atomic_write(path: Path, data: bytes, mode: int):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tp = Path(tmp)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.chmod(tp, stat.S_IMODE(mode))
        os.replace(tp, path)
    except Exception:
        tp.unlink(missing_ok=True)
        raise


def main() -> int:
    ap = argparse.ArgumentParser(description="Apply exact read-force plans produced by mobile_autopatch v4 core")
    ap.add_argument("elf", type=Path)
    ap.add_argument("patches", nargs="+")
    ap.add_argument("--core", type=Path, default=Path("/tmp/mobile_autopatch_v4.py"))
    ap.add_argument("--window", type=int, default=96)
    ap.add_argument("-o", "--output", type=Path)
    ap.add_argument("--manifest", type=Path, default=Path("patch_manifest_v5.json"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    core = load_core(args.core)
    image = core.ElfImage.load(args.elf)
    if image.machine != "EM_AARCH64" or not image.little_endian:
        raise SystemExit("unsupported ELF; expected little-endian AArch64")

    specs = [core.parse_patch(x) for x in args.patches]
    targets = [core.resolve_target(image, s, "auto", core.DEFAULT_GHIDRA_IMAGE_BASE) for s in specs]
    results = []
    merged = {}

    for target in targets:
        xrefs, pages = core.scan_target_xrefs(image, target, max(1, min(args.window, 256)))
        exact_reads = [x for x in xrefs if x.access == "read" and x.access_width == target.spec.width]
        plan = core.make_patch_plan(target, xrefs)
        planned_rvas = {int(p["instruction_rva"]) for p in plan}
        exact_rvas = {x.instruction_rva for x in exact_reads}
        if not exact_reads:
            raise SystemExit(f"{target.spec.name}: no exact width-matched read xref")
        if planned_rvas != exact_rvas:
            raise SystemExit(f"{target.spec.name}: incomplete plan: exact={sorted(exact_rvas)} planned={sorted(planned_rvas)}")

        for p in plan:
            off = int(p["instruction_file_offset"])
            old = int(p["original_word"], 16)
            new = int(p["replacement_word"], 16)
            if off & 3 or off < 0 or off + 4 > len(image.data):
                raise SystemExit(f"{target.spec.name}: bad instruction offset 0x{off:X}")
            actual = int.from_bytes(image.data[off:off+4], "little")
            if actual != old:
                raise SystemExit(f"{target.spec.name}: guard mismatch at 0x{p['instruction_rva']:X}: expected 0x{old:08X}, found 0x{actual:08X}")
            if old == new:
                raise SystemExit(f"{target.spec.name}: replacement is unchanged at 0x{p['instruction_rva']:X}")
            prev = merged.get(off)
            if prev and int(prev["replacement_word"], 16) != new:
                raise SystemExit(f"conflicting patch at file offset 0x{off:X}")
            merged[off] = dict(p)

        results.append({
            "target": target.spec.name,
            "requested_value": target.spec.value,
            "target_rva": target.rva,
            "exact_xrefs": len(xrefs),
            "exact_reads": len(exact_reads),
            "exact_writes": sum(x.access == "write" for x in xrefs),
            "page_candidates": len(pages),
            "plan": plan,
        })

    plans = [merged[k] for k in sorted(merged)]
    before = image.data
    patched = bytearray(before)
    for p in plans:
        off = int(p["instruction_file_offset"])
        new = int(p["replacement_word"], 16)
        patched[off:off+4] = new.to_bytes(4, "little")

    for p in plans:
        off = int(p["instruction_file_offset"])
        expected = int(p["replacement_word"], 16).to_bytes(4, "little")
        if bytes(patched[off:off+4]) != expected:
            raise SystemExit(f"in-memory verify failed at 0x{p['instruction_rva']:X}")

    out = args.output or default_output(args.elf)
    manifest = {
        "input": str(args.elf),
        "sha256_before": sha256(before),
        "dry_run": args.dry_run,
        "output": None if args.dry_run else str(out),
        "sha256_after": None if args.dry_run else sha256(bytes(patched)),
        "targets": results,
        "applied_patch_plan": plans,
    }

    print(f"[*] source SHA256: {manifest['sha256_before']}")
    for r in results:
        print(f"[*] {r['target']}: xrefs={r['exact_xrefs']} reads={r['exact_reads']} writes={r['exact_writes']} plan={len(r['plan'])}")
    for p in plans:
        print(f"    0x{p['instruction_rva']:X}: {p['original_word']} -> {p['replacement_word']} bytes={p['replacement_bytes_le']}")

    if args.dry_run:
        print(f"[+] validated {len(plans)} patches; dry-run, no output written")
    else:
        if out.resolve() == args.elf.resolve():
            raise SystemExit("refusing to overwrite source ELF")
        if out.exists():
            raise SystemExit(f"output already exists: {out}")
        atomic_write(out, bytes(patched), args.elf.stat().st_mode)
        written = out.read_bytes()
        if len(written) != len(before) or sha256(written) != manifest["sha256_after"]:
            raise SystemExit("output verification failed")
        for p in plans:
            off = int(p["instruction_file_offset"])
            if written[off:off+4].hex() != p["replacement_bytes_le"]:
                raise SystemExit(f"post-write instruction verify failed at 0x{p['instruction_rva']:X}")
        print(f"[+] output: {out}")
        print(f"[+] patched SHA256: {manifest['sha256_after']}")
        print(f"[+] verified {len(plans)} replacement instructions")

    args.manifest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[+] manifest: {args.manifest}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
