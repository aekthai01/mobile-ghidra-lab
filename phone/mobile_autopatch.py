#!/usr/bin/env python3
"""Phone-local ELF patcher for Ghidra-style global names.

Step 1 scope:
- parse names such as byte_36AE84=1 and dword_36AF34=3
- translate Ghidra VA -> ELF RVA using the Ghidra image base
- translate ELF RVA -> file offset using PT_LOAD program headers
- detect memory-only/BSS targets and refuse to corrupt the file
- patch a copy of the ELF and verify the written bytes

This tool does not do signature matching yet. It is intentionally small and strict so
that address translation is proven before cross-version matching is added.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence

try:
    from elftools.elf.elffile import ELFFile
except ImportError as exc:  # pragma: no cover - exercised by the phone environment
    raise SystemExit(
        "missing dependency: pyelftools\n"
        "Termux: pkg install python && python -m pip install pyelftools"
    ) from exc


DEFAULT_GHIDRA_IMAGE_BASE = 0x100000

# Keep Step 1 deliberately unambiguous. DAT_ has no width encoded in its name, so it
# is not accepted yet. Ghidra's byte/word/dword/qword and undefined<N> names do.
PREFIX_WIDTHS = {
    "byte": 1,
    "word": 2,
    "dword": 4,
    "qword": 8,
    "undefined": 1,
    "undefined1": 1,
    "undefined2": 2,
    "undefined4": 4,
    "undefined8": 8,
}

PATCH_RE = re.compile(
    r"^(?P<prefix>byte|word|dword|qword|undefined(?:1|2|4|8)?)_"
    r"(?P<address>[0-9A-Fa-f]+)=(?P<value>0[xX][0-9A-Fa-f]+|[0-9]+)$",
    re.IGNORECASE,
)


class PatchError(RuntimeError):
    pass


@dataclass(frozen=True)
class PatchSpec:
    expression: str
    name: str
    width: int
    ghidra_va: int
    value: int

    def encode(self, little_endian: bool) -> bytes:
        byteorder = "little" if little_endian else "big"
        return self.value.to_bytes(self.width, byteorder=byteorder, signed=False)


@dataclass(frozen=True)
class LoadSegment:
    index: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int
    flags: int

    @property
    def file_end_va(self) -> int:
        return self.vaddr + self.filesz

    @property
    def memory_end_va(self) -> int:
        return self.vaddr + self.memsz


@dataclass(frozen=True)
class SectionInfo:
    name: str
    address: int
    size: int
    section_type: str


@dataclass(frozen=True)
class Location:
    kind: str  # file-backed | memory-only | unmapped
    rva: int
    width: int
    segment_index: Optional[int] = None
    file_offset: Optional[int] = None
    section: Optional[str] = None
    detail: str = ""


@dataclass(frozen=True)
class ResolvedPatch:
    expression: str
    name: str
    width: int
    ghidra_va: int
    image_base: int
    elf_rva: int
    value: int
    encoded_hex: str
    location_kind: str
    section: Optional[str]
    segment_index: Optional[int]
    file_offset: Optional[int]
    original_hex: Optional[str]
    original_value: Optional[int]
    detail: str


@dataclass(frozen=True)
class ElfLayout:
    elf_class: int
    little_endian: bool
    machine: str
    elf_type: str
    file_size: int
    segments: tuple[LoadSegment, ...]
    sections: tuple[SectionInfo, ...]

    @classmethod
    def from_path(cls, path: Path) -> "ElfLayout":
        try:
            file_size = path.stat().st_size
        except OSError as exc:
            raise PatchError(f"cannot stat input ELF: {exc}") from exc

        try:
            with path.open("rb") as fh:
                elf = ELFFile(fh)
                segments = []
                for index, seg in enumerate(elf.iter_segments()):
                    if str(seg["p_type"]) != "PT_LOAD":
                        continue
                    segments.append(
                        LoadSegment(
                            index=index,
                            offset=int(seg["p_offset"]),
                            vaddr=int(seg["p_vaddr"]),
                            filesz=int(seg["p_filesz"]),
                            memsz=int(seg["p_memsz"]),
                            flags=int(seg["p_flags"]),
                        )
                    )

                sections = []
                for sec in elf.iter_sections():
                    sections.append(
                        SectionInfo(
                            name=sec.name,
                            address=int(sec["sh_addr"]),
                            size=int(sec["sh_size"]),
                            section_type=str(sec["sh_type"]),
                        )
                    )

                if not segments:
                    raise PatchError("ELF has no PT_LOAD segments")

                return cls(
                    elf_class=int(elf.elfclass),
                    little_endian=bool(elf.little_endian),
                    machine=str(elf.header["e_machine"]),
                    elf_type=str(elf.header["e_type"]),
                    file_size=file_size,
                    segments=tuple(segments),
                    sections=tuple(sections),
                )
        except PatchError:
            raise
        except Exception as exc:
            raise PatchError(f"cannot parse ELF: {exc}") from exc

    def section_for_range(self, rva: int, width: int) -> Optional[SectionInfo]:
        end = rva + width
        matches = [
            sec
            for sec in self.sections
            if sec.size > 0 and rva >= sec.address and end <= sec.address + sec.size
        ]
        if not matches:
            return None
        # Prefer the smallest containing section if unusual overlapping sections exist.
        return min(matches, key=lambda sec: sec.size)

    def locate(self, rva: int, width: int) -> Location:
        if rva < 0 or width <= 0:
            return Location("unmapped", rva, width, detail="invalid address/width")

        end = rva + width
        memory_matches = [
            seg
            for seg in self.segments
            if rva >= seg.vaddr and end <= seg.memory_end_va
        ]
        if not memory_matches:
            return Location(
                "unmapped",
                rva,
                width,
                detail="range is outside every PT_LOAD memory range",
            )
        if len(memory_matches) != 1:
            return Location(
                "unmapped",
                rva,
                width,
                detail=f"range is covered by {len(memory_matches)} PT_LOAD segments; refusing ambiguity",
            )

        seg = memory_matches[0]
        sec = self.section_for_range(rva, width)
        sec_name = sec.name if sec else None

        if end > seg.file_end_va:
            detail = "target exists only in the in-memory tail of PT_LOAD (BSS/zero-fill); no file bytes exist"
            if sec and sec.section_type == "SHT_NOBITS":
                detail = f"target is in {sec.name} (SHT_NOBITS); no file bytes exist"
            return Location(
                "memory-only",
                rva,
                width,
                segment_index=seg.index,
                section=sec_name,
                detail=detail,
            )

        file_offset = seg.offset + (rva - seg.vaddr)
        if file_offset < 0 or file_offset + width > self.file_size:
            return Location(
                "unmapped",
                rva,
                width,
                segment_index=seg.index,
                section=sec_name,
                detail="PT_LOAD translation points outside the physical file",
            )

        return Location(
            "file-backed",
            rva,
            width,
            segment_index=seg.index,
            file_offset=file_offset,
            section=sec_name,
            detail="resolved through PT_LOAD",
        )


def parse_number(text: str) -> int:
    text = text.strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text, 10)


def parse_patch(expression: str) -> PatchSpec:
    expression = expression.strip()
    match = PATCH_RE.fullmatch(expression)
    if not match:
        raise PatchError(
            f"invalid patch expression {expression!r}; expected e.g. byte_36AE84=1 or dword_36AF34=3"
        )

    prefix = match.group("prefix").lower()
    width = PREFIX_WIDTHS[prefix]
    ghidra_va = int(match.group("address"), 16)
    value = parse_number(match.group("value"))
    max_value = (1 << (width * 8)) - 1
    if not 0 <= value <= max_value:
        raise PatchError(
            f"value {value} does not fit {width} byte(s) for {match.group('prefix')}_{match.group('address')}"
        )

    return PatchSpec(
        expression=expression,
        name=f"{match.group('prefix')}_{match.group('address')}",
        width=width,
        ghidra_va=ghidra_va,
        value=value,
    )


def ghidra_to_rva(ghidra_va: int, image_base: int) -> int:
    if image_base < 0:
        raise PatchError("Ghidra image base cannot be negative")
    if ghidra_va < image_base:
        raise PatchError(
            f"Ghidra VA 0x{ghidra_va:X} is below image base 0x{image_base:X}"
        )
    return ghidra_va - image_base


def load_patch_file(path: Path) -> list[str]:
    expressions: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PatchError(f"cannot read patch file {path}: {exc}") from exc

    for line_no, raw in enumerate(lines, 1):
        text = raw.split("#", 1)[0].strip()
        if not text:
            continue
        if " " in text or "\t" in text:
            raise PatchError(
                f"{path}:{line_no}: one patch expression per line is required"
            )
        expressions.append(text)
    return expressions


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def default_output_path(src: Path) -> Path:
    if src.suffix:
        return src.with_name(f"{src.stem}.patched{src.suffix}")
    return src.with_name(src.name + ".patched")


def read_uint(data: bytes, little_endian: bool) -> int:
    return int.from_bytes(data, byteorder="little" if little_endian else "big", signed=False)


def check_overlaps(items: Sequence[tuple[int, int, str]]) -> None:
    ordered = sorted(items)
    for left, right in zip(ordered, ordered[1:]):
        left_start, left_end, left_name = left
        right_start, right_end, right_name = right
        if right_start < left_end:
            raise PatchError(
                f"patches overlap: {left_name} [0x{left_start:X},0x{left_end:X}) and "
                f"{right_name} [0x{right_start:X},0x{right_end:X})"
            )


def resolve_patches(
    layout: ElfLayout,
    source_bytes: bytes,
    specs: Sequence[PatchSpec],
    image_base: int,
) -> list[ResolvedPatch]:
    resolved: list[ResolvedPatch] = []
    overlaps: list[tuple[int, int, str]] = []

    for spec in specs:
        rva = ghidra_to_rva(spec.ghidra_va, image_base)
        location = layout.locate(rva, spec.width)
        encoded = spec.encode(layout.little_endian)
        original_hex: Optional[str] = None
        original_value: Optional[int] = None

        if location.kind == "file-backed":
            assert location.file_offset is not None
            start = location.file_offset
            end = start + spec.width
            original = source_bytes[start:end]
            if len(original) != spec.width:
                raise PatchError(
                    f"short read at file offset 0x{start:X}: wanted {spec.width}, got {len(original)}"
                )
            original_hex = original.hex()
            original_value = read_uint(original, layout.little_endian)
            overlaps.append((start, end, spec.name))

        resolved.append(
            ResolvedPatch(
                expression=spec.expression,
                name=spec.name,
                width=spec.width,
                ghidra_va=spec.ghidra_va,
                image_base=image_base,
                elf_rva=rva,
                value=spec.value,
                encoded_hex=encoded.hex(),
                location_kind=location.kind,
                section=location.section,
                segment_index=location.segment_index,
                file_offset=location.file_offset,
                original_hex=original_hex,
                original_value=original_value,
                detail=location.detail,
            )
        )

    check_overlaps(overlaps)
    return resolved


def print_summary(layout: ElfLayout, src: Path, image_base: int, items: Sequence[ResolvedPatch]) -> None:
    endian = "little" if layout.little_endian else "big"
    print(f"[*] input       : {src}")
    print(f"[*] ELF         : ELF{layout.elf_class} {layout.machine} {layout.elf_type} {endian}-endian")
    print(f"[*] Ghidra base : 0x{image_base:X}")
    for item in items:
        print()
        print(f"[{item.name}]")
        print(f"  Ghidra VA   : 0x{item.ghidra_va:X}")
        print(f"  ELF RVA     : 0x{item.elf_rva:X}")
        print(f"  width       : {item.width}")
        print(f"  section     : {item.section or '<unknown>'}")
        print(f"  location    : {item.location_kind}")
        if item.file_offset is not None:
            print(f"  file offset : 0x{item.file_offset:X}")
            print(f"  original    : {item.original_hex} ({item.original_value})")
            print(f"  replacement : {item.encoded_hex} ({item.value})")
        else:
            print(f"  reason      : {item.detail}")


def atomic_write(path: Path, data: bytes, source_mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(temp_path, stat.S_IMODE(source_mode))
        os.replace(temp_path, path)
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        finally:
            raise


def verify_output(path: Path, items: Sequence[ResolvedPatch]) -> None:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PatchError(f"cannot verify output: {exc}") from exc

    for item in items:
        if item.location_kind != "file-backed" or item.file_offset is None:
            continue
        expected = bytes.fromhex(item.encoded_hex)
        actual = data[item.file_offset:item.file_offset + item.width]
        if actual != expected:
            raise PatchError(
                f"verification failed for {item.name} at 0x{item.file_offset:X}: "
                f"expected {expected.hex()}, got {actual.hex()}"
            )


def build_report(
    src: Path,
    output: Optional[Path],
    layout: ElfLayout,
    image_base: int,
    before_sha256: str,
    after_sha256: Optional[str],
    dry_run: bool,
    items: Sequence[ResolvedPatch],
) -> dict:
    return {
        "input": str(src),
        "output": str(output) if output else None,
        "dry_run": dry_run,
        "ghidra_image_base": f"0x{image_base:X}",
        "elf": {
            "class": layout.elf_class,
            "machine": layout.machine,
            "type": layout.elf_type,
            "little_endian": layout.little_endian,
        },
        "sha256_before": before_sha256,
        "sha256_after": after_sha256,
        "patches": [asdict(item) for item in items],
    }


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Patch file-backed ELF globals using Ghidra-style names, locally on Termux.",
        epilog=(
            "example: python mobile_autopatch.py lib.so byte_36AE84=1 dword_36AF34=3 --dry-run\n"
            "         python mobile_autopatch.py lib.so --patch-file patches.txt"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("elf", type=Path, help="input ELF/.so")
    parser.add_argument("patches", nargs="*", help="patch expressions such as byte_36AE84=1")
    parser.add_argument(
        "--patch-file",
        type=Path,
        help="UTF-8 text file with one patch expression per line; # comments are allowed",
    )
    parser.add_argument(
        "--ghidra-image-base",
        default=f"0x{DEFAULT_GHIDRA_IMAGE_BASE:X}",
        help=f"Ghidra image base (default: 0x{DEFAULT_GHIDRA_IMAGE_BASE:X} for this project)",
    )
    parser.add_argument("-o", "--output", type=Path, help="output ELF; default: <name>.patched.so")
    parser.add_argument("--dry-run", action="store_true", help="resolve and validate only; write nothing")
    parser.add_argument("--overwrite", action="store_true", help="allow replacing an existing output file")
    parser.add_argument("--json-report", type=Path, help="optional JSON resolution/patch report")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)

    try:
        src: Path = args.elf
        if not src.is_file():
            raise PatchError(f"input file does not exist: {src}")

        expressions = list(args.patches)
        if args.patch_file:
            expressions.extend(load_patch_file(args.patch_file))
        if not expressions:
            raise PatchError("no patches supplied")

        specs = [parse_patch(expr) for expr in expressions]
        image_base = parse_number(args.ghidra_image_base)
        layout = ElfLayout.from_path(src)
        source_bytes = src.read_bytes()
        if len(source_bytes) != layout.file_size:
            raise PatchError("input file size changed while reading; refusing to patch a moving target")

        before_sha = sha256_bytes(source_bytes)
        items = resolve_patches(layout, source_bytes, specs, image_base)
        print_summary(layout, src, image_base, items)

        blocked = [item for item in items if item.location_kind != "file-backed"]
        if blocked:
            print()
            print("[!] no bytes were written")
            for item in blocked:
                print(f"[!] {item.name}: {item.location_kind}: {item.detail}")
            print("[!] A memory-only/BSS target must be handled by patching the code that initializes/uses it, not by inventing a file offset.")
            report = build_report(
                src, None, layout, image_base, before_sha, None, True, items
            )
            if args.json_report:
                args.json_report.parent.mkdir(parents=True, exist_ok=True)
                args.json_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
            return 4

        if args.dry_run:
            print()
            print("[+] dry-run passed: every target is uniquely file-backed; no bytes were written")
            report = build_report(
                src, None, layout, image_base, before_sha, None, True, items
            )
            if args.json_report:
                args.json_report.parent.mkdir(parents=True, exist_ok=True)
                args.json_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
            return 0

        output = args.output or default_output_path(src)
        if output.resolve() == src.resolve():
            raise PatchError("output must not be the original ELF; this tool never patches the source in place")
        if output.exists() and not args.overwrite:
            raise PatchError(f"output already exists: {output} (use --overwrite to replace it)")

        patched = bytearray(source_bytes)
        for item in items:
            assert item.file_offset is not None
            replacement = bytes.fromhex(item.encoded_hex)
            patched[item.file_offset:item.file_offset + item.width] = replacement

        source_mode = src.stat().st_mode
        atomic_write(output, bytes(patched), source_mode)
        verify_output(output, items)
        after_sha = sha256_bytes(output.read_bytes())

        print()
        print(f"[+] patched     : {output}")
        print(f"[+] SHA256 old  : {before_sha}")
        print(f"[+] SHA256 new  : {after_sha}")
        print("[+] verification: replacement bytes re-read successfully")

        report = build_report(
            src, output, layout, image_base, before_sha, after_sha, False, items
        )
        if args.json_report:
            args.json_report.parent.mkdir(parents=True, exist_ok=True)
            args.json_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"[+] report      : {args.json_report}")
        return 0

    except (PatchError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
