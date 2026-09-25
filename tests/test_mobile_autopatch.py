import unittest

from tools.mobile_autopatch import (
    ElfLayout,
    LoadSegment,
    PatchError,
    SectionInfo,
    ghidra_to_rva,
    parse_patch,
)


class PatchParserTests(unittest.TestCase):
    def test_parses_byte_and_dword(self):
        b = parse_patch("byte_36AE84=1")
        d = parse_patch("dword_36AF34=3")
        self.assertEqual((b.width, b.ghidra_va, b.value), (1, 0x36AE84, 1))
        self.assertEqual((d.width, d.ghidra_va, d.value), (4, 0x36AF34, 3))

    def test_rejects_value_overflow(self):
        with self.assertRaises(PatchError):
            parse_patch("byte_36AE84=256")

    def test_rejects_ambiguous_dat_name(self):
        with self.assertRaises(PatchError):
            parse_patch("DAT_36AE84=1")

    def test_ghidra_base_translation(self):
        self.assertEqual(ghidra_to_rva(0x36AE84, 0x100000), 0x26AE84)
        self.assertEqual(ghidra_to_rva(0x36AF34, 0x100000), 0x26AF34)


class ElfLocationTests(unittest.TestCase):
    def make_layout(self):
        return ElfLayout(
            elf_class=64,
            little_endian=True,
            machine="EM_AARCH64",
            elf_type="ET_DYN",
            file_size=0x4000,
            segments=(
                LoadSegment(
                    index=1,
                    offset=0x1000,
                    vaddr=0x2000,
                    filesz=0x300,
                    memsz=0x500,
                    flags=6,
                ),
            ),
            sections=(
                SectionInfo(".data", 0x2000, 0x300, "SHT_PROGBITS"),
                SectionInfo(".bss", 0x2300, 0x200, "SHT_NOBITS"),
            ),
        )

    def test_file_backed_va_maps_through_pt_load(self):
        loc = self.make_layout().locate(0x2100, 4)
        self.assertEqual(loc.kind, "file-backed")
        self.assertEqual(loc.file_offset, 0x1100)
        self.assertEqual(loc.section, ".data")

    def test_bss_is_memory_only_not_fake_file_offset(self):
        loc = self.make_layout().locate(0x2350, 1)
        self.assertEqual(loc.kind, "memory-only")
        self.assertIsNone(loc.file_offset)
        self.assertEqual(loc.section, ".bss")
        self.assertIn("no file bytes exist", loc.detail)

    def test_range_crossing_file_to_bss_is_blocked(self):
        loc = self.make_layout().locate(0x22FF, 4)
        self.assertEqual(loc.kind, "memory-only")
        self.assertIsNone(loc.file_offset)

    def test_unmapped_range_is_rejected(self):
        loc = self.make_layout().locate(0x9000, 4)
        self.assertEqual(loc.kind, "unmapped")
        self.assertIsNone(loc.file_offset)


if __name__ == "__main__":
    unittest.main()
