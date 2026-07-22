"""Tests for constant folding of loads from read-only regions on AMD64.

An AMD64 PE import call (``call qword ptr [rip+disp]``) lifts to a load from a
constant address (the IAT slot). With the slot's section registered as a
read-only region and ``const_prop=True``, the loaded pointer must be recorded
in ``IRSB.const_vals`` so CFG recovery can resolve the call without invoking
an indirect-jump resolver.

Before the fix, pyvex_c/analysis.c read the load address via ``Ico.U32``
(truncating 64-bit addresses) and stored the loaded value in a 4-byte ``UInt``
that ``load_value()`` writes 8 bytes into for I64 loads.
"""

import struct
import unittest

import pyvex

SLOT_ADDR = 0x1_4000_1100  # above 4 GiB so truncated addresses cannot resolve
TARGET = 0x1_40F0_0020


class TestRoRegionConstFoldAmd64(unittest.TestCase):
    """Constant-fold IAT-style loads on AMD64 via registered read-only regions."""

    def _lift_with_region(self, code: bytes) -> pyvex.IRSB:
        region = struct.pack("<Q", TARGET)
        buf = pyvex.ffi.from_buffer(region)
        assert pyvex.pvc.register_readonly_region(SLOT_ADDR, len(region), buf)
        try:
            return pyvex.lift(
                code,
                0x1_4000_1000,
                pyvex.ARCH_AMD64,
                load_from_ro_regions=True,
                const_prop=True,
                collect_data_refs=True,
            )
        finally:
            pyvex.pvc.deregister_all_readonly_regions()

    def _assert_next_tmp_folded(self, irsb: pyvex.IRSB):
        assert isinstance(irsb.next, pyvex.expr.RdTmp)
        folded = {cv.tmp: cv.value for cv in irsb.const_vals or []}
        self.assertIn(irsb.next.tmp, folded)
        self.assertEqual(folded[irsb.next.tmp], TARGET)

    def test_call_qword_rip_relative(self):
        # call qword ptr [rip + 0xfa] -> loads SLOT_ADDR
        irsb = self._lift_with_region(b"\xff\x15\xfa\x00\x00\x00")
        self.assertEqual(irsb.jumpkind, "Ijk_Call")
        self._assert_next_tmp_folded(irsb)

    def test_jmp_qword_rip_relative(self):
        # jmp qword ptr [rip + 0xfa] -> loads SLOT_ADDR (IAT jump thunk)
        irsb = self._lift_with_region(b"\xff\x25\xfa\x00\x00\x00")
        self.assertEqual(irsb.jumpkind, "Ijk_Boring")
        self._assert_next_tmp_folded(irsb)

    def test_data_ref_to_slot_is_preserved(self):
        # folding must not drop the xref to the IAT slot itself
        irsb = self._lift_with_region(b"\xff\x15\xfa\x00\x00\x00")
        refs = [(r.data_addr, r.data_size) for r in irsb.data_refs or []]
        self.assertIn((SLOT_ADDR, 8), refs)

    def test_unregistered_region_does_not_fold(self):
        irsb = pyvex.lift(
            b"\xff\x15\xfa\x00\x00\x00",
            0x1_4000_1000,
            pyvex.ARCH_AMD64,
            load_from_ro_regions=True,
            const_prop=True,
            collect_data_refs=True,
        )
        folded = {cv.tmp: cv.value for cv in irsb.const_vals or []}
        assert isinstance(irsb.next, pyvex.expr.RdTmp)
        self.assertNotIn(irsb.next.tmp, folded)


if __name__ == "__main__":
    unittest.main()
