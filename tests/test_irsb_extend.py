"""Tests for IRSB.extend().

``lift()`` joins the blocks produced by different lifters the same way, for example when libVEX stops at an instruction
that only a gym spotter can lift. The joined block must describe all of its instructions, and the appended block must
stay intact.
"""

# pylint: disable=missing-class-docstring,no-self-use
import struct
import unittest

import pyvex


def _ins_addr_of_stmt(irsb: pyvex.IRSB, stmt_idx: int) -> int:
    for stmt in reversed(irsb.statements[: stmt_idx + 1]):
        if type(stmt) is pyvex.stmt.IMark:
            return stmt.addr + stmt.delta
    raise AssertionError(f"Statement {stmt_idx} is not preceded by an IMark")


def _exit_targets(irsb: pyvex.IRSB) -> list[tuple[int, int]]:
    targets = []
    for ins_addr, stmt_idx, stmt in irsb.exit_statements:
        assert isinstance(stmt, pyvex.stmt.Exit)
        assert irsb.statements[stmt_idx] is stmt
        targets.append((ins_addr, stmt.dst.value))
    return targets


class TestIRSBExtend(unittest.TestCase):
    def test_extend_does_not_modify_the_appended_irsb(self):
        # Two blocks at the same address, so that each of them is contiguous with the appended block
        first = pyvex.lift(b"\x50", 0x1000, pyvex.ARCH_X86)  # push eax
        second = pyvex.lift(b"\x51", 0x1000, pyvex.ARCH_X86)  # push ecx
        appended = pyvex.lift(b"\x52", 0x1001, pyvex.ARCH_X86)  # push edx
        appended_str = str(appended)

        for irsb in (first, second):
            irsb.extend(appended)
            assert str(appended) == appended_str
            assert irsb.typecheck()
            assert irsb.size == 2
            assert irsb.instruction_addresses == (0x1000, 0x1001)

        assert appended.typecheck()

    def test_extend_empty_irsb_does_not_alias_the_appended_irsb(self):
        block = pyvex.lift(b"\x50", 0x1000, pyvex.ARCH_X86)  # push eax
        block_str = str(block)

        irsb = pyvex.IRSB(None, 0x1000, pyvex.ARCH_X86)
        irsb.extend(block)
        irsb.extend(pyvex.lift(b"\x51", 0x1001, pyvex.ARCH_X86))  # push ecx

        assert str(block) == block_str
        assert block.typecheck()
        assert irsb.typecheck()
        assert irsb.size == 2
        assert irsb.instruction_addresses == (0x1000, 0x1001)

    def test_extend_refreshes_exit_statements(self):
        irsb = pyvex.lift(b"\x50", 0x1000, pyvex.ARCH_X86)  # push eax
        assert irsb.exit_statements == ()  # computes and caches the exits
        irsb.extend(pyvex.lift(b"\x74\x02", 0x1001, pyvex.ARCH_X86))  # je 0x1005

        assert _exit_targets(irsb) == [(0x1001, 0x1005)]
        assert irsb.default_exit_target == 0x1003
        assert irsb.constant_jump_targets == {0x1003, 0x1005}

    def test_lift_through_spotter_keeps_derived_state(self):
        # swapgs is lifted by AMD64Spotter, so lift() joins the blocks around it with extend()
        addr = 0x400000
        code = (
            bytes.fromhex("488b0500010000")  # mov rax, [rip + 0x100]
            + bytes.fromhex("0f01f8")  # swapgs
            + bytes.fromhex("488b1d00020000")  # mov rbx, [rip + 0x200]
        )
        jz_addr = addr + len(code)
        code += b"\x0f\x84" + struct.pack("<i", 0x1000 - (jz_addr + 6))  # jz 0x1000
        fallthrough = addr + len(code)

        irsb = pyvex.lift(code, addr, pyvex.ARCH_AMD64, collect_data_refs=True)

        assert irsb.size == len(code)
        assert irsb.jumpkind == "Ijk_Boring"
        imarks = [stmt for stmt in irsb.statements if type(stmt) is pyvex.stmt.IMark]
        assert irsb.instructions == len(imarks)
        assert irsb.instruction_addresses == tuple(imark.addr + imark.delta for imark in imarks)
        assert {0x400000, 0x400007, 0x40000A, jz_addr} <= set(irsb.instruction_addresses)

        assert irsb.default_exit_target == fallthrough
        assert irsb.constant_jump_targets == {0x1000, fallthrough}
        assert _exit_targets(irsb) == [(jz_addr, 0x1000)]

        refs = {(ref.data_addr, ref.ins_addr) for ref in irsb.data_refs or []}
        assert (0x400107, 0x400000) in refs
        assert (0x400211, 0x40000A) in refs
        for ref in irsb.data_refs or []:
            assert _ins_addr_of_stmt(irsb, ref.stmt_idx) == ref.ins_addr

    def test_lift_through_spotter_keeps_const_vals(self):
        # An IAT call after an instruction lifted by AMD64Spotter: the folded call target must survive the join
        addr = 0x1_4000_1000
        slot_addr = 0x1_4000_1100
        target = 0x1_40F0_0020
        code = bytes.fromhex("488b0500010000") + bytes.fromhex("0f01f8")  # mov rax, [rip + 0x100]; swapgs
        call_addr = addr + len(code)
        code += b"\xff\x15" + struct.pack("<i", slot_addr - (call_addr + 6))  # call qword ptr [slot_addr]

        region = struct.pack("<Q", target)
        buf = pyvex.ffi.from_buffer(region)
        assert pyvex.pvc.register_readonly_region(slot_addr, len(region), buf)
        try:
            irsb = pyvex.lift(
                code,
                addr,
                pyvex.ARCH_AMD64,
                load_from_ro_regions=True,
                const_prop=True,
                collect_data_refs=True,
            )
        finally:
            pyvex.pvc.deregister_all_readonly_regions()

        assert irsb.jumpkind == "Ijk_Call"
        assert isinstance(irsb.next, pyvex.expr.RdTmp)
        folded = {cv.tmp: cv.value for cv in irsb.const_vals or []}
        assert folded.get(irsb.next.tmp) == target
        for cv in irsb.const_vals or []:
            stmt = irsb.statements[cv.stmt_idx]
            assert type(stmt) is pyvex.stmt.WrTmp and stmt.tmp == cv.tmp
        assert (slot_addr, call_addr) in {(ref.data_addr, ref.ins_addr) for ref in irsb.data_refs or []}


if __name__ == "__main__":
    unittest.main()
