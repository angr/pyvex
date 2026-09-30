import os
from pathlib import Path

import pyvex


def branch_target(instruction_index, addr):
    binaries = Path(os.environ.get("PYVEX_TEST_BINARIES_ROOT", Path(__file__).resolve().parents[2] / "binaries"))
    instructions = (binaries / "tests" / "s390x" / "brcth-displacements.bin").read_bytes()
    assert len(instructions) == 24
    data = instructions[instruction_index * 6 : (instruction_index + 1) * 6]
    irsb = pyvex.lift(data, addr, pyvex.ARCH_S390X)
    assert irsb.size == 6
    assert irsb.jumpkind == "Ijk_Boring"
    assert irsb.next is not None
    assert isinstance(irsb.next, pyvex.IRExpr.Const)
    assert irsb.next.con.value == addr + 6
    assert irsb.statements is not None
    exits = [stmt.dst.value for stmt in irsb.statements if isinstance(stmt, pyvex.IRStmt.Exit)]
    assert len(exits) == 1
    return exits[0]


def test_s390x_brcth_large_displacement():
    # brcth %r1,0x21000 -- 0x10000 halfwords forward, more than a signed
    # 16-bit displacement can hold.
    assert branch_target(0, 0x1000) == 0x21000


def test_s390x_brcth_small_displacement():
    # brcth %r1,0x1006 -- 3 halfwords forward.
    assert branch_target(1, 0x1000) == 0x1006


def test_s390x_brcth_negative_displacement():
    # brcth %r1,0xffe -- 1 halfword backward.
    assert branch_target(2, 0x1000) == 0xFFE


def test_s390x_brcth_large_negative_displacement():
    # brcth %r1,-0x10000 halfwords, wrapping below zero in 64 bits.
    assert branch_target(3, 0x1000) == 0xFFFFFFFFFFFE1000


if __name__ == "__main__":
    test_s390x_brcth_large_displacement()
    test_s390x_brcth_small_displacement()
    test_s390x_brcth_negative_displacement()
    test_s390x_brcth_large_negative_displacement()
