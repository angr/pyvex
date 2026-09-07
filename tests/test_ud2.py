import pyvex


def test_ud2():
    # On x86 and amd64, ud2 is a valid 2-byte instruction that means "undefined instruction". Upon decoding a basic
    # block that ends with ud2, we should treat it as an explicit NoDecode, instead of skipping the instruction and
    # resume lifting.

    b = pyvex.block.IRSB(b"\x90\x90\x0f\x0b\x90\x90", 0x20, pyvex.ARCH_AMD64)
    assert b.jumpkind == "Ijk_NoDecode"
    assert b.next.con.value == 0x22
    assert b.size == 4


def test_ud2_x86():
    # x86 lifts ud2 exactly like amd64 does: the instruction is decoded and counted towards the
    # block size, and the block ends on an explicit NoDecode that jumps back to the ud2 itself.

    b = pyvex.block.IRSB(b"\x90\x90\x0f\x0b\x90\x90", 0x20, pyvex.ARCH_X86)
    assert b.jumpkind == "Ijk_NoDecode"
    assert b.next.con.value == 0x22
    assert b.size == 4


def test_ud2_x86_leading():
    # a ud2 in the leading position still produces a block holding just that instruction, rather
    # than an empty block that a fallback lifter would have to claim.

    b = pyvex.block.IRSB(b"\x0f\x0b\x90\x90", 0x20, pyvex.ARCH_X86)
    assert b.jumpkind == "Ijk_NoDecode"
    assert b.next.con.value == 0x20
    assert b.size == 2


if __name__ == "__main__":
    test_ud2()
    test_ud2_x86()
    test_ud2_x86_leading()
