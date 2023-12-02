import pyvex


def test_ud2():
    # On x86 and amd64, ud2 is a valid 2-byte instruction that means "undefined instruction". Upon decoding a basic
    # block that ends with ud2, we should treat it as an explicit NoDecode, instead of skipping the instruction and
    # resume lifting.

    b = pyvex.block.IRSB(b"\x90\x90\x0f\x0b\x90\x90", 0x20, pyvex.ARCH_AMD64)
    assert b.jumpkind == "Ijk_NoDecode"
    assert b.next.con.value == 0x22
    assert b.size == 4


if __name__ == "__main__":
    test_ud2()
