
import nose.tools

import archinfo
import pyvex


def test_ud2():

    # On x86 and amd64, ud2 is a valid 2-byte instruction that means "undefined instruction". Upon decoding a basic
    # block that ends with ud2, we should treat it as an explicit NoDecode, instead of skipping the instruction and
    # resume lifting.

    b = pyvex.block.IRSB('\x90\x90\x0f\x0b\x90\x90', 0x20, archinfo.ArchAMD64())
    nose.tools.assert_equals(b.jumpkind, "Ijk_NoDecode")
    nose.tools.assert_equals(b.next.con.value, 0x22)
    nose.tools.assert_equals(b.size, 4)


if __name__ == "__main__":
    test_ud2()
