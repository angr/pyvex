import pyvex


def branch_target(data, addr):
    irsb = pyvex.lift(data, addr, pyvex.ARCH_S390X)
    exits = [stmt.dst.value for stmt in irsb.statements if isinstance(stmt, pyvex.IRStmt.Exit)]
    assert len(exits) == 1
    return exits[0]


def test_s390x_brcth_large_displacement():
    # brcth %r1,0x21000 -- 0x10000 halfwords forward, more than a signed
    # 16-bit displacement can hold.
    assert branch_target(b"\xcc\x16\x00\x01\x00\x00", 0x1000) == 0x21000


def test_s390x_brcth_small_displacement():
    # brcth %r1,0x1006 -- 3 halfwords forward.
    assert branch_target(b"\xcc\x16\x00\x00\x00\x03", 0x1000) == 0x1006


def test_s390x_brcth_negative_displacement():
    # brcth %r1,0xffe -- 1 halfword backward.
    assert branch_target(b"\xcc\x16\xff\xff\xff\xff", 0x1000) == 0xFFE


def test_s390x_brcth_large_negative_displacement():
    # brcth %r1,-0x10000 halfwords, wrapping below zero in 64 bits.
    assert branch_target(b"\xcc\x16\xff\xff\x00\x00", 0x1000) == 0xFFFFFFFFFFFE1000


if __name__ == "__main__":
    test_s390x_brcth_large_displacement()
    test_s390x_brcth_small_displacement()
    test_s390x_brcth_negative_displacement()
    test_s390x_brcth_large_negative_displacement()
