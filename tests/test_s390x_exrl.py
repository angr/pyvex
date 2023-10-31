import pyvex


def test_s390x_exrl():
    arch = pyvex.ARCH_S390X
    irsb = pyvex.lift(
        b"\xc6\x10\x00\x00\x00\x04"  # exrl %r1,0x400408
        b"\x07\xfe"  # br %r14
        b"\xd7\x00\x20\x00\x30\x00"  # xc 0(0,%r2),0(%r3)
        b"\x7d\xa7",  # padding
        0x400400,
        arch,
    )
    irsb_str = str(irsb)

    # check last_execute_target, only top 6 bytes are relevant
    assert "0xd700200030000000" in irsb_str
    assert "s390x_dirtyhelper_EX" in irsb_str
    assert "{ PUT(ia) = 0x400400; Ijk_Boring }" in irsb_str
    assert "------ IMark(0x400406, 2, 0) ------" in irsb_str
    assert irsb.jumpkind == "Ijk_Ret"


if __name__ == "__main__":
    test_s390x_exrl()
