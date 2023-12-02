import pyvex


def test_s390x_lochi():
    arch = pyvex.ARCH_S390X
    irsb = pyvex.lift(b"\xec\x18\xab\xcd\x00\x42", 0x400400, arch)  # lochi %r1,0xabcd,8
    irsb_str = str(irsb)

    assert "s390_calculate_cond(0x0000000000000008" in irsb_str
    assert "PUT(r1_32) = 0xffffabcd" in irsb_str
    assert irsb.jumpkind in "Ijk_Boring"


if __name__ == "__main__":
    test_s390x_lochi()
