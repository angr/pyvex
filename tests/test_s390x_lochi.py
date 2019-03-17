import archinfo
import pyvex
import nose.tools


def test_s390x_lochi():
    arch = archinfo.ArchS390X()
    irsb = pyvex.lift(
        b'\xec\x18\xab\xcd\x00\x42',  # lochi %r1,0xabcd,8
        0x400400,
        arch)
    irsb_str = str(irsb)

    nose.tools.assert_in('s390_calculate_cond(0x0000000000000008', irsb_str)
    nose.tools.assert_in('PUT(r1_32) = 0xffffabcd', irsb_str)
    nose.tools.assert_equal(irsb.jumpkind, 'Ijk_Boring')

if __name__ == '__main__':
    test_s390x_lochi()
