import archinfo
import pyvex
import nose.tools


def test_s390x_exrl():
    arch = archinfo.ArchS390X()
    irsb = pyvex.lift(
        b'\xc6\x10\x00\x00\x00\x04'  # exrl %r1,0x400408
        b'\x07\xfe'  # br %r14
        b'\xd7\x00\x20\x00\x30\x00'  # xc 0(0,%r2),0(%r3)
        b'\x7d\xa7',  # padding
        0x400400,
        arch)
    irsb_str = str(irsb)
    
    nose.tools.assert_in('0xd700200030007da7', irsb_str)
    nose.tools.assert_in('s390x_dirtyhelper_EX', irsb_str)
    nose.tools.assert_in('{ PUT(ia) = 0x400400; Ijk_Boring }', irsb_str)
    nose.tools.assert_in('------ IMark(0x400406, 2, 0) ------', irsb_str)
    nose.tools.assert_equal(irsb.jumpkind, 'Ijk_Ret')

if __name__ == '__main__':
    test_s390x_exrl()
