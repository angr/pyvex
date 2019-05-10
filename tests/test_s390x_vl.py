#!/usr/bin/env python3
import archinfo
import pyvex
import nose.tools


def test_s390x_vl():
    arch = archinfo.ArchS390X()
    irsb = pyvex.lift(
        b'\xe7\x40\x90\xa8\x00\x06',  # vl %v4, 0xa8(%r9)
        0x11c6c9e,
        arch)
    irsb_str = str(irsb)

    nose.tools.assert_in('GET:I64(r9)', irsb_str)
    nose.tools.assert_in('Add64(0x00000000000000a8', irsb_str)
    nose.tools.assert_in('LDbe:V128', irsb_str)
    nose.tools.assert_in('PUT(v4) =', irsb_str)
    nose.tools.assert_equal(irsb.jumpkind, 'Ijk_Boring')


if __name__ == '__main__':
    test_s390x_vl()
