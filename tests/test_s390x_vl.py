#!/usr/bin/env python3
import archinfo
import pyvex


def test_s390x_vl():
    arch = archinfo.ArchS390X()
    irsb = pyvex.lift(b"\xe7\x40\x90\xa8\x00\x06", 0x11C6C9E, arch)  # vl %v4, 0xa8(%r9)
    irsb_str = str(irsb)

    assert "GET:I64(r9)" in irsb_str
