import os
import unittest

import pyvex

# angr/binaries is checked out beside the repository under test in the
# ecosystem CI job. The standalone platform jobs check out pyvex alone, so the
# real-binary test below skips there.
BINARIES = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
ACME_CLIENT = os.path.join(BINARIES, "s390x", "exrl", "acme-client")

# angr maps that PIE at 0x400000 and CFGFast scans the executable segment for
# code, which lands it on 0x40723a. Nothing executes there: the entry stub ends
# at 0x407233 and branches to 0x407240, and 0x40723a is two bytes into the word
# at 0x407238 that the stub loads to find _DYNAMIC. Its low half plus the
# padding after it read as exrl %r6 with a target 235,802,126 bytes ahead.
# tests/s390x/exrl/README.md in angr/binaries has the rest.
LOAD_BASE = 0x400000
ENTRY_OFFSET = 0x7210
EXRL_OFFSET = 0x723A


def read_acme_client():
    if not os.path.isdir(BINARIES):
        raise unittest.SkipTest(f"angr/binaries is not checked out beside pyvex: {BINARIES} is missing")
    with open(ACME_CLIENT, "rb") as fp:
        return fp.read()


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


def test_s390x_exrl_target_before_buffer():
    """The EXRL displacement is signed. Reading it as unsigned aimed the target
    about 8GB past the buffer, and put that address in the emitted lookup too.
    """
    arch = pyvex.ARCH_S390X
    irsb = pyvex.lift(
        b"\xc6\x10\xff\xff\xff\x00"  # exrl %r1,0x400200
        b"\x07\xfe",  # br %r14
        0x400400,
        arch,
    )
    irsb_str = str(irsb)

    # The target is 0x200 bytes back, so it is not in the buffer and cannot be
    # prefetched; the run-time lookup is emitted, and it reads the right place.
    assert "LDbe:I64(0x0000000000400200)" in irsb_str
    assert "s390x_dirtyhelper_EX" in irsb_str
    assert irsb.size == 6
    assert irsb.jumpkind == "Ijk_InvalICache"


def test_s390x_exrl_target_past_buffer():
    """Nothing constrains the displacement, so a bogus EXRL points anywhere
    within 4GB of the buffer. Nothing outside it is read; the run-time lookup
    resolves the target instead.
    """
    arch = pyvex.ARCH_S390X
    irsb = pyvex.lift(
        b"\xc6\x10\x00\x00\x10\x00"  # exrl %r1,0x402400
        b"\x07\xfe",  # br %r14
        0x400400,
        arch,
    )
    irsb_str = str(irsb)

    assert "LDbe:I64(0x0000000000402400)" in irsb_str
    assert "s390x_dirtyhelper_EX" in irsb_str
    assert irsb.size == 6
    assert irsb.jumpkind == "Ijk_InvalICache"


def test_s390x_exrl_target_past_max_bytes():
    """An EXRL target may sit outside the lift window and still be inside the
    caller's buffer, which is how angr lifts: it hands over a whole segment and
    caps the block at max_bytes. The target is readable, so it is still used.
    """
    arch = pyvex.ARCH_S390X
    block = (
        b"\xc6\x10\x00\x00\x00\x64"  # exrl %r1,0x4004c8
        b"\x07\xfe"  # br %r14
    )
    target = b"\xd7\x00\x20\x00\x30\x00"  # xc 0(0,%r2),0(%r3)
    buf = bytearray(block + b"\x00" * (0xC8 - len(block)) + target)

    for data in (bytes(buf), pyvex.ffi.from_buffer(buf)):
        irsb = pyvex.lift(data, 0x400400, arch, max_bytes=len(block))
        assert "0xd700200030000000" in str(irsb)
        assert irsb.jumpkind == "Ijk_Ret"

    # Drop the last byte of the target and it no longer fits in the buffer.
    irsb = pyvex.lift(pyvex.ffi.from_buffer(buf[:-1]), 0x400400, arch, max_bytes=len(block))
    assert "0xd700200030000000" not in str(irsb)
    assert irsb.jumpkind == "Ijk_InvalICache"

    # A bare pointer has no extent to state, so max_bytes is all that is read.
    sized = pyvex.ffi.from_buffer(buf)
    irsb = pyvex.lift(pyvex.ffi.cast("unsigned char *", sized), 0x400400, arch, max_bytes=len(block))
    assert "0xd700200030000000" not in str(irsb)
    assert irsb.jumpkind == "Ijk_InvalICache"


def test_s390x_exrl_inside_a_larger_buffer():
    """The whole segment angr hands over starts before the block, and the EXRL
    need not be the block's first instruction, so the target is displaced from
    the EXRL rather than from either start.
    """
    arch = pyvex.ARCH_S390X
    block = (
        b"\xa7\x5b\xff\xff"  # aghi %r5,-1
        b"\xc6\x10\x00\x00\x00\x62"  # exrl %r1,0x4004c8
        b"\x07\xfe"  # br %r14
    )
    target = b"\xd7\x00\x20\x00\x30\x00"  # xc 0(0,%r2),0(%r3)
    prefix = b"\x07\xfe" * 8  # code before the block, never decoded
    buf = bytearray(prefix + block + b"\x00" * (0xC8 - len(block)) + target)

    irsb = pyvex.lift(pyvex.ffi.from_buffer(buf), 0x400400, arch, max_bytes=len(block), bytes_offset=len(prefix))
    assert "0xd700200030000000" in str(irsb)
    assert irsb.jumpkind == "Ijk_Ret"


def test_s390x_exrl_truncated():
    """A block whose last instruction is a truncated EXRL. CFGFast lifts at
    addresses it finds by scanning, so it hands the lifter such a block
    routinely.
    """
    arch = pyvex.ARCH_S390X
    irsb = pyvex.lift(
        b"\xa7\x5b\xff\xff"  # aghi %r5,-1
        b"\xc6\x50\xff",  # first three bytes of a six-byte exrl
        0x1000,
        arch,
    )

    # The exrl does not fit in the block, so only the aghi is lifted.
    assert irsb.size == 4
    assert irsb.jumpkind == "Ijk_Boring"


def test_s390x_exrl_real_binary():
    """A compiler-produced object that this used to kill the process on:
    acme-client 1.3.5 for s390x, out of Alpine v3.23. CFGFast's scan reaches a
    data word between two functions, the six bytes there decode as an EXRL
    aiming 235,802,126 bytes ahead, and libVEX fetched that out of the
    translation buffer without a bounds check -- around 225 MiB past the end of
    the 73,920-byte executable segment cle hands over.
    """
    image = read_acme_client()
    arch = pyvex.ARCH_S390X

    # The entry stub, lifted out of the file. Nothing in it reads outside the
    # buffer, so it says the fixture is being read and lifted correctly. Its
    # last instruction is the branch to 0x407240, which is why nothing ever
    # runs the bytes the scan trips on.
    irsb = pyvex.lift(image, LOAD_BASE + ENTRY_OFFSET, arch, bytes_offset=ENTRY_OFFSET)
    assert irsb.size == 36
    assert irsb.jumpkind == "Ijk_Boring"
    assert "PUT(ia) = 0x0000000000407240; Ijk_Boring" in str(irsb)

    # And the address the scan reaches, both as the whole file and as the six
    # bytes a block cut at max_bytes leaves. The target is far outside the
    # buffer either way, so it is not prefetched and the run-time lookup is
    # emitted instead.
    for data, offset in ((image, EXRL_OFFSET), (image[EXRL_OFFSET : EXRL_OFFSET + 6], 0)):
        irsb = pyvex.lift(data, LOAD_BASE + EXRL_OFFSET, arch, bytes_offset=offset)
        irsb_str = str(irsb)
        assert "LDbe:I64(0x000000000e4e8048)" in irsb_str
        assert "s390x_dirtyhelper_EX" in irsb_str
        assert irsb.size == 6
        assert irsb.jumpkind == "Ijk_InvalICache"


if __name__ == "__main__":
    test_s390x_exrl()
    test_s390x_exrl_target_before_buffer()
    test_s390x_exrl_target_past_buffer()
    test_s390x_exrl_target_past_max_bytes()
    test_s390x_exrl_inside_a_larger_buffer()
    test_s390x_exrl_truncated()
    test_s390x_exrl_real_binary()
