"""ARMv8.1-A LSE atomics and the ARMv8.3-A LDAPR load, over a compiled fixture.

Every word of ``tests/aarch64/lse_atomics`` in the sibling angr/binaries
checkout is lifted, so the test needs that checkout and an architecture
definition; both are present in the ecosystem CI job and absent from the
per-platform one, which skips.
"""

import os
import struct

import pytest

import pyvex

FIXTURE = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests", "aarch64", "lse_atomics"
)

needs_fixture = pytest.mark.skipif(
    not os.path.exists(FIXTURE), reason="needs the angr/binaries checkout beside this one"
)


def _arch():
    return pytest.importorskip("archinfo").ArchAArch64()


def _text_section(path):
    """Return the (virtual address, bytes) of .text in a little-endian ELF64 file."""
    with open(path, "rb") as f:
        image = f.read()
    e_shoff = struct.unpack_from("<Q", image, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", image, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", image, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", image, 0x3E)[0]
    headers = [struct.unpack_from("<IIQQQQIIQQ", image, e_shoff + i * e_shentsize) for i in range(e_shnum)]
    strtab_off = headers[e_shstrndx][4]
    for name_off, _, _, addr, offset, size, _, _, _, _ in headers:
        end = image.index(b"\0", strtab_off + name_off)
        if image[strtab_off + name_off : end] == b".text":
            return addr, image[offset : offset + size]
    raise AssertionError(f"{path} has no .text section")


def _is_lse_atomic(word):
    """ARMv8.1-A LD<OP>{,A}{,L} and SWP{,A}{,L}."""
    return (
        (word >> 24) & 0x3F == 0b111000
        and (word >> 21) & 1 == 1
        and (word >> 12) & 0xF <= 0b1000
        and (word >> 10) & 3 == 0
    )


def _is_cas(word):
    """ARMv8.1-A CAS{,A}{,L}."""
    return (word >> 23) & 0x7F == 0b0010001 and (word >> 21) & 1 == 1 and (word >> 10) & 0x1F == 0b11111


def _is_casp(word):
    """ARMv8.1-A CASP{,A}{,L}."""
    return (
        (word >> 31) & 1 == 0
        and (word >> 23) & 0x7F == 0b0010000
        and (word >> 21) & 1 == 1
        and (word >> 10) & 0x1F == 0b11111
    )


def _is_ldapr(word):
    """ARMv8.3-A LDAPR{,B,H}."""
    return (word >> 21) & 0x1FF == 0b111000101 and (word >> 10) & 0x7FF == 0b11111110000


def _is_rcpc2(word):
    """ARMv8.4-A LDAPUR/STLUR, which libVEX does not decode (kde bug 496477)."""
    return (word >> 24) & 0x3F == 0b011001 and (word >> 21) & 1 == 0 and (word >> 10) & 3 == 0


def _words():
    addr, text = _text_section(FIXTURE)
    for offset in range(0, len(text) - 3, 4):
        yield addr + offset, text[offset : offset + 4], struct.unpack_from("<I", text, offset)[0]


def _first(predicate):
    return next((a, d) for a, d, w in _words() if predicate(w))


@needs_fixture
def test_lse_atomics_decode():
    arch = _arch()
    counts = {"lse": 0, "cas": 0, "casp": 0, "ldapr": 0, "rcpc2": 0}
    undecoded = []
    for addr, data, word in _words():
        for key, predicate in (
            ("lse", _is_lse_atomic),
            ("cas", _is_cas),
            ("casp", _is_casp),
            ("ldapr", _is_ldapr),
            ("rcpc2", _is_rcpc2),
        ):
            if predicate(word):
                counts[key] += 1
        irsb = pyvex.lift(data, addr, arch, max_bytes=4, opt_level=0)
        if irsb.size == 0 or irsb.jumpkind == "Ijk_NoDecode":
            undecoded.append(word)

    # The fixture carries every group, so a rebuild that drops one makes this
    # test say so rather than passing vacuously.
    assert counts == {"lse": 63, "cas": 10, "casp": 8, "ldapr": 8, "rcpc2": 8}

    # ARMv8.4-A RCpc2 is the one group libVEX still refuses, upstream included.
    assert len(undecoded) == counts["rcpc2"]
    assert all(_is_rcpc2(word) for word in undecoded)


@needs_fixture
def test_lse_atomic_is_a_cas_with_a_retry():
    addr, data = _first(_is_lse_atomic)
    irsb = pyvex.lift(data, addr, _arch(), max_bytes=4, opt_level=0)
    assert irsb.size == 4
    assert any(isinstance(stmt, pyvex.stmt.CAS) for stmt in irsb.statements)
    retries = [
        stmt
        for stmt in irsb.statements
        if isinstance(stmt, pyvex.stmt.Exit) and stmt.dst.value == addr and stmt.jumpkind == "Ijk_Boring"
    ]
    assert len(retries) == 1
    # The retry is guarded on the CAS having failed.
    assert "CasCmpNE" in str(irsb)


@needs_fixture
def test_casp_is_a_double_cas():
    addr, data = _first(_is_casp)
    irsb = pyvex.lift(data, addr, _arch(), max_bytes=4, opt_level=0)
    assert irsb.size == 4
    cas = next(stmt for stmt in irsb.statements if isinstance(stmt, pyvex.stmt.CAS))
    assert cas.expdHi is not None
    assert cas.dataHi is not None


@needs_fixture
def test_ldapr_is_an_acquiring_load():
    addr, data = _first(_is_ldapr)
    irsb = pyvex.lift(data, addr, _arch(), max_bytes=4, opt_level=0)
    assert irsb.size == 4
    assert any(isinstance(stmt, pyvex.stmt.MBE) for stmt in irsb.statements)
    assert "LDle" in str(irsb)
