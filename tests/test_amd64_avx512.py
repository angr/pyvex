# pylint: disable=no-self-use
"""AVX-512 (EVEX) lifting tests for amd64.

The corpus in avx512_corpus.json was harvested from the instruction tests
that shipped with the Valgrind AVX-512 patch series (KDE bug 383010) and
assembled with gcc; each entry is (encoding hex, objdump mnemonic).
"""

import json
import os
import unittest

import pyvex
from pyvex import ARCH_AMD64

CORPUS_PATH = os.path.join(os.path.dirname(__file__), "avx512_corpus.json")

# Instruction families the lifter does not implement. They must fail to
# decode cleanly rather than mis-lift or crash.
KNOWN_UNDECODED = {
    "vcmpss",  # EVEX scalar compares into an opmask
    "vcmpsd",
}


def lift(hexbytes, arch=ARCH_AMD64):
    return pyvex.lift(bytes.fromhex(hexbytes), 0x400000, arch)


class TestAVX512Corpus(unittest.TestCase):
    """Every harvested encoding lifts, type-checks, and round-trips."""

    @classmethod
    def setUpClass(cls):
        with open(CORPUS_PATH, encoding="utf-8") as f:
            cls.corpus = json.load(f)

    def test_corpus_is_nonempty(self):
        assert len(self.corpus) > 2000

    def test_everything_decodes(self):
        undecoded = []
        for hexbytes, mnemonic in self.corpus:
            irsb = lift(hexbytes)
            if irsb.jumpkind == "Ijk_NoDecode":
                undecoded.append((hexbytes, mnemonic))

        unexpected = [(h, m) for h, m in undecoded if m.split()[0] not in KNOWN_UNDECODED]
        assert not unexpected, "unexpectedly undecoded:\n" + "\n".join(f"  {h}  {m}" for h, m in unexpected[:20])

    def test_decoded_blocks_typecheck(self):
        for hexbytes, mnemonic in self.corpus:
            irsb = lift(hexbytes)
            if irsb.jumpkind == "Ijk_NoDecode":
                continue
            assert irsb.typecheck(), f"typecheck failed for {mnemonic} ({hexbytes})"

    def test_known_gaps_still_missing(self):
        """If a gap starts decoding, KNOWN_UNDECODED is stale -- tighten it."""
        seen = set()
        for hexbytes, mnemonic in self.corpus:
            head = mnemonic.split()[0]
            if head in KNOWN_UNDECODED and lift(hexbytes).jumpkind == "Ijk_NoDecode":
                seen.add(head)
        assert seen == KNOWN_UNDECODED, f"no longer undecoded: {KNOWN_UNDECODED - seen}"


class TestAVX512Lifting(unittest.TestCase):
    """Golden IR for the EVEX features that are easy to get wrong."""

    def test_zmm_registers_are_512_bit(self):
        # vaddps %zmm2, %zmm1, %zmm0
        irsb = lift("62f1744858c2")
        text = str(irsb)
        assert "GET:V512(zmm1)" in text
        assert "GET:V512(zmm2)" in text
        assert "PUT(zmm0)" in text

    def test_merge_masking_reads_the_destination(self):
        # vaddps %zmm2, %zmm1, %zmm0{%k1} -- the old zmm0 is blended back in
        irsb = lift("62f1744958c2")
        text = str(irsb)
        assert "GET:I64(k1)" in text
        assert "ExpandBitsToV512" in text
        assert "GET:V512(zmm0)" in text, "merge-masking must read the destination"

    def test_zero_masking_does_not_read_the_destination(self):
        # vaddps %zmm2, %zmm1, %zmm0{%k1}{z}
        irsb = lift("62f174c958c2")
        text = str(irsb)
        assert "ExpandBitsToV512" in text
        assert "GET:V512(zmm0)" not in text, "zero-masking must not read the destination"

    def test_vector_length_truncation(self):
        # the same opcode at EVEX.128/256/512 uses correspondingly sized IR
        for encoding, ty in (("62f1740858c2", "V128"), ("62f1742858c2", "V256"), ("62f1744858c2", "V512")):
            text = str(lift(encoding))
            assert "PUT(zmm0)" in text, encoding
            assert ty in text, encoding

    def test_opmask_register_ops(self):
        # kmovw %k1, %eax
        assert "GET:I16(k1)" in str(lift("c5f893c1"))

    def test_compare_into_opmask(self):
        # vpcmpgtd %zmm2, %zmm1, %k2
        text = str(lift("62f1754866d2"))
        assert "Cmp32Sx16" in text
        assert "PUT(k2)" in text

    def test_writemasked_compare_ands_the_mask(self):
        # vpcmpgtd %zmm2, %zmm1, %k2{%k3}
        text = str(lift("62f1754b66d2"))
        assert "GET:I64(k3)" in text
        assert "And64" in text

    def test_broadcast_load(self):
        # vpbroadcastd (%rsi), %zmm6
        assert "PUT(zmm6)" in str(lift("62f27d485836"))

    def test_ternlog(self):
        # vpternlogd $0xca, %zmm2, %zmm1, %zmm0
        assert "Ternlog32x16" in str(lift("62f3754825c2ca"))

    def test_unimplemented_evex_is_a_clean_decode_failure(self):
        """An opcode absent from the instruction table must not crash.

        The table only covers KNL/SKX, so real binaries will contain EVEX
        encodings it does not know; those have to come back as NoDecode.
        """
        decoded = nodecode = 0
        for opcode in range(256):
            encoding = "62f17d48" + f"{opcode:02x}" + "c2"
            if lift(encoding).jumpkind == "Ijk_NoDecode":
                nodecode += 1
            else:
                decoded += 1
        assert nodecode > 100, "expected most of the EVEX opcode space to be undecoded"
        assert decoded > 20, "expected a good part of the EVEX opcode space to decode"


class TestAVXRegression(unittest.TestCase):
    """AVX/AVX2 must be unaffected by the AVX-512 guest state re-layout.

    There was no AVX coverage here before AVX-512 landed, and the ZMM
    registers replaced the YMM ones in the guest state, so these guard the
    pre-existing behaviour.
    """

    def test_vmovdqa_ymm(self):
        # vmovdqa %ymm1, %ymm0. The ymm registers are the low half of the zmm
        # ones, and pyvex names a guest offset by its register regardless of
        # the access width, so a 256-bit access reads back as zmm1/zmm0.
        text = str(lift("c5fd6fc1"))
        assert "GET:V256(zmm1)" in text
        assert "PUT(zmm0) =" in text
        assert "PUT(zmm0hy) = 0" in text, "VEX.256 must zero bits 511:256"

    def test_vaddps_ymm(self):
        # vaddps %ymm2, %ymm1, %ymm0
        text = str(lift("c5f458c2"))
        assert "Add32Fx8" in text

    def test_xmm_write_zeroes_upper_lanes(self):
        # vmovaps %xmm1, %xmm0 -- VEX.128 zeroes bits 511:128
        text = str(lift("c5f828c1"))
        assert "GET:V128(zmm1)" in text
        assert "PUT(ymm0hx) = 0" in text, "VEX.128 must zero bits 255:128"
        assert "PUT(zmm0hy) = 0" in text, "VEX.128 must zero bits 511:256"

    def test_sse_still_lifts(self):
        # addps %xmm1, %xmm0
        assert "Add32Fx4" in str(lift("0f58c1"))

    def test_ymm_offsets_match_zmm_bases(self):
        """ymmN must alias the low half of zmmN, not live somewhere else."""
        for i in range(16):
            zmm = ARCH_AMD64.get_register_offset(f"zmm{i}")
            assert ARCH_AMD64.get_register_offset(f"ymm{i}") == zmm
            assert ARCH_AMD64.get_register_offset(f"xmm{i}") == zmm


if __name__ == "__main__":
    unittest.main()
