# pylint: disable=no-self-use
"""A failed EVEX decode must not poison later amd64 lifts.

The EVEX prefix state is a global in the lifter. A hard decode failure inside
EVEX parsing used to longjmp out with that state still set, after which every
ModRM-using instruction in the process decoded with register numbers >= 16
and failed (seen as whole functions turning into Ijk_NoDecode stubs).
"""

import unittest

import pyvex
from pyvex import ARCH_AMD64

# "add %al,%ch" followed by a 0x62 (EVEX) prefix with the reserved mm=0 field:
# bytes from the middle of an instruction stream, i.e. not an instruction.
GARBAGE_WITH_BAD_EVEX = "02e862000000e949ffffff"
# mov %rdi,%rbp ; ret
MOV_RBP_RDI_RET = "4889fdc3"


def lift(hexbytes):
    return pyvex.lift(bytes.fromhex(hexbytes), 0x400000, ARCH_AMD64)


class TestEVEXStateReset(unittest.TestCase):
    def test_bad_evex_prefix_does_not_poison_following_lifts(self):
        before = lift(MOV_RBP_RDI_RET)
        assert before.jumpkind == "Ijk_Ret"
        assert before.instructions == 2

        bad = lift(GARBAGE_WITH_BAD_EVEX)
        assert bad.jumpkind == "Ijk_NoDecode"

        after = lift(MOV_RBP_RDI_RET)
        assert after.jumpkind == "Ijk_Ret"
        assert after.size == 4
        assert after.instructions == 2


if __name__ == "__main__":
    unittest.main()
