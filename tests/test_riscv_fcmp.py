import os
import unittest

import pyvex

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../binaries/tests"))

# A gcc-built RISC-V shared object whose .text carries feq.s, flt.s and flt.d.
RISCV_BINARY = os.path.join(test_location, "riscv", "autotalent-autotalent.so")

# It is not position independent and its .text sits at file offset + 0x400000.
RISCV_BASE = 0x400000

OP_FP = 0b1010011
FCMP_S = 0b1010000  # funct7 of feq.s / flt.s / fle.s
FCMP_D = 0b1010001  # funct7 of feq.d / flt.d / fle.d
COMPARISONS = {0b000: "fle", 0b001: "flt", 0b010: "feq"}  # funct3


def fcmp_encodings(data: bytes) -> dict[int, str]:
    """Every OP-FP floating point comparison encoding in `data`, keyed by offset."""
    found = {}
    for offset in range(0, len(data) - 3, 2):
        word = int.from_bytes(data[offset : offset + 4], "little")
        funct7 = word >> 25
        if word & 0b1111111 != OP_FP or funct7 not in (FCMP_S, FCMP_D):
            continue
        comparison = COMPARISONS.get((word >> 12) & 0b111)
        if comparison is not None:
            found[offset] = comparison + (".s" if funct7 == FCMP_S else ".d")
    return found


@unittest.skipUnless(os.path.exists(RISCV_BINARY), "the angr/binaries checkout is not beside this one")
def test_float_comparisons_decode():
    with open(RISCV_BINARY, "rb") as fp:
        data = fp.read()

    encodings = fcmp_encodings(data)
    assert len(encodings) >= 25, f"expected the fixture to carry comparisons, found {len(encodings)}"

    undecoded = {}
    for offset, mnemonic in encodings.items():
        irsb = pyvex.lift(data[offset : offset + 4], RISCV_BASE + offset, pyvex.ARCH_RISCV64_LE)
        if irsb.size != 4 or irsb.jumpkind == "Ijk_NoDecode":
            undecoded[hex(RISCV_BASE + offset)] = mnemonic

    assert not undecoded, f"pyvex failed to decode {len(undecoded)} float comparisons: {undecoded}"


if __name__ == "__main__":
    test_float_comparisons_decode()
