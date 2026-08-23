import pyvex

# exrl %r1,0x400408; br %r14; xc 0(0,%r2),0(%r3); padding
EXPANDABLE = b"\xc6\x10\x00\x00\x00\x04\x07\xfe\xd7\x00\x20\x00\x30\x00\x7d\xa7"

# The same block with an execute target whose first byte is 0x00. libVEX
# selects the arm of s390_irgen_EX that has no code information yet on that
# byte, and caches the target in a global that outlives the lift.
LEADING_ZERO_TARGET = b"\xc6\x10\x00\x00\x00\x04\x07\xfe\x00\x07\x20\x00\x30\x00\x7d\xa7"


def expands_execute_target(data):
    return "0xd700200030000000" in str(pyvex.lift(data, 0x400400, pyvex.ARCH_S390X))


def test_s390x_ex_leading_zero_target_does_not_persist():
    pyvex.lift(LEADING_ZERO_TARGET, 0x400400, pyvex.ARCH_S390X)
    assert expands_execute_target(EXPANDABLE)


if __name__ == "__main__":
    test_s390x_ex_leading_zero_target_does_not_persist()
