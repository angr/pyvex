import pyvex


def test_riscv64_sc():
    # sc.{w,d} builds an IRStmt_LLSC whose result the IR contract fixes at Ity_I1. Giving the temp a
    # wider type makes the statement fail the IR sanity check, and libVEX then reports the whole
    # block as NoDecode -- so every store-conditional in a RISC-V binary became undecodable bytes.
    for encoding, name in ((b"\xaf\x36\xb9\x18", "sc.d a3, a1, (s2)"), (b"\xaf\x26\xb9\x18", "sc.w a3, a1, (s2)")):
        irsb = pyvex.lift(encoding + b"\x82\x80", 0x1000, pyvex.ARCH_RISCV64_LE)
        assert irsb.jumpkind != "Ijk_NoDecode", name
        assert irsb.instruction_addresses[0] == 0x1000
        assert irsb.instruction_addresses[1] == 0x1004


def test_riscv64_float_comparisons():
    # feq and flt compare into a temp the same way fle does. fle wraps the Ity_I1 comparison in
    # Iop_1Uto32 to match its Ity_I32 temp; feq and flt did not, and failed the sanity check.
    encodings = {
        "feq.s": b"\x53\x25\xb5\xa0",
        "flt.s": b"\x53\x15\xb5\xa0",
        "fle.s": b"\x53\x05\xb5\xa0",
        "feq.d": b"\x53\x25\xb5\xa2",
        "flt.d": b"\x53\x15\xb5\xa2",
        "fle.d": b"\x53\x05\xb5\xa2",
    }
    for name, encoding in encodings.items():
        irsb = pyvex.lift(encoding + b"\x82\x80", 0x1000, pyvex.ARCH_RISCV64_LE)
        assert irsb.jumpkind != "Ijk_NoDecode", name
        assert irsb.instruction_addresses[1] == 0x1004, name


if __name__ == "__main__":
    test_riscv64_sc()
    test_riscv64_float_comparisons()
