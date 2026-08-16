import pyvex

# lui $v1, 0x8004 ; addiu $v0, $v1, -0x3098 -- two instructions every MIPS decodes.
PREFIX = b"\x3c\x03\x80\x04\x24\x62\xcf\x68"
BASE = 0x80010938
RESERVED = BASE + len(PREFIX)

# One encoding per group of MIPS64-only instructions that guest_mips_toIR.c used to
# decode unconditionally. Each builds 64-bit IR, which on a 32-bit guest fails either
# the vassert in putIReg or the IR sanity check.
MIPS64_ONLY = {
    "ld $a0, -0x3098($v1)": b"\xdc\x64\xcf\x68",
    "daddiu $v0, $v1, 0x7d": b"\x64\x62\x00\x7d",
    "daddu $v0, $v1, $a0": b"\x00\x64\x10\x2d",
    "dsll $v0, $v0, 0x17": b"\x00\x02\x15\xf8",
    "dsll32 $v1, $v1, 0": b"\x00\x03\x18\x3c",
    "dsrl32 $v0, $v0, 0x14": b"\x00\x02\x15\x3e",
    "dmult $v0, $v1": b"\x00\x43\x00\x1c",
    "ldl $t0, 0($v0)": b"\x68\x48\x00\x00",
    "ldr $t0, 7($v0)": b"\x6c\x48\x00\x07",
    "sdl $t0, 0($a2)": b"\xb0\xc8\x00\x00",
    "sdr $t0, 7($a2)": b"\xb4\xc8\x00\x07",
    "dmtc1 $zero, $f0": b"\x44\xa0\x00\x00",
    "dext $a1, $v1, 0, 1": b"\x7c\x65\x00\x03",
    "dsbh $a1, $a0": b"\x7c\x04\x28\xa4",
    "dclz $a1, $v1": b"\x70\x64\x28\x24",
}

# The OCTEON "plus 32" branches test a bit above 31, so they are MIPS64-only too.
# They need a delay slot, hence the extra word.
MIPS64_ONLY_BRANCHES = {
    "bbit032 $v1, 0, .+0x40": b"\xd8\x64\x00\x10",
    "bbit132 $v1, 0, .+0x40": b"\xf8\x64\x00\x10",
}

# Decoded in 32-bit mode by the cases that handle them, and so left alone.
STILL_DECODED_ON_MIPS32 = {
    "sd $ra, 0x5c8($sp)": b"\xff\xbf\x05\xc8",
    "lwu $a0, 0x10($v1)": b"\x9c\x64\x00\x10",
}

# The guard shares these opcode slots with encodings a 32-bit guest does decode,
# so it is narrower than the mnemonic. Each of these differs from a rejected
# encoding only in the field that makes the difference -- sa, or the low 11 bits.
NARROWER_THAN_THE_MNEMONIC = {
    # SPECIAL function 0x1c-0x1f with sa != 0 is the MIPSR6 group, not DMULT.
    "dmul $v0, $v1, $a0": b"\x00\x64\x10\x9c",
    # COP1 rs=1 with the low 11 bits set is not DMFC1.
    "cop1 rs=1, low bits set": b"\x44\x22\x15\x14",
    # SPECIAL3 DBSHFL with sa outside {2, 5} is not DSBH or DSHD.
    "dbshfl sa=0x0b": b"\x7c\x04\x2a\xe4",
    # The 32-bit OCTEON branches, which differ from bbit032/bbit132 by one bit.
    "bbit0 $v1, 0, .+0x40": b"\xc8\x64\x00\x10",
    "bbit1 $v1, 0, .+0x40": b"\xe8\x64\x00\x10",
}


def test_mips32_reserved_instruction_keeps_the_decoded_prefix():
    # A MIPS64-only encoding is a Reserved Instruction on a 32-bit guest. Decoding it
    # anyway assigned an I64 to an I32 guest register, and the resulting assertion
    # unwound the whole translation: the caller got an empty IRSB whose Ijk_NoDecode
    # pointed at the start of the block rather than at the instruction that failed, so
    # the instructions decoded ahead of it were lost too.
    for name, encoding in MIPS64_ONLY.items():
        irsb = pyvex.lift(PREFIX + encoding, BASE, pyvex.ARCH_MIPS32_BE)
        assert irsb.jumpkind == "Ijk_NoDecode", name
        assert irsb.size == len(PREFIX), name
        assert irsb.instruction_addresses[:2] == (BASE, BASE + 4), name
        assert irsb.next.con.value == RESERVED, name


def test_mips64_still_decodes_the_same_instructions():
    for name, encoding in MIPS64_ONLY.items():
        irsb = pyvex.lift(PREFIX + encoding + b"\x03\xe0\x00\x08\x00\x00\x00\x00", BASE, pyvex.ARCH_MIPS64_BE)
        assert irsb.jumpkind != "Ijk_NoDecode", name
        assert RESERVED in irsb.instruction_addresses, name


def test_mips32_still_decodes_what_it_used_to():
    for name, encoding in STILL_DECODED_ON_MIPS32.items():
        irsb = pyvex.lift(PREFIX + encoding, BASE, pyvex.ARCH_MIPS32_BE)
        assert RESERVED in irsb.instruction_addresses, name


def test_mips32_reserved_branch_keeps_the_decoded_prefix():
    # A branch needs its delay slot, so these carry one. Without the guard the
    # whole translation is lost exactly as for the non-branch encodings.
    for name, encoding in MIPS64_ONLY_BRANCHES.items():
        irsb = pyvex.lift(PREFIX + encoding + b"\x00\x00\x00\x00", BASE, pyvex.ARCH_MIPS32_BE)
        assert irsb.jumpkind == "Ijk_NoDecode", name
        assert irsb.size == len(PREFIX), name
        assert irsb.next.con.value == RESERVED, name


def test_mips64_still_decodes_the_reserved_branches():
    for name, encoding in MIPS64_ONLY_BRANCHES.items():
        irsb = pyvex.lift(PREFIX + encoding + b"\x00\x00\x00\x00", BASE, pyvex.ARCH_MIPS64_BE)
        assert irsb.jumpkind != "Ijk_NoDecode", name


def test_the_guard_is_narrower_than_the_mnemonic():
    # Each of these lands in an opcode slot the guard also covers, and each is
    # decoded by a 32-bit guest today, so rejecting it would be a regression.
    for name, encoding in NARROWER_THAN_THE_MNEMONIC.items():
        irsb = pyvex.lift(PREFIX + encoding + b"\x00\x00\x00\x00", BASE, pyvex.ARCH_MIPS32_BE)
        assert irsb.size > len(PREFIX), name
        assert irsb.jumpkind != "Ijk_NoDecode", name


if __name__ == "__main__":
    test_mips32_reserved_instruction_keeps_the_decoded_prefix()
    test_mips64_still_decodes_the_same_instructions()
    test_mips32_still_decodes_what_it_used_to()
    test_mips32_reserved_branch_keeps_the_decoded_prefix()
    test_mips64_still_decodes_the_reserved_branches()
    test_the_guard_is_narrower_than_the_mnemonic()
