import pyvex


def test_mipsn32_uses_the_64_bit_guest():
    """
    n32 and O64 hold a 64-bit MIPS instruction stream in an ELFCLASS32 container, so the guest
    is VexArchMIPS64 while a pointer is 32 bits wide. `sd` -- the 64-bit store a non-leaf
    prologue uses to spill $gp -- is where the 32-bit guest goes wrong: it lifts the same word
    as a 4-byte store instead of refusing it.

      10000110: 27bdffe0 ; addiu $sp, $sp, -0x20
      10000114: ffbc0008 ; sd    $gp, 8($sp)
      10000118: 3c1c0002 ; lui   $gp, 2
    """
    data = b"\x27\xbd\xff\xe0" b"\xff\xbc\x00\x08" b"\x3c\x1c\x00\x02"
    kwargs = {"data": data, "mem_addr": 0x10000110, "num_inst": 3, "opt_level": 0}

    n32 = pyvex.IRSB(arch=pyvex.ARCH_MIPSN32_BE, **kwargs)
    m64 = pyvex.IRSB(arch=pyvex.ARCH_MIPS64_BE, **kwargs)
    m32 = pyvex.IRSB(arch=pyvex.ARCH_MIPS32_BE, **kwargs)

    assert n32.instructions == 3
    assert n32.size == 12
    # n32 must lift exactly as the 64-bit architecture does.
    assert [str(stmt) for stmt in n32.statements] == [str(stmt) for stmt in m64.statements]
    assert "Ity_I64" in n32.tyenv.types
    # The 32-bit guest has no 64-bit value anywhere, which is the store being silently narrowed.
    assert "Ity_I64" not in m32.tyenv.types

    # The word size is the only thing n32 does not share with the 64-bit architecture.
    assert pyvex.ARCH_MIPSN32_BE.bits == 32
    assert pyvex.ARCH_MIPSN32_BE.vex_arch == pyvex.ARCH_MIPS64_BE.vex_arch


if __name__ == "__main__":
    test_mipsn32_uses_the_64_bit_guest()
