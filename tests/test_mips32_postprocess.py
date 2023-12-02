import pyvex


def test_mips32_unconditional_jumps():
    # 0040000c: 10000002 ; <input:28> beq $zero, $zero, LABEL_ELSE_IF
    # 00400010: 00000000 ; <input:31> sll $zero, $zero, 0
    # 00400014: 08100012 ; <input:34> j LABEL_DONE
    # 00400018: <LABEL_ELSE_IF> ; <input:37> LABEL_ELSE_IF:
    irsb = pyvex.IRSB(
        data=(b"\x10\x00\x00\x02" b"\x00\x00\x00\x00"),
        mem_addr=0x40000C,
        arch=pyvex.ARCH_MIPS32_BE,
        num_inst=2,
        opt_level=0,
    )
    assert type(irsb.next) is pyvex.expr.Const
    assert irsb.next.con.value == 0x400018


if __name__ == "__main__":
    test_mips32_unconditional_jumps()
