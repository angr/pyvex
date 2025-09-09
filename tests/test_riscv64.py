#!/usr/bin/env python3
import pyvex


def test_riscv64_sll_srl_sla():
    arch = pyvex.ARCH_RISCV64_LE
    #           sll x7, x10, x17  ; srl x7, x10, x17  ; sra x7, x10, x17
    opcodes = [b"\xb3\x13\x15\x01",b"\xb3\x53\x15\x01",b"\xb3\x53\x15\x41"]
    for instr in opcodes: 
        irsb = pyvex.lift(instr, 0x100000, arch)
        irsb_str = str(irsb)
        assert "GET:I64(x17)" in irsb_str
        assert "64to8(" in irsb_str
        assert "And8(0x3f," in irsb_str # 0x3f = 63 => only use the lowest 6 bits
        assert "GET:I64(x10)" in irsb_str
        # Sar64, Shl64, Shr64 in irsb_str
        assert "PUT(x7) =" in irsb_str

def test_riscv64_sllw_srlw_slaw():
    arch = pyvex.ARCH_RISCV64_LE
    #           sllw x7, x10, x17 ; srlw x7, x10, x17 ; sraw x7, x10, x17
    opcodes = [b"\xbb\x13\x15\x01",b"\xbb\x53\x15\x01",b"\xbb\x53\x15\x41"]
    for instr in opcodes: 
        irsb = pyvex.lift(instr, 0x100000, arch)
        irsb_str = str(irsb)
        assert "GET:I64(x17)" in irsb_str
        assert "64to8(" in irsb_str
        assert "And8(0x1f," in irsb_str # 0x1f = 31 => only use the lowest 5 bits
        assert "GET:I64(x10)" in irsb_str
        assert "64to32(" in irsb_str
        # Sar32, Shl32, Shr32 in irsb_str
        assert "PUT(x7) =" in irsb_str


if __name__ == "__main__":
    test_riscv64_sll_srl_sla()
    test_riscv64_sllw_srlw_slaw()