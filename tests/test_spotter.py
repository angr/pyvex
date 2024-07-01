import os

import pyvex
import pyvex.lifting
from pyvex.lifting import register
from pyvex.lifting.util import GymratLifter, Instruction, Type

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../binaries/tests"))


class Instruction_IMAGINARY(Instruction):
    bin_format = bin(0x0F0B)[2:].zfill(16)
    name = "IMAGINARY"

    def compute_result(self):
        a = self.constant(10, Type.int_27)
        b = self.constant(20, Type.int_27)
        a + b


class ImaginarySpotter(GymratLifter):
    instrs = [Instruction_IMAGINARY]


register(ImaginarySpotter, "X86")

basic_goal = """
IRSB {
   t0:Ity_I27

   00 | ------ IMark(0x1, 2, 0) ------
   01 | t0 = Add27((0xa :: Ity_I27),(0x14 :: Ity_I27))
   NEXT: PUT(eip) = 0x00000003; Ijk_Boring
}
"""


def test_basic():
    b = pyvex.block.IRSB(b"\x0f\x0b", 1, pyvex.ARCH_X86)
    assert str(b).strip() == basic_goal.strip()


def test_embedded():
    b = pyvex.block.IRSB(b"\x50" * 3 + b"\x0f\x0b" + b"\x50" * 6, 1, pyvex.ARCH_X86)
    for i, stmt in enumerate(b.statements):
        if type(stmt) is pyvex.stmt.IMark and stmt.addr == 0x4 and stmt.len == 2 and stmt.delta == 0:
            imaginary_trans_stmt = b.statements[i + 1]
            assert type(imaginary_trans_stmt) is pyvex.stmt.WrTmp
            addexpr = imaginary_trans_stmt.data
            assert type(addexpr) is pyvex.expr.Binop
            assert addexpr.op == "Iop_Add27"
            arg1, arg2 = addexpr.args
            assert type(arg1) is pyvex.expr.Const
            assert arg1.con.value == 10
            assert type(arg2) is pyvex.expr.Const
            assert arg2.con.value == 20
            return
    assert False, "Could not find matching IMark"


class Instruction_MSR(Instruction):
    bin_format = bin(0x8808F380)[2:].zfill(32)
    name = "MSR.W"

    def compute_result(self):
        a = self.constant(10, Type.int_27)
        b = self.constant(20, Type.int_27)
        a + b


class Instruction_CPSIEI(Instruction):
    bin_format = bin(0xB662)[2:].zfill(16)
    name = "CPSIE I"

    def compute_result(self):
        a = self.constant(10, Type.int_27)
        b = self.constant(20, Type.int_27)
        a + b


class Instruction_CPSIEF(Instruction):
    bin_format = bin(0xB661)[2:].zfill(16)
    name = "CPSIE F"

    def compute_result(self):
        a = self.constant(10, Type.int_27)
        b = self.constant(20, Type.int_27)
        a + b


class CortexSpotter(GymratLifter):
    instrs = [Instruction_MSR, Instruction_CPSIEI, Instruction_CPSIEF]


register(CortexSpotter, "ARMEL")


def test_tmrs():
    arch = pyvex.ARCH_ARM_LE
    ins = b"\xef\xf3\x08\x82"
    b = pyvex.block.IRSB(ins, 1, arch)
    assert b.jumpkind == "Ijk_Boring"
    assert isinstance(b.statements[1].data, pyvex.expr.Get)
    assert arch.translate_register_name(b.statements[1].data.offset) in ["sp", "r13"]
    assert isinstance(b.statements[2], pyvex.stmt.Put)


def test_tmsr():
    arch = pyvex.ARCH_ARM_LE
    inss = b"\x82\xf3\x08\x88"
    b = pyvex.block.IRSB(inss, 1, arch, opt_level=3)
    assert b.jumpkind == "Ijk_Boring"
    assert isinstance(b.statements[1].data, pyvex.expr.Get)
    assert arch.translate_register_name(b.statements[1].data.offset) == "r2"
    assert isinstance(b.statements[2], pyvex.stmt.Put)


if __name__ == "__main__":
    test_basic()
    test_embedded()
    test_tmrs()
    test_tmsr()
