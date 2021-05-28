import os
import pyvex
import angr
import archinfo
from pyvex.lifting import register
from pyvex.lifting.util import *
import nose
import pyvex.lifting

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

class Instruction_IMAGINARY(Instruction):
    bin_format = bin(0x0f0b)[2:].zfill(16)
    name = 'IMAGINARY'

    def compute_result(self):
        a = self.constant(10, Type.int_27)
        b = self.constant(20, Type.int_27)
        a + b

class ImaginarySpotter(GymratLifter):
    instrs = [Instruction_IMAGINARY]

register(ImaginarySpotter, 'X86')

basic_goal = """
IRSB {
   t0:Ity_I27

   00 | ------ IMark(0x1, 2, 0) ------
   01 | t0 = Add27((0xa :: Ity_I27),(0x14 :: Ity_I27))
   NEXT: PUT(eip) = 0x00000003; Ijk_Boring
}
"""

def test_basic():
    b = pyvex.block.IRSB(b'\x0f\x0b', 1, archinfo.ArchX86())
    nose.tools.assert_equal(str(b).strip(), basic_goal.strip())

def test_embedded():
    b = pyvex.block.IRSB(b'\x50' * 3 + b'\x0f\x0b' + b'\x50' * 6, 1, archinfo.ArchX86())
    for i, stmt in enumerate(b.statements):
        if type(stmt) is pyvex.stmt.IMark and stmt.addr == 0x4 and stmt.len == 2 and stmt.delta == 0:
            imaginary_trans_stmt = b.statements[i+1]
            nose.tools.assert_is(type(imaginary_trans_stmt), pyvex.stmt.WrTmp)
            addexpr = imaginary_trans_stmt.data
            nose.tools.assert_is(type(addexpr), pyvex.expr.Binop)
            nose.tools.assert_equal(addexpr.op, 'Iop_Add27')
            arg1, arg2 = addexpr.args
            nose.tools.assert_is(type(arg1), pyvex.expr.Const)
            nose.tools.assert_equal(arg1.con.value, 10)
            nose.tools.assert_is(type(arg2), pyvex.expr.Const)
            nose.tools.assert_equal(arg2.con.value, 20)
            return
    nose.tools.assert_false(True, msg='Could not find matching IMark')

class Instruction_MSR(Instruction):
    bin_format = bin(0x8808f380)[2:].zfill(32)
    name = 'MSR.W'

    def compute_result(self):
        a = self.constant(10, Type.int_27)
        b = self.constant(20, Type.int_27)
        c = a + b

class Instruction_CPSIEI(Instruction):
    bin_format = bin(0xb662)[2:].zfill(16)
    name = 'CPSIE I'

    def compute_result(self):
        a = self.constant(10, Type.int_27)
        b = self.constant(20, Type.int_27)
        c = a + b

class Instruction_CPSIEF(Instruction):
    bin_format = bin(0xb661)[2:].zfill(16)
    name = 'CPSIE F'

    def compute_result(self):
        a = self.constant(10, Type.int_27)
        b = self.constant(20, Type.int_27)
        c = a + b

class CortexSpotter(GymratLifter):
    instrs = [Instruction_MSR, Instruction_CPSIEI, Instruction_CPSIEF]

register(CortexSpotter, 'ARMEL')

def test_full_binary():
    p = angr.Project(os.path.join(test_location, 'armel', 'RTOSDemo.axf.issue_685'), arch="ARMEL")
    st = p.factory.call_state(0x000013ce+1)
    b = st.block().vex
    simgr = p.factory.simulation_manager(st)
    simgr.step()
    nose.tools.assert_equal(b.jumpkind, 'Ijk_Sys_syscall')
    nose.tools.assert_equal(simgr.active[0].regs.ip_at_syscall.args[0], 0x13fb)

def test_tmrs():
    test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))
    p = angr.Project(os.path.join(test_location, 'armel', 'helloworld'), arch="ARMEL")
    ins = b'\xef\xf3\x08\x82'
    b = pyvex.block.IRSB(ins, 1, p.arch)
    nose.tools.assert_equal(b.jumpkind, "Ijk_Boring")
    nose.tools.assert_equal(type(b.statements[1].data),pyvex.expr.Get)
    nose.tools.assert_equal(p.arch.register_names.get(b.statements[1].data.offset , ''),"sp")
    nose.tools.assert_equal(type(b.statements[2]),pyvex.stmt.Put)

def test_tmsr():
    test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))
    p = angr.Project(os.path.join(test_location, 'armel', 'helloworld'), arch="ARMEL")
    inss = b'\x82\xf3\x08\x88'
    b = pyvex.block.IRSB(inss, 1, p.arch, opt_level=3)
    nose.tools.assert_equal(b.jumpkind, "Ijk_Boring")
    nose.tools.assert_equal(type(b.statements[1].data),pyvex.expr.Get)
    nose.tools.assert_equal(p.arch.register_names.get(b.statements[1].data.offset , ''),"r2")
    nose.tools.assert_equal(type(b.statements[2]),pyvex.stmt.Put)

if __name__ == '__main__':
    test_basic()
    test_embedded()
    test_full_binary()
    test_tmrs()
    test_tmsr()
