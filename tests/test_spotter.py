import os
import angr
import pyvex
import archinfo
from pyvex.lift import register
from pyvex.lift.util import *
import nose

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

class Instruction_IMAGINARY(Instruction):
    bin_format = bin(0x45e1)[2:].zfill(16)
    name = 'IMAGINARY'

    def compute_result(self):
        a = self.constant(10, Type.int_27)
        b = self.constant(20, Type.int_27)
        a + b

class ImaginarySpotter(GymratLifter):
    instrs = [Instruction_IMAGINARY]

register(ImaginarySpotter, 'ARMEL')

basic_goal = """
IRSB {
   t0:Ity_I27

   00 | ------ IMark(0x1, 2, 0) ------
   01 | t0 = Add27((0xa :: Ity_I27),(0x14 :: Ity_I27))
   NEXT: PUT(pc) = None; Ijk_NoDecode
}
"""

def test_basic():
    b = pyvex.block.IRSB('\x45\xe1', 1, archinfo.ArchARMEL())
    nose.tools.assert_equal(str(b).strip(), basic_goal.strip())

embedded_goal = """
   77 | ------ IMark(0x7, 2, 0) ------
   78 | t146 = Add27((0xa :: Ity_I27),(0x14 :: Ity_I27))
"""

def test_embedded():
    b = pyvex.block.IRSB('\x07\x21' * 3 + '\x45\xe1' + '\x07\x21' * 6, 1, archinfo.ArchARMEL())
    for i, stmt in enumerate(b.statements):
        if type(stmt) is pyvex.stmt.IMark and stmt.addr == 0x7 and stmt.len == 2 and stmt.delta == 0:
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
    bin_format = bin(0x80f30888)[2:].zfill(32)
    name = 'MSR.W'

    def compute_result(self):
        a = self.constant(10, Type.int_27)
        b = self.constant(20, Type.int_27)
        c = a + b

class Instruction_CPSIEI(Instruction):
    bin_format = bin(0x62b6)[2:].zfill(16)
    name = 'CPSIE I'

    def compute_result(self):
        a = self.constant(10, Type.int_27)
        b = self.constant(20, Type.int_27)
        c = a + b

class Instruction_CPSIEF(Instruction):
    bin_format = bin(0x61b6)[2:].zfill(16)
    name = 'CPSIE F'

    def compute_result(self):
        a = self.constant(10, Type.int_27)
        b = self.constant(20, Type.int_27)
        c = a + b

class CortexSpotter(GymratLifter):
    instrs = [Instruction_MSR, Instruction_CPSIEI, Instruction_CPSIEF]

register(CortexSpotter, 'ARMEL')

def test_full_binary():
    p = angr.Project(os.path.join(test_location, 'armel', 'RTOSDemo.axf.issue_685'))
    st = p.factory.call_state(0x000013ce+1)
    b = st.block().vex
    simgr = p.factory.simgr(st)
    simgr.step()
    nose.tools.assert_equal(b.jumpkind, 'Ijk_Sys_syscall')
    nose.tools.assert_equal(simgr.active[0].addr, 0x13fb)

if __name__ == '__main__':
    test_basic()
    test_embedded()
    test_full_binary()
