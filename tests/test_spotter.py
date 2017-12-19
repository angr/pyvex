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
    ARCHES=['ARMEL']
    instrs = [Instruction_IMAGINARY]

register(ImaginarySpotter)

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
   78 | t68 = Add27((0xa :: Ity_I27),(0x14 :: Ity_I27))
"""

def test_embedded():
    b = pyvex.block.IRSB('\x07\x21' * 3 + '\x45\xe1' + '\x07\x21' * 6, 1, archinfo.ArchARMEL())
    nose.tools.assert_in(embedded_goal, str(b))

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
    ARCHES = ['ARMEL']
    instrs = [Instruction_MSR, Instruction_CPSIEI, Instruction_CPSIEF]

register(CortexSpotter)

def test_full_binary():
    p = angr.Project(os.path.join(test_location, 'armel', 'RTOSDemo.axf.issue_685'))
    st = p.factory.call_state(0x000013ce+1)
    b = st.block().vex
    simgr = p.factory.simgr(st)
    simgr.step()
    nose.tools.assert_equal(b.jumpkind, 'Ijk_Sys_syscall')
    nose.tools.assert_equal(simgr.active[0].addr, 0x13fb)

def test_long_block():
    b = pyvex.block.IRSB('\x50' * 6000, 0, archinfo.ArchX86())
    nose.tools.assert_equal(b.size, 6000)

if __name__ == '__main__':
    test_basic()
    test_embedded()
    test_full_binary()
    test_long_block()
