
import logging
import bitstring
from .vex_helper import *
from ...expr import *
from .. import LiftingException

l = logging.getLogger(__name__)

class HalfRep(GymratLifter):
    """
    For when your lifter is lazy
    """
    REQUIRE_DATA_PY = True

    def create_bitstrm(self):
        self.bitstrm = bitstring.ConstBitStream(bytes=self.thedata)

    def lift(self, disassemble=False, dump_irsb=False):
        irsb_c = IRSBCustomizer(self.irsb)
        if not self.arch.capstone:
            # Well, that won't work
            pass
        else:
            # Let's give it a try
            try:
                cs = self.arch.capstone
                insn = list(cs.disasm(self.data, self.irsb.addr, count=1))[0]
                s = "%#08x: %s %s" % (self.irsb.addr, insn.mnemonic, insn.op_str)
                with open("/tmp/halfrep.log", 'a') as f:
                    f.write(s + "\n")
                l.warning("HALFREP: %s" % s)
                irsb_c.imark(self.irsb.addr, len(insn.bytes), 0)
            except:
                l.exception("Error disassembling instruction during halfrep")
                return None
        irsb_c.irsb.jumpkind = JumpKind.NoDecode
        return self.irsb

    def error(self):
        return self.errors

    def disassemble(self):
        return self.lift(disassemble=True)


test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))


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

