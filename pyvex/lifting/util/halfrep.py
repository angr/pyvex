
import logging
import bitstring

from .vex_helper import *

l = logging.getLogger(__name__)

class HalfRep(GymratLifter):
    """
    For when your lifter is lazy
    """
    REQUIRE_DATA_PY = True

    def create_bitstrm(self):
        self.bitstrm = bitstring.ConstBitStream(bytes=self.thedata)

    def lift(self, disassemble=False, dump_irsb=False):
        self.thedata = self.data[:self.max_bytes]
        if not self.arch.capstone:
            # Well, that won't work
            pass
        else:
        instr.jump(None, irsb_c.irsb.addr + irsb_c.irsb.size)
        irsb_c.irsb.jumpkind = JumpKind.NoDecode
        return self.irsb

    def pp_disas(self):
        disasstr = ""
        insts = self.disassemble()
        for addr, name, args in insts:
            args_str = ",".join(str(a) for a in args)
            disasstr += "%0#08x:\t%s %s\n" % (addr, name, args_str)
        print disasstr

    def error(self):
        return self.errors

    def disassemble(self):
        return self.lift(disassemble=True)


from ...expr import *
from .. import LiftingException
