import logging
import bitstring
from .instr_helper import Instruction
from .vex_helper import *
from ...expr import *
from .. import LiftingException

l = logging.getLogger(__name__)

class Instruction_MRCMCR(Instruction):
    bin_format = 'cccc110PUNWLnnnnddddppppOOOOOOOO'
    # c = cond
    # d = CPd
    # O = Offset
    # p = CP#

    def compute_result(self):
        # TODO at least look at the conditionals
        # TODO Clobber the dst reg of MCR
        # TODO maybe treat coproc regs as simple storage (even though they are very much not)
        l.warning("Ignoring MRC/MCR instruction at %#08x" % self.addr)

class Instruction_CDP(Instruction):
    bin_format = 'cccc1110oooonnnnddddppppPPPxmmmm'
    # c = cond
    # d = CPd
    # O = Offset
    # p = CP#

    def compute_result(self):
        # TODO At least look at the conditionals
        # TODO Clobber the dest reg of LDC
        # TODO Maybe clobber the dst reg of CDP, if we're really adventurous
        l.warning("Ignoring CP op instruction at %#08x" % self.addr)




class ARMSpotter(GymratLifter):
    instrs = [Instruction_MRCMCR, Instruction_CDP]


register(ARMSpotter, "ARM")
register(ARMSpotter, "ARMEL")
