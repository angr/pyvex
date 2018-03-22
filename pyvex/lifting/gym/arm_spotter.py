
from ..util.lifter_helper import GymratLifter
from ..util.instr_helper import Instruction
from ..util import JumpKind, Type
from .. import register
from ...expr import *

l = logging.getLogger(__name__)

class Instruction_MRCMCR(Instruction):
    name = "MRC/MCR"
    bin_format = 'cccc110PUNWLnnnnddddppppOOOOOOOO'
    # c = cond
    # d = CPd
    # O = Offset
    # p = CP#

    def compute_result(self):
        # TODO at least look at the conditionals
        # TODO Clobber the dst reg of MCR
        # TODO maybe treat coproc regs as simple storage (even though they are very much not)
        l.debug("Ignoring MRC/MCR instruction at %#x.", self.addr)


class Instruction_MSR(Instruction):
    name = "MSR"
    bin_format = 'cccc00i10d10xxxj1111ssssssssssss'
    #             11100011001000011111000010010001
    #             11100001011011111111000000000001

    def compute_result(self):
        l.debug("Ignoring MSR instruction at %#x.", self.addr)


class Instruction_MRS(Instruction):
    name = "MRS"
    bin_format = "cccc00010s001111dddd000000000000"

    def compute_result(self):
        l.debug("Ignoring MRS instruction at %#x.", self.addr)


class Instruction_STM(Instruction):
    name = "STM"
    bin_format = 'cccc100pusw0bbbbrrrrrrrrrrrrrrrr'

    def compute_result(self):
        l.debug("Ignoring STMxx instruction at %#x.", self.addr)


class Instruction_LDM(Instruction):
    name = "STM"
    bin_format = 'cccc100pusw1bbbbrrrrrrrrrrrrrrrr'

    def parse(self, bitstrm):
        data = super(Instruction_LDM, self).parse(bitstrm)
        self.reg_list = int(data['r'], 2)

    def compute_result(self):
        # test if PC will be set. If so, the jumpkind of this block should be Ijk_Ret
        if (self.reg_list >> 15) == 1:
            self.jump(0, self.constant(0, Type.int_32),
                      JumpKind.Ret
                      )

        l.debug("Ignoring LDMxx instruction at %#x.", self.addr)



class Instruction_CDP(Instruction):
    name = "CDP"
    bin_format = 'cccc1110oooonnnnddddppppPPPxmmmm'
    # c = cond
    # d = CPd
    # O = Offset
    # p = CP#

    def compute_result(self):
        # TODO At least look at the conditionals
        # TODO Clobber the dest reg of LDC
        # TODO Maybe clobber the dst reg of CDP, if we're really adventurous
        l.debug("Ignoring CDP op instruction at %#x.", self.addr)


class ARMSpotter(GymratLifter):
    instrs = [
        Instruction_MRCMCR,
        Instruction_MSR,
        Instruction_MRS,
        Instruction_STM,
        Instruction_LDM,
        Instruction_CDP
    ]


register(ARMSpotter, "ARM")
register(ARMSpotter, "ARMEL")
