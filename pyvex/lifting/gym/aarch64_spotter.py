import logging
from ..util.lifter_helper import GymratLifter
from ..util.instr_helper import Instruction
from .. import register

l = logging.getLogger(__name__)

class Aarch64Instruction(Instruction): # pylint: disable=abstract-method
    # NOTE: WARNING: There is no MRS, MSR, SYSL in VEX's ARM implementation
    # You must use straight nasty hacks instead.
    pass

class Instruction_SYSL(Aarch64Instruction):
    name = "SYSL"
    bin_format = "1101010100101qqqnnnnmmmmppprrrrr"

    def compute_result(self): # pylint: disable=arguments-differ
        l.debug("Ignoring SYSL instruction at %#x.", self.addr)

class Instruction_MSR(Aarch64Instruction):
    name = "MSR"
    bin_format = "11010101000ioqqqnnnnmmmmppprrrrr"

    def compute_result(self): # pylint: disable=arguments-differ
        l.debug("Ignoring MSR instruction at %#x.", self.addr)

class Instruction_MRS(Aarch64Instruction):
    name = "MRS"
    bin_format = "110101010011opppnnnnmmmmppprrrrr"

    def compute_result(self): # pylint: disable=arguments-differ
        l.debug("Ignoring MRS instruction at %#x.", self.addr)

class AARCH64Spotter(GymratLifter):
    instrs = [
        Instruction_MRS,
        Instruction_MSR,
        Instruction_SYSL]

register(AARCH64Spotter, "ARM64")
register(AARCH64Spotter, "AARCH64")
