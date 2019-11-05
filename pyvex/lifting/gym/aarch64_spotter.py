from ..util.lifter_helper import GymratLifter
from ..util.instr_helper import Instruction
from .. import register
import logging

l = logging.getLogger(__name__)

class Aarch64Instruction(Instruction): # pylint: disable=abstract-method
    pass

class Instruction_SYSL(Aarch64Instruction):
    name = "SYSL"
    bin_format = "1101010100101qqqnnnnmmmmppprrrrr"

    def compute_result(self): # pylint: disable=arguments-differ
        l.debug("Ignoring %s instruction at %#x. VEX cannot support this instruction. See pyvex/lifting/gym/aarch64_spotter.py",
(self.name, self.addr))

class Instruction_MSR(Aarch64Instruction):
    name = "MSR"
    bin_format = "11010101000ioqqqnnnnmmmmppprrrrr"

    def compute_result(self): # pylint: disable=arguments-differ
        l.debug("Ignoring %s instruction at %#x. VEX cannot support this instruction. See pyvex/lifting/gym/aarch64_spotter.py",
(self.name, self.addr))


class Instruction_MRS(Aarch64Instruction):
    name = "MRS"
    bin_format = "110101010011opppnnnnmmmmppprrrrr"

    def compute_result(self): # pylint: disable=arguments-differ
        l.debug("Ignoring %s instruction at %#x. VEX cannot support this instruction. See pyvex/lifting/gym/aarch64_spotter.py",
(self.name, self.addr))

class AARCH64Spotter(GymratLifter):
    instrs = [
        Instruction_MRS,
        Instruction_MSR,
        Instruction_SYSL]

register(AARCH64Spotter, "ARM64")
register(AARCH64Spotter, "AARCH64")

