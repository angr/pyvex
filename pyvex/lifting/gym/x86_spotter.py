from ..util.lifter_helper import GymratLifter
from ..util.instr_helper import Instruction
from .. import register
import logging

l = logging.getLogger(__name__)


class X86Instruction(Instruction): # pylint: disable=abstract-method
    pass

class Instruction_ENDBR(X86Instruction):
    name = "ENDBR"
    bin_format = '1111001100001111000111101111101b'

    def compute_result(self): # pylint: disable=arguments-differ
        # Perhaps, if one wanted to verify ENDBR behavior during compilation
        # Throw some CCall or whatever in here.
        if self.data['b'] == '1':
            l.debug("Ignoring ENDBR32 instruction at %#x.", self.addr)
        elif self.data['b'] == '0':
            l.debug("Ignoring ENDBR64 instruction at %#x.", self.addr)

class X86Spotter(GymratLifter):
    instrs = [
        Instruction_ENDBR]

register(X86Spotter, "X86")
register(X86Spotter, "AMD64")
