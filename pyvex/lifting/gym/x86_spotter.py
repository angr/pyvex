from .. import register
from ..util import GymratLifter, Instruction, Type

# pylint: disable=missing-class-docstring

class Instruction_RDMSR(Instruction):
    name = "RDMSR"
    bin_format = "0000111100110010"  # 0f 32

    def compute_result(self, *args):
        ecx = self.get('ecx', Type.int_32)
        result = self.dirty(Type.int_64, '%sg_dirtyhelper_RDMSR' % self.arch.name.lower(), (ecx,))
        edx = result.narrow_high(Type.int_32)
        eax = result.narrow_low(Type.int_32)
        if self.arch.bits == 32:
            self.put(eax, 'eax')
            self.put(edx, 'edx')
        else:
            self.put(eax.widen_unsigned(Type.int_64), 'rax')
            self.put(edx.widen_unsigned(Type.int_64), 'rdx')

class Instruction_XGETBV(Instruction):
    name = "XGETBV"
    bin_format = "000011110000000111010000"  # 0f 01 d0

    def compute_result(self, *args):
        ecx = self.get('ecx', Type.int_32)
        result = self.dirty(Type.int_64, '%sg_dirtyhelper_XGETBV' % self.arch.name.lower(), (ecx,))
        edx = result.narrow_high(Type.int_32)
        eax = result.narrow_low(Type.int_32)
        if self.arch.bits == 32:
            self.put(eax, 'eax')
            self.put(edx, 'edx')
        else:
            self.put(eax.widen_unsigned(Type.int_64), 'rax')
            self.put(edx.widen_unsigned(Type.int_64), 'rdx')

class AMD64Spotter(GymratLifter):
    instrs = [Instruction_RDMSR, Instruction_XGETBV]

class X86Spotter(GymratLifter):
    instrs = [Instruction_RDMSR, Instruction_XGETBV]

register(AMD64Spotter, 'AMD64')
register(X86Spotter, 'X86')
