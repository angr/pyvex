import struct
import archinfo
import pyvex
from functools import wraps
from pyvex.expr import *
from pyvex.lift import Lifter, register
from .vex_helper import *
from syntax_wrapper import VexValue
import logging
import bitstring

def is_empty(bitstrm):
    try:
        bitstrm.peek(1)
        return False
    except bitstring.ReadError:
        return True


class ParseError(Exception):
    pass


class GymratTranslator(Translator):
    """
    This is a base class for lifters that use Gymrat.
    For most architectures, all you need to do is subclass this, and set the property "instructions"
    to be a list of classes that define each instruction.
    By default, a lifter will decode instructions by attempting to instantiate every class until one works.
    This will use an IRSBCustomizer, which will, if it succeeds, add the appropriate VEX instructions to a pyvex IRSB.
    pyvex, when lifting a block of code for this architecture, will call the method "lift", which will produce the IRSB
    of the lifted code.
    """
    def __init__(self, irsb, max_inst, max_bytes, bytes_offset, **kwargs):
        super(GymratTranslator, self).__init__(self, irsb, max_inst, max_bytes, bytes_offset, **kwargs)
        self.logger = logging.getLogger('translator')
        self.logger.setLevel(logging.DEBUG)

        if 'asm' in kwargs:
            if 'binary' in kwargs:
                raise Exception('Cannnot translate both assembly and binary')
            pass
        elif 'binary' in kwargs:
            pass
        else:
            raise Exception('Translator must be given either assembly or binary')

    def _from_binary(self, data):
        if 'CData' in str(type(data)):
            thedata = "".join([chr(data[x]) for x in range(max_bytes)])
        else:
            thedata = data
        self.bitstrm = bitstring.ConstBitStream(bytes=thedata)

    def _from_asm(self, asm):
        pass


#     def __init__(self, irsb, data, max_inst, max_bytes, bytes_offset, opt_level=None,
#                     traceflags=None, allow_lookback=None):
#         super(GymratLifter, self).__init__(irsb, data, max_inst, max_bytes,
#                 bytes_offset, opt_level, traceflags, allow_lookback)
#         self.logger = logging.getLogger('lifter')
#         self.logger.setLevel(logging.DEBUG)

    def binary_to_instructions(self): # TODO THIS DOES NOT WORK DO NOT USE THIS THIS WILL BREAK
        self._to_instructions(self, sometypeofstrm, lambda x, *args, **kwargs: x.binary_to_instructions(*args, **kwargs))
        return self.instrs

    def asm_to_instructions(self): # TODO THIS DOES NOT WORK DO NOT USE THIS THIS WILL BREAK
        self._to_instructions(self, sometypeofstrm, lambda x, *args, **kwargs: x.binary_to_instructions(*args, **kwargs))
        return self.instrs

    def _to_instructions(self, srcstrm, convert_func):
        try:
            count = 0
            disas = []
            if not self.max_inst:
                self.max_inst = 1000000
            addr = self.irsb._addr
            bytepos = self.bitstrm.bytepos
            while (count < self.max_inst
                    and srcstrm.bytepos < self.max_bytes
                    and not is_empty(srcstrm)):
                # Try every instruction until one works
                for possible_instr in self.instrs:
                    try:
                        instr = possible_instr(self.stcstrm, self.irsb.arch.memory_endness, addr) # TODO write a stream class that accounts for endianness or figure out how to use bitstring
                        break
                    except ParseError:
                        pass
                    except Exception, e:
                        self.logger.debug(e.message)
                else:
                    errorstr = 'Unknown instruction at position %d' % self.bitstrm.bytepos
                    self.logger.critical(errorstr)
                    self.logger.critical("Address: %#08x" % addr)
                    raise Exception(errorstr)

                self.instrs.append(instr)
                if instr.ends_block:
                    return

                addr += self.bitstrm.bytepos - bytepos
                pos = self.bitstrm.bytepos
                count += 1
        except Exception, e:
            self.errors = e.message
            self.logger.exception("Error decoding block:")
            raise e

    def instructions_to_asm(self):
        return [ins.to_asm() for ins in self.instrs]

    def instructions_to_binary(self):
        return [ins.to_binary() for ins in self.instrs]

    def instructions_to_vex(self):
        irsb_c = IRSBCustomizer(self.irsb)
        for ins in self.instrs: # TODO probably check if self.instrs actually exist...
            ins.to_vex(irsb_c)
        return self.irsb


#    def encode(self):
#         try:
#             count = 0
#             disas = []
#             if not self.max_inst:
#                 self.max_inst = 1000000
#             addr = self.irsb._addr
#             while (count < self.max_inst
#                     and self.bitstrm.bytpose < self.max_bytes
#                     and not is_empty(self.bitstrm))
#                 for possible_instr in self.instrs:
#                     try:
#                         instr = possible_instr

#     def lift(self, disassemble=False, assemble=False, dump_irsb=False):
#         if disassemble:
#             return [instr.disassemble() for instr in self.decode()]
#         self.irsb.jumpkind = JumpKind.Invalid
#         irsb_c = IRSBCustomizer(self.irsb)
#         instructions = self.decode()
#         for i, instr in enumerate(instructions):
#             instr(irsb_c, instructions[:i], instructions[i+1:])
#             if irsb_c.irsb.jumpkind == JumpKind.Invalid:
#                 break
#         if dump_irsb:
#             self.irsb.pp()
#         return self.irsb

    def pp_disas(self, addr, name, args):
        args_str = ",".join(str(a) for a in args)
        return "%0#08x:\t%s %s" % (addr, name, args_str)

    def error(self): # TODO Figure out how we are doing errors
        return self.errors

if __name__ == '__main__':
    pass
