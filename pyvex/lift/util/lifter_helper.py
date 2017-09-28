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

l = logging.getLogger(__name__)

def is_empty(bitstrm):
    try:
        bitstrm.peek(1)
        return False
    except bitstring.ReadError:
        return True


class ParseError(Exception):
    pass


class GymratLifter(Lifter):
    """
    This is a base class for lifters that use Gymrat.
    For most architectures, all you need to do is subclass this, and set the property "instructions"
    to be a list of classes that define each instruction.
    By default, a lifter will decode instructions by attempting to instantiate every class until one works.
    This will use an IRSBCustomizer, which will, if it succeeds, add the appropriate VEX instructions to a pyvex IRSB.
    pyvex, when lifting a block of code for this architecture, will call the method "lift", which will produce the IRSB
    of the lifted code.
    """
    def __init__(self, irsb, data, max_inst, max_bytes, bytes_offset, opt_level=None,
                    traceflags=None, allow_lookback=None):
        super(GymratLifter, self).__init__(irsb, data, max_inst, max_bytes,
                bytes_offset, opt_level, traceflags, allow_lookback)
        if 'CData' in str(type(data)):
            thedata = "".join([chr(data[x]) for x in range(max_bytes)])
        else:
            thedata = data
        self.thedata = thedata
        l.debug(repr(thedata))

    def create_bitstrm(self):
        self.bitstrm = bitstring.ConstBitStream(bytes=self.thedata)

    def decode(self):
        self.create_bitstrm()
        try:
            count = 0
            disas = []
            if not self.max_inst:
                self.max_inst = 1000000
            addr = self.irsb._addr
            l.debug("Starting block at address: " + hex(addr))
            bytepos = self.bitstrm.bytepos
            while (count < self.max_inst
                    and (self.bitstrm.bitpos + 7) / 8 < self.max_bytes
                    and not is_empty(self.bitstrm)):
                # Try every instruction until one works
                for possible_instr in self.instrs:
                    try:
                        #l.debug("Trying " + possible_instr.name)
                        instr = possible_instr(self.bitstrm, self.irsb.arch, addr)
                        break
                    except ParseError:
                        pass #l.exception(repr(possible_instr))
                    except Exception, e:
                        l.debug(e.message)
                        raise e
                else:
                    errorstr = 'Unknown instruction at bit position %d' % self.bitstrm.bitpos
                    l.debug(errorstr)
                    l.debug("Address: %#08x" % addr)
                    #raise Exception(errorstr)
                    break
                disas.append(instr)
                l.debug("Matched " + instr.name)
                addr += self.bitstrm.bytepos - bytepos
                bytepos = self.bitstrm.bytepos
                count += 1
            return disas
        except Exception, e:
            self.errors = e.message
            l.exception("Error decoding block:")
            raise e

    def lift(self, disassemble=False, dump_irsb=False):
        if disassemble:
            return [instr.disassemble() for instr in self.decode()]
        self.irsb.jumpkind = JumpKind.Invalid
        irsb_c = IRSBCustomizer(self.irsb)
        instructions = self.decode()
        l.debug("Decoding complete.")
        #self.pp_disas()
        for i, instr in enumerate(instructions):
            l.debug("Lifting instruction " + instr.name)
            instr(irsb_c, instructions[:i], instructions[i+1:])
            if irsb_c.irsb.jumpkind != JumpKind.Invalid:
                break
        else:
            instructions[-1].jump(None, instructions[-1].addr + instructions[-1].bytewidth)
        l.debug(self.irsb._pp_str())
        if dump_irsb:
            self.irsb.pp()
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

if __name__ == '__main__':
    pass
