
import logging
import bitstring

from .vex_helper import *
from ..lifter import Lifter
from ...const import vex_int_class

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

    __slots__ = ('bitstrm', 'errors', 'thedata', )

    REQUIRE_DATA_PY = True
    instrs = None

    def __init__(self, *args):
        super().__init__(*args)
        self.bitstrm = None
        self.errors = None
        self.thedata = None

    def create_bitstrm(self):
        self.bitstrm = bitstring.ConstBitStream(bytes=self.thedata)

    def _decode_next_instruction(self, addr):
        # Try every instruction until one works
        for possible_instr in self.instrs:
            try:
                l.info("Trying " + possible_instr.name)
                return possible_instr(self.bitstrm, self.irsb.arch, addr)
            # a ParserError signals that this instruction did not match
            # we need to try other instructions, so we ignore this error
            except ParseError:
                pass #l.exception(repr(possible_instr))
            # if we are out of input, ignore.
            # there may be other, shorter instructions that still match,
            # so we continue with the loop
            except bitstring.ReadError:
                pass

        # If no instruction matches, log an error
        errorstr = 'Unknown instruction at bit position %d' % self.bitstrm.bitpos
        l.debug(errorstr)
        l.debug("Address: %#08x" % addr)

    def decode(self):
        try:
            self.create_bitstrm()
            count = 0
            disas = []
            addr = self.irsb.addr
            l.debug("Starting block at address: " + hex(addr))
            bytepos = self.bitstrm.bytepos


            while (not is_empty(self.bitstrm)):
                instr = self._decode_next_instruction(addr)
                if not instr: break
                disas.append(instr)
                l.debug("Matched " + instr.name)
                addr += self.bitstrm.bytepos - bytepos
                bytepos = self.bitstrm.bytepos
                count += 1
            return disas
        except Exception as e:
            self.errors = str(e)
            l.exception("Error decoding block at offset {:#x} (address {:#x}):".format(bytepos, addr))
            raise

    def lift(self, disassemble=False, dump_irsb=False):
        self.thedata = self.data[:self.max_bytes] if isinstance(self.data, (bytes, bytearray, memoryview)) else self.data[:self.max_bytes].encode()
        l.debug(repr(self.thedata))
        instructions = self.decode()

        if disassemble:
            return [instr.disassemble() for instr in instructions]
        self.irsb.jumpkind = JumpKind.Invalid
        irsb_c = IRSBCustomizer(self.irsb)
        l.debug("Decoding complete.")
        for i, instr in enumerate(instructions[:self.max_inst]):
            l.debug("Lifting instruction " + instr.name)
            instr(irsb_c, instructions[:i], instructions[i+1:])
            if irsb_c.irsb.jumpkind != JumpKind.Invalid:
                break
            elif (i+1) == self.max_inst: # if we are on our last iteration
                instr.jump(None, irsb_c.irsb.addr + irsb_c.irsb.size)
                break
        else:
            if len(irsb_c.irsb.statements) == 0:
                raise LiftingException('Could not decode any instructions')
            irsb_c.irsb.jumpkind = JumpKind.NoDecode
            dst = irsb_c.irsb.addr + irsb_c.irsb.size
            dst_ty = vex_int_class(irsb_c.irsb.arch.bits).type
            irsb_c.irsb.next = irsb_c.mkconst(dst, dst_ty)
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
        print(disasstr)

    def error(self):
        return self.errors

    def disassemble(self):
        return self.lift(disassemble=True)


from ...expr import *
from .. import LiftingException
