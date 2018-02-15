
import logging
import bitstring

from .vex_helper import *
from ..lifter import Lifter

l = logging.getLogger(__name__)

def is_empty(bitstrm):
    try:
        bitstrm.peek(1)
        return False
    except bitstring.ReadError:
        return True


class ParseError(Exception):
    """This exception is used by the instruction's parse method to signal that the tried instruction does not
    match at the current position.
    """
    pass


class RequireContextError(Exception):
    """This exception indicates the the instruction requires a larger number of surrounding instruction context
    than provided to compute its sematics. For example, some architectures have instructions to "skip the next"
    instruction. If you such an instruction appears at the end of a block to lift, this exception can be raised.

    It is important that no modifications have been applied to the IRSB before this exception is raised, as
    these cannot be rolled back.

    :ivar int amount: At least this many future (if positive) or past (if negative) are requied to interpret the instruction. This is a lower bound, the actual number may be higher.
    """

    def __init__(self, amount=0):
        self.amount = amount

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
    REQUIRE_DATA_PY = True

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
            addr = self.irsb._addr
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
        except Exception, e:
            self.errors = e.message
            l.exception("Error decoding block at offset {:#x} (address {:#x}):".format(bytepos, addr))
            raise e

    def lift(self, disassemble=False, dump_irsb=False):
        self.thedata = self.data[:self.max_bytes]
        l.debug(repr(self.thedata))
        instructions = self.decode()

        if disassemble:
            return [instr.disassemble() for instr in instructions]

        l.debug("Decoding complete.")
        self.irsb.jumpkind = None
        for i, instr in enumerate(instructions[:self.max_inst]):
            # first, create a scratch IRSB so we can throw the changes away if lifting fails
            next_irsb_part = pyvex.IRSB.empty_block(self.irsb.arch, self.irsb.addr)
            irsb_c = IRSBCustomizer(next_irsb_part)

            # try to do the lifting
            # if the instruction requires more context, we stop
            # decoding here and just return the block we have so far
            l.debug("Lifting instruction " + instr.name)
            try:
                instr(irsb_c, instructions[:i], instructions[i+1:])
            except RequireContextError:
                break

            # lifting was successful so add the part to the full IRSB
            self.irsb.extend(next_irsb_part)
            if self.irsb.jumpkind is not None:
                break

        if len(self.irsb.statements) == 0:
            raise LiftingException('Could not lift any instructions')

        if self.irsb.jumpkind is None:
            self.irsb.next = Const(vex_int_class(self.irsb.arch.bits)(self.irsb.addr + self.irsb.size))
            self.irsb.jumpkind = JumpKind.Boring if len(instructions) >= self.max_inst else JumpKind.NoDecode

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


from ...expr import *
from .. import LiftingException
