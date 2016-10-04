import threading
from . import VEXObject

_libvex_lock = threading.Lock()

class IRSB(VEXObject):
    """
    The IRSB is the primary interface to pyvex. Constructing one of these will make a call into LibVEX to perform a
    translation.

    IRSB stands for *Intermediate Representation Super-Block*. An IRSB in VEX is a single-entry, multiple-exit code
    block.

    :ivar arch:             The architecture this block is lifted under
    :vartype arch:          :class:`archinfo.Arch`
    :ivar statements:       The statements in this block
    :vartype statements:    list of :class:`IRStmt`
    :ivar next:             The expression for the default exit target of this block
    :vartype next:          :class:`IRExpr`
    :ivar int offsIP:       The offset of the instruction pointer in the VEX guest state
    :ivar int stmts_used:   The number of statements in this IRSB
    :ivar str jumpkind:     The type of this block's default jump (call, boring, syscall, etc) as a VEX enum string
    :ivar bool direct_next: Whether this block ends with a direct (not indirect) jump or branch
    """

    __slots__ = ['c_irsb', 'arch', 'statements', 'next', 'tyenv', 'offsIP', 'stmts_used', 'jumpkind', '_addr',
                 'direct_next'
                 ]

    def __init__(self, data, mem_addr, arch, num_inst=None, num_bytes=None, bytes_offset=0,
                 traceflags=0):  # pylint:disable=redefined-builtin
        """
        :param data:            The bytes to lift. Can be either a string of bytes or a cffi buffer object.
        :type data:             str or bytes or cffi.FFI.CData
        :param int mem_addr:    The address to lift the data at.
        :param arch:            The architecture to lift the data as.
        :type arch:             :class:`archinfo.Arch`
        :param num_inst:        The maximum number of instructions to lift. Max 99. (See note below)
        :param num_bytes:       The maximum number of bytes to use. Max 400.
        :param bytes_offset:    The offset into `data` to start lifting at.
        :param traceflags:      The libVEX traceflags, controlling VEX debug prints.

        .. note:: Explicitly specifying the number of instructions to lift (`num_inst`) may not always work
                  exactly as expected. For example, on MIPS, it is meaningless to lift a branch or jump
                  instruction without its delay slot. VEX attempts to Do The Right Thing by possibly decoding
                  fewer instructions than requested. Specifically, this means that lifting a branch or jump
                  on MIPS as a single instruction (`num_inst=1`) will result in an empty IRSB, and subsequent
                  attempts to run this block will raise `SimIRSBError('Empty IRSB passed to SimIRSB.')`.
        """
        try:
            _libvex_lock.acquire()

            VEXObject.__init__(self)

            if isinstance(data, (str, bytes)):
                num_bytes = len(data) if num_bytes is None else num_bytes
                c_bytes = ffi.new('char [%d]' % (len(data) + 8), data + '\0' * 8)
            else:
                if not num_bytes:
                    raise PyVEXError("C-backed bytes must have the length specified by num_bytes")
                c_bytes = data

            if num_bytes == 0:
                raise PyVEXError("No bytes provided")
            pvc.vta.traceflags = traceflags

            vex_arch = getattr(pvc, arch.vex_arch)

            arch.vex_archinfo['hwcache_info']['caches'] = ffi.NULL

            if num_inst is not None:
                c_irsb = pvc.vex_block_inst(vex_arch, arch.vex_archinfo, c_bytes + bytes_offset, mem_addr, num_inst)
            else:
                c_irsb = pvc.vex_block_bytes(vex_arch, arch.vex_archinfo, c_bytes + bytes_offset, mem_addr, num_bytes,
                                             1)

            if c_irsb == ffi.NULL:
                raise PyVEXError(ffi.string(pvc.last_error) if pvc.last_error != ffi.NULL else "unknown error")

            # We must use a pickle value, CData objects are not pickeable so not ffi.NULL
            arch.vex_archinfo['hwcache_info']['caches'] = None

            self.c_irsb = c_irsb
            self.arch = arch
            self.statements = [stmt.IRStmt._translate(c_irsb.stmts[i], self) for i in xrange(c_irsb.stmts_used)]
            self.next = expr.IRExpr._translate(c_irsb.next, self)
            self.tyenv = IRTypeEnv(c_irsb.tyenv)
            self.offsIP = c_irsb.offsIP
            self.stmts_used = c_irsb.stmts_used
            self.jumpkind = ints_to_enums[c_irsb.jumpkind]

            self._addr = mem_addr
            self.direct_next = self._is_defaultexit_direct_jump()

            del self.c_irsb
        finally:
            _libvex_lock.release()

    def pp(self):
        """
        Pretty-print the IRSB to stdout.
        """
        print self._pp_str()

    def _pp_str(self):
        """
        Return the pretty-printed IRSB.

        :rtype: str
        """
        sa = []
        sa.append("IRSB {")
        sa.append("   %s" % self.tyenv)
        sa.append("")
        for i, s in enumerate(self.statements):
            sa.append("   %02d | %s" % (i, s))
        sa.append(
            "   NEXT: PUT(%s) = %s; %s" % (self.arch.translate_register_name(self.offsIP), self.next, self.jumpkind))
        sa.append("}")
        return '\n'.join(sa)

    @property
    def expressions(self):
        """
        A list of all expressions contained in the IRSB.
        """
        expressions = []
        for s in self.statements:
            expressions.extend(s.expressions)
        expressions.append(self.next)
        return expressions

    @property
    def instructions(self):
        """
        The number of instructions in this block
        """
        return len([s.addr for s in self.statements if isinstance(s, stmt.IMark)])

    @property
    def size(self):
        """
        The size of this block, in bytes
        """
        return sum([s.len for s in self.statements if isinstance(s, stmt.IMark)])

    @property
    def operations(self):
        """
        A list of all operations done by the IRSB, as libVEX enum names
        """
        ops = []
        for e in self.expressions:
            if hasattr(e, 'op'):
                ops.append(e.op)
        return ops

    @property
    def all_constants(self):
        """
        Returns all constants in the block (including incrementing of the program counter) as :class:`pyvex.const.IRConst`.
        """
        return sum((e.constants for e in self.expressions), [])

    @property
    def constants(self):
        """
        The constants (excluding updates of the program counter) in the IRSB as :class:`pyvex.const.IRConst`.
        """
        return sum(
            (s.constants for s in self.statements if not (isinstance(s, stmt.Put) and s.offset == self.offsIP)), [])

    @property
    def constant_jump_targets(self):
        """
        A set of the static jump targets of the basic block.
        """
        exits = set()
        for s in self.statements:
            if isinstance(s, stmt.Exit):
                exits.add(s.dst.value)

        default_target = self._get_defaultexit_target()
        if default_target is not None:
            exits.add(default_target)

        return exits

    @property
    def constant_jump_targets_and_jumpkinds(self):
        """
        A dict of the static jump targets of the basic block to their jumpkind.
        """
        exits = dict()
        for s in self.statements:
            if isinstance(s, stmt.Exit):
                exits[s.dst.value] = s.jumpkind

        default_target = self._get_defaultexit_target()
        if default_target is not None:
            exits[default_target] = self.jumpkind

        return exits


    def _get_defaultexit_target(self):
        """
        The default exit target, if it is constant, or None.
        """
        if isinstance(self.next, expr.Const):
            return self.next.con.value

        if not isinstance(self.next, expr.RdTmp):
            raise PyVEXError("unexpected self.next type: %s", self.next.__class__.__name__)

        tmp_next = self.next.tmp
        reg_next = None
        reg_next_size = None
        for stat in reversed(self.statements):
            if isinstance(stat, stmt.WrTmp) and stat.tmp == tmp_next:
                data = stat.data
            elif isinstance(stat, stmt.Put) and stat.offset == reg_next:
                data = stat.data
                if data.result_size != reg_next_size:
                    return None
            elif isinstance(stat, stmt.LoadG) and stat.dst == tmp_next:
                return None
            else:
                continue

            if isinstance(data, expr.Const):
                return data.con.value
            elif isinstance(data, expr.RdTmp):
                tmp_next = data.tmp
                reg_next = None
            elif isinstance(data, expr.Get):
                tmp_next = None
                reg_next = data.offset
                reg_next_size = data.result_size
            else:
                return None

        if tmp_next is not None:
            raise PyVEXError('Malformed IRSB at address #%x. Please report to Fish.' % self._addr)
        return None

    def _is_defaultexit_direct_jump(self):
        """
        Checks if the default of this IRSB a direct jump or not.
        """
        if not (self.jumpkind == 'Ijk_Boring' or self.jumpkind == 'Ijk_Call'):
            return False

        target = self._get_defaultexit_target()
        return target is not None


class IRTypeEnv(VEXObject):
    """
    An IR type environment.

    :ivar types:        A list of the types of all the temporaries in this block as VEX enum strings.
                        `types[3]` is the type of t3.
    :vartype types:     list of str
    """

    __slots__ = [ 'types', 'types_used' ]

    def __init__(self, tyenv):
        VEXObject.__init__(self)
        self.types = [ints_to_enums[tyenv.types[t]] for t in xrange(tyenv.types_used)]
        self.types_used = tyenv.types_used

    def __str__(self):
        return ' '.join(("t%d:%s" % (i, t)) for i, t in enumerate(self.types))

from . import expr, stmt, ffi, pvc
from .enums import ints_to_enums
from .errors import PyVEXError
