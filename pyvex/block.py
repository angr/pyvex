from __future__ import print_function

from . import VEXObject
from . import expr, stmt
from .lift import lift
from .enums import get_enum_from_int, get_int_from_enum
from .const import get_type_size
from .errors import PyVEXError

import logging
l = logging.getLogger("pyvex.block")

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
    :ivar int size:         The size of this block in bytes
    :ivar int addr:         The address of this basic block, i.e. the address in the first IMark
    """

    __slots__ = ['_addr', 'arch', 'statements', 'next', 'tyenv', 'jumpkind', '_direct_next', '_size']

    def __init__(self, data, mem_addr, arch, max_inst=None, max_bytes=None, bytes_offset=0, traceflags=0, opt_level=1, num_inst=None, num_bytes=None):
        """
        :param data:            The bytes to lift. Can be either a string of bytes or a cffi buffer object.
                                You may also pass None to initialize an empty IRSB.
        :type data:             str or bytes or cffi.FFI.CData or None
        :param int mem_addr:    The address to lift the data at.
        :param arch:            The architecture to lift the data as.
        :type arch:             :class:`archinfo.Arch`
        :param max_inst:        The maximum number of instructions to lift. Max 99. (See note below)
        :param max_bytes:       The maximum number of bytes to use. Max 5000.
        :param bytes_offset:    The offset into `data` to start lifting at.
        :param traceflags:      The libVEX traceflags, controlling VEX debug prints.
        :param opt_level:       The level of optimization to apply to the IR, 0-2.

        .. note:: Explicitly specifying the number of instructions to lift (`max_inst`) may not always work
                  exactly as expected. For example, on MIPS, it is meaningless to lift a branch or jump
                  instruction without its delay slot. VEX attempts to Do The Right Thing by possibly decoding
                  fewer instructions than requested. Specifically, this means that lifting a branch or jump
                  on MIPS as a single instruction (`max_inst=1`) will result in an empty IRSB, and subsequent
                  attempts to run this block will raise `SimIRSBError('Empty IRSB passed to SimIRSB.')`.
        """
        if max_inst is None: max_inst = num_inst
        if max_bytes is None: max_bytes = num_bytes
        VEXObject.__init__(self)
        self._addr = mem_addr
        self.arch = arch

        self.statements = []
        self.next = None
        self.tyenv = IRTypeEnv(arch)
        self.jumpkind = None
        self._direct_next = None
        self._size = None

        if data is not None:
            lift(self, data, max_bytes, max_inst, bytes_offset, opt_level, traceflags)

    def pp(self):
        """
        Pretty-print the IRSB to stdout.
        """
        print(self._pp_str())

    def typecheck(self):
        try:
            # existence assertions
            assert self.next is not None, "Missing next expression"
            assert self.jumpkind is not None, "Missing jumpkind"

            # type assertions
            assert isinstance(self.next, expr.IRExpr), "Next expression is not an expression"
            assert type(self.jumpkind is str), "Jumpkind is not a string"
            assert self.jumpkind.startswith('Ijk_'), "Jumpkind is not a jumpkind enum"
            assert self.tyenv.typecheck(), "Type environment contains invalid types"

            # statement assertions
            last_imark = None
            for i, st in enumerate(self.statements):
                assert isinstance(st, stmt.IRStmt), "Statement %d is not an IRStmt" % i
                try:
                    assert st.typecheck(self.tyenv), "Statement %d failed to typecheck" % i
                except: # pylint: disable=bare-except
                    assert False, "Statement %d errored in typechecking" % i

                if type(st) is stmt.NoOp:
                    continue
                elif type(st) is stmt.IMark:
                    if last_imark is not None:
                        # pylint: disable=unsubscriptable-object
                        assert last_imark[0] + last_imark[1] == st.addr, "IMarks sizes overlap or have gaps"
                    last_imark = (st.addr, st.len)
                else:
                    assert last_imark is not None, "Operation statement appears before IMark"

            assert last_imark is not None, "No IMarks present in block"
        except AssertionError as e:
            l.debug(e.args[0])
            return False
        return True

    #
    # alternate constructors
    #

    @staticmethod
    def from_c(c_irsb, mem_addr, arch):
        irsb = IRSB(None, mem_addr, arch)
        irsb._from_c(c_irsb)
        return irsb

    @staticmethod
    def from_py(tyenv, stmts, next_expr, jumpkind, mem_addr, arch):
        irsb = IRSB(None, mem_addr, arch)

        irsb.tyenv = tyenv
        irsb.statements = stmts
        irsb.next = next_expr
        irsb.jumpkind = jumpkind
        irsb._direct_next = irsb._is_defaultexit_direct_jump()

        return irsb

    #
    # simple properties useful for analysis
    #

    @property
    def stmts_used(self):
        return len(self.statements)

    @property
    def offsIP(self):
        return self.arch.ip_offset

    @property
    def direct_next(self):
        if self._direct_next is None:
            self._direct_next = self._is_defaultexit_direct_jump()
        return self._direct_next

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
        return len([s for s in self.statements if isinstance(s, stmt.IMark)])

    @property
    def size(self):
        """
        The size of this block, in bytes
        """
        if self._size is None:
            self._size = sum([s.len for s in self.statements if isinstance(s, stmt.IMark)])
        return self._size

    @property
    def addr(self):
        for s in self.statements:
            if isinstance(s, stmt.IMark):
                return s.addr
        return None

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

    #
    # private methods
    #

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
            stmt_str = ''
            if isinstance(s, stmt.Put):
                stmt_str = s.__str__(reg_name=self.arch.translate_register_name(s.offset, s.data.result_size(self.tyenv)/8))
            elif isinstance(s, stmt.WrTmp) and isinstance(s.data, expr.Get):
                stmt_str = s.__str__(reg_name=self.arch.translate_register_name(s.data.offset, s.data.result_size(self.tyenv)/8))
            elif isinstance(s, stmt.Exit):
                stmt_str = s.__str__(reg_name=self.arch.translate_register_name(s.offsIP, self.arch.bits / 8))
            else:
                stmt_str = s.__str__()
            sa.append("   %02d | %s" % (i, stmt_str))
        sa.append(
            "   NEXT: PUT(%s) = %s; %s" % (self.arch.translate_register_name(self.offsIP), self.next, self.jumpkind))
        sa.append("}")
        return '\n'.join(sa)

    def _get_defaultexit_target(self):
        """
        The default exit target, if it is constant, or None.
        """
        if isinstance(self.next, expr.Const):
            return self.next.con.value

        if not isinstance(self.next, expr.RdTmp):
            raise PyVEXError("unexpected self.next type: %s" % self.next.__class__.__name__)

        tmp_next = self.next.tmp
        reg_next = None
        reg_next_size = None
        for stat in reversed(self.statements):
            if isinstance(stat, stmt.WrTmp) and stat.tmp == tmp_next:
                data = stat.data
            elif isinstance(stat, stmt.Put) and stat.offset == reg_next:
                data = stat.data
                if data.result_size(self.tyenv) != reg_next_size:
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
                reg_next_size = data.result_size(self.tyenv)
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

    #
    # internal "constructors" to fill this block out with data from various sources
    #

    def _from_c(self, c_irsb):
        self.statements = [stmt.IRStmt._from_c(c_irsb.stmts[i]) for i in range(c_irsb.stmts_used)]
        self.tyenv = IRTypeEnv._from_c(self.arch, c_irsb.tyenv)
        self.next = expr.IRExpr._from_c(c_irsb.next)
        self.jumpkind = get_enum_from_int(c_irsb.jumpkind)

class IRTypeEnv(VEXObject):
    """
    An IR type environment.

    :ivar types:        A list of the types of all the temporaries in this block as VEX enum strings.
                        `types[3]` is the type of t3.
    :vartype types:     list of str
    """

    __slots__ = ['types', 'wordty']

    def __init__(self, arch, types=None):
        VEXObject.__init__(self)
        self.types = [] if types is None else types
        self.wordty = 'Ity_I%d' % arch.bits

    def __str__(self):
        return ' '.join(("t%d:%s" % (i, t)) for i, t in enumerate(self.types))

    def lookup(self, tmp):
        """
        Return the type of temporary variable `tmp` as an enum string
        """
        if tmp < 0 or tmp > self.types_used:
            l.debug("Invalid temporary number %d", tmp)
            raise IndexError(tmp)
        return self.types[tmp]

    def sizeof(self, tmp):
        return get_type_size(self.lookup(tmp))

    def add(self, ty):
        """
        Add a new tmp of type `ty` to the environment. Returns the number of the new tmp.
        """
        self.types.append(ty)
        return self.types_used - 1

    @property
    def types_used(self):
        return len(self.types)

    @staticmethod
    def _from_c(arch, c_tyenv):
        return IRTypeEnv(arch, [get_enum_from_int(c_tyenv.types[t]) for t in range(c_tyenv.types_used)])

    @staticmethod
    def _to_c(tyenv):
        c_tyenv = pvc.emptyIRTypeEnv()
        for ty in tyenv.types:
            pvc.newIRTemp(c_tyenv, get_int_from_enum(ty))
        return c_tyenv

    def typecheck(self):
        for ty in self.types:
            try:
               get_type_size(ty)
            except ValueError:
                return False

from . import pvc