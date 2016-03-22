"""
Python bindings for Valgrind's VEX IR.
"""
import collections

_counts = collections.Counter()

import os
import sys

# the lock
import threading

_libvex_lock = threading.Lock()

if sys.platform == 'darwin':
    library_file = "pyvex_static.dylib"
else:
    library_file = "pyvex_static.so"

_pyvex_paths = [os.path.join(os.path.dirname(__file__), '..', 'pyvex_c', library_file),
                os.path.join(sys.prefix, 'lib', library_file)]

_sigh = os.path.abspath(__file__)
_prev_sigh = '$'
while _sigh != _prev_sigh:
    _prev_sigh = _sigh
    _sigh = os.path.dirname(_sigh)
    _pyvex_paths.append(os.path.join(_sigh, 'lib', library_file))

for pyvex_path in _pyvex_paths:
    if os.path.exists(pyvex_path):
        break
else:
    raise ImportError("unable to find pyvex_static.so")

#
# Heeeere's pyvex!
#
import cffi

ffi = cffi.FFI()
from . import vex_ffi

ffi.cdef(vex_ffi.ffi_str)
pvc = ffi.dlopen(pyvex_path)  # pylint:disable=undefined-loop-variable
pvc.vex_init()
dir(pvc)  # lookup all the definitions (wtf)
enums_to_ints = {_: getattr(pvc, _) for _ in dir(pvc) if hasattr(pvc, _) and isinstance(getattr(pvc, _), int)}
ints_to_enums = {getattr(pvc, _): _ for _ in dir(pvc) if hasattr(pvc, _) and isinstance(getattr(pvc, _), int)}
enum_IROp_fromstr = {_: enums_to_ints[_] for _ in enums_to_ints if _.startswith('Iop_')}
type_sizes = {
    'Ity_INVALID': None,
    'Ity_I1': 1,
    'Ity_I8': 8,
    'Ity_I16': 16,
    'Ity_I32': 32,
    'Ity_I64': 64,
    'Ity_I128': 128,
    'Ity_F16': 16,
    'Ity_F32': 32,
    'Ity_F64': 64,
    'Ity_F128': 128,
    'Ity_D32': 32,
    'Ity_D64': 64,
    'Ity_D128': 128,
    'Ity_V128': 128,
    'Ity_V256': 256
}


def set_iropt_level(lvl):
    """
    Set the VEX optimization level to `lvl`. Valid values are 0, 1 and 2.

    0 performs no optimization, 1 performs basic optimizations, and 2 performs loop unrolling, among other things.
    """
    pvc.vex_control.iropt_level = lvl


def _get_op_type(op):
    irsb = pvc.emptyIRSB()
    t = pvc.newIRTemp(irsb.tyenv, pvc.Ity_I8)
    e = pvc.IRExpr_Unop(enums_to_ints[op], pvc.IRExpr_RdTmp(t))
    return ints_to_enums[pvc.typeOfIRExpr(irsb.tyenv, e)]


_op_types = {_: _get_op_type(_) for _ in enums_to_ints if
             _.startswith('Iop_') and _ != 'Iop_INVALID' and _ != 'Iop_LAST'}


def typeOfIROp(op): return _op_types[op]


def vex_endness_from_string(endness_str):
    return getattr(pvc, endness_str)


def default_vex_archinfo():
    return {
        'hwcaps': 0,
        'endness': vex_endness_from_string('VexEndnessLE'),
        'ppc_icache_line_szB': 0,
        'ppc_dcbz_szB': 0,
        'ppc_dcbzl_szB': 0,
        'arm64_dMinLine_lg2_szB': 0,
        'arm64_iMinLine_lg2_szB': 0,
        'hwcache_info': {
            'num_levels': 0,
            'num_caches': 0,
            'caches': None,
            'icaches_maintain_coherence': True,
        },
        'x86_cr0': 0xffffffff
    }


class VEXObject(object):
    """
    The base class for Vex types.
    """
    pass
    # def __init__(self):
    #   print "CREATING:",type(self)
    #   _counts[type(self)] += 1

    # def __del__(self):
    #   print "DELETING:",type(self)
    #   _counts[type(self)] -= 1


class PyVEXError(Exception): pass


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
    def __init__(self, data, mem_addr, arch, num_inst=None, num_bytes=None, bytes_offset=0,
                 traceflags=0):  # pylint:disable=redefined-builtin
        """
        :param data:            The bytes to lift. Can be either a string of bytes or a cffi buffer object.
        :type data:             str or bytes or cffi.FFI.CData
        :param int mem_addr:    The address to lift the data at.
        :param arch:            The architecture to lift the data as.
        :type arch:             :class:`archinfo.Arch`

        The following are optional:
        :param num_inst:        The maximum number of instructions to lift. Max 99.
        :param num_bytes:       The maximum number of bytes to use. Max 400.
        :param bytes_offset:    The offset into `data` to start lifting at.
        :param traceflags:      The libVEX traceflags, controlling VEX debug prints.
        """
        try:
            _libvex_lock.acquire()

            VEXObject.__init__(self)

            if isinstance(data, (str, bytes)):
                num_bytes = len(data) if num_bytes is None else num_bytes
                c_bytes = ffi.new('char [%d]' % (num_bytes + 8), data + '\0' * 8)
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
            self.statements = [IRStmt.IRStmt._translate(c_irsb.stmts[i], self) for i in range(c_irsb.stmts_used)]
            self.next = IRExpr.IRExpr._translate(c_irsb.next, self)
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
        All expressions contained in the IRSB.
        :rtype: list of :class:`IRExpr`
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
        :rtype: int
        """
        return len([s.addr for s in self.statements if isinstance(s, IRStmt.IMark)])

    @property
    def size(self):
        """
        The size of this block, in bytes
        :rtype: int
        """
        return sum([s.len for s in self.statements if isinstance(s, IRStmt.IMark)])

    @property
    def operations(self):
        """
        All operations done by the IRSB, as libVEX enum names
        :rtype: list of str
        """
        ops = []
        for e in self.expressions:
            if hasattr(e, 'op'):
                ops.append(e.op)
        return ops

    @property
    def all_constants(self):
        """
        Returns all constants (including incrementing of the program counter).
        :rtype: list of :class:`IRConst`
        """
        return sum((e.constants for e in self.expressions), [])

    @property
    def constants(self):
        """
        The constants (excluding updates of the program counter) in the IRSB.
        :rtype: list of :class:`IRConst`
        """
        return sum(
            (s.constants for s in self.statements if not (isinstance(s, IRStmt.Put) and s.offset == self.offsIP)), [])

    @property
    def constant_jump_targets(self):
        """
        The static jump targets of the basic block.
        :rtype: set of int
        """
        exits = set()
        for s in self.statements:
            if isinstance(s, IRStmt.Exit):
                exits.add(s.dst.value)

        default_target = self._get_defaultexit_target()
        if default_target is not None:
            exits.add(default_target)

        return exits

    def _get_defaultexit_target(self):
        """
        Retrieves the default exit target, if it is constant.
        :rtype: int or None
        """
        if isinstance(self.next, IRExpr.Const):
            return self.next.con.value

        if not isinstance(self.next, IRExpr.RdTmp):
            raise PyVEXError("unexpected self.next type: %s", self.next.__class__.__name__)

        tmp_next = self.next.tmp
        for stmt in reversed(self.statements):
            if isinstance(stmt, IRStmt.WrTmp) and stmt.tmp == tmp_next:
                data = stmt.data

                if isinstance(data, IRExpr.Const):
                    return data.con.value
                elif isinstance(data, IRExpr.RdTmp):
                    tmp_next = data.tmp
                else:
                    return None

            elif isinstance(stmt, IRStmt.LoadG) and stmt.dst == tmp_next:
                return None

        raise PyVEXError('Malformed IRSB at address 0x%x. Please report to Fish.' % self._addr)

    def _is_defaultexit_direct_jump(self):
        """
        Checks if the default of this IRSB a direct jump or not.
        :rtype: bool
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
    def __init__(self, tyenv):
        VEXObject.__init__(self)
        self.types = [ints_to_enums[tyenv.types[t]] for t in xrange(tyenv.types_used)]
        self.types_used = tyenv.types_used

    def __str__(self):
        return ' '.join(("t%d:%s" % (i, t)) for i, t in enumerate(self.types))


class IRCallee(VEXObject):
    """
    Describes a helper function to call.
    """
    def __init__(self, callee):
        VEXObject.__init__(self)
        self.regparms = callee.regparms
        self.name = ffi.string(callee.name)
        self.mcx_mask = callee.mcx_mask
        self.addr = int(ffi.cast("unsigned long long", callee.mcx_mask))

    def __str__(self):
        return self.name


class IRRegArray(VEXObject):
    """
    A section of the guest state that we want te be able to index at run time, so as to be able to describe indexed or
    rotating register files on the guest.

    :ivar int base:     The offset into the state that this array starts
    :ivar str elemTy:   The types of the elements in this array, as VEX enum strings
    :ivar int nElems:   The number of elements in this array
    """
    def __init__(self, arr):
        VEXObject.__init__(self)
        self.base = arr.base
        self.elemTy = ints_to_enums[arr.elemTy]
        self.nElems = arr.nElems

    def __str__(self):
        return "%s:%sx%d" % (self.base, self.elemTy[4:], self.nElems)


from . import IRConst
from . import IRExpr
from . import IRStmt
