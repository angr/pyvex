import sys

import collections
_counts = collections.Counter()

import os
pyvex_path = os.path.join(os.path.dirname(__file__), '..', 'pyvex_c', 'pyvex_static.so')
if not os.path.exists(pyvex_path) and "VIRTUAL_ENV" in os.environ:
    virtual_env = os.environ["VIRTUAL_ENV"]
    pyvex_path = os.path.join(virtual_env, 'lib', 'pyvex_static.so')
if not os.path.exists(pyvex_path):
    raise ImportError("unable to find pyvex_static.so")

#
# Heeeere's pyvex!
#
import cffi
ffi = cffi.FFI()
from . import vex_ffi
ffi.cdef(vex_ffi.ffi_str)
pvc = ffi.dlopen(pyvex_path)
pvc.vex_init()
dir(pvc) # lookup all the definitions (wtf)
enums_to_ints = { _:getattr(pvc,_) for _ in dir(pvc) if isinstance(getattr(pvc,_), int) }
ints_to_enums = { getattr(pvc,_):_ for _ in dir(pvc) if isinstance(getattr(pvc,_), int) }
enum_IROp_fromstr = { _:enums_to_ints[_] for _ in enums_to_ints if _.startswith('Iop_') }
type_sizes = {
    'Ity_INVALID': None,
    'Ity_I1': 1,
    'Ity_I8': 8,
    'Ity_I16': 16,
    'Ity_I32': 32,
    'Ity_I64': 64,
    'Ity_I128': 128,
    'Ity_F16':  16,
    'Ity_F32':  32,
    'Ity_F64':  64,
    'Ity_F128': 128,
    'Ity_D32':  32,
    'Ity_D64':  64,
    'Ity_D128': 128,
    'Ity_V128': 128,
    'Ity_V256': 256
}

def set_iropt_level(lvl):
    pvc.vex_control.iropt_level = lvl

def _get_op_type(op):
    irsb = pvc.emptyIRSB()
    t = pvc.newIRTemp(irsb.tyenv, pvc.Ity_I8)
    e = pvc.IRExpr_Unop(enums_to_ints[op], pvc.IRExpr_RdTmp(t))
    return ints_to_enums[pvc.typeOfIRExpr(irsb.tyenv, e)]
_op_types = { _:_get_op_type(_) for _ in enums_to_ints if _.startswith('Iop_') and _ != 'Iop_INVALID' and _ != 'Iop_LAST' }
def typeOfIROp(op): return _op_types[op]

class VEXObject(object):
    pass
    #def __init__(self):
    #   print "CREATING:",type(self)
    #   _counts[type(self)] += 1

    #def __del__(self):
    #   print "DELETING:",type(self)
    #   _counts[type(self)] -= 1

class PyVEXError(Exception): pass

# various objects
class IRSB(VEXObject):
    def __init__(self, bytes, mem_addr, arch, num_inst=None, num_bytes=None, bytes_offset=None, traceflags=0): #pylint:disable=redefined-builtin
        VEXObject.__init__(self)

        if bytes_offset is not None and bytes_offset > 0:
            if num_bytes:
                bytes = bytes[bytes_offset:num_bytes-bytes_offset]
            else:
                bytes = bytes[bytes_offset:]
        pvc.vta.traceflags = traceflags

        num_bytes = len(bytes) if num_bytes is None else num_bytes
        if num_bytes == 0:
            raise PyVEXError("No bytes provided")

        vex_arch = getattr(pvc, arch.vex_arch)
        vex_end = getattr(pvc, arch.vex_endness)

        if num_inst is not None:
            c_irsb = pvc.vex_block_inst(vex_arch, vex_end, bytes, mem_addr, num_inst)
        else:
            c_irsb = pvc.vex_block_bytes(vex_arch, vex_end, bytes, mem_addr, num_bytes, 0)

        if c_irsb == ffi.NULL:
            raise PyVEXError(ffi.string(pvc.last_error) if pvc.last_error != ffi.NULL else "unknown error")

        self.c_irsb = c_irsb
        self.arch = arch
        self.statements = [ IRStmt.IRStmt._translate(c_irsb.stmts[i], self) for i in range(c_irsb.stmts_used) ]
        self.next = IRExpr.IRExpr._translate(c_irsb.next, self)
        self.tyenv = IRTypeEnv(c_irsb.tyenv)
        self.offsIP = c_irsb.offsIP
        self.stmts_used = c_irsb.stmts_used
        self.jumpkind = ints_to_enums[c_irsb.jumpkind]

        del self.c_irsb

    def pp(self):
        print "IRSB {"
        print "   %s" % self.tyenv
        print ""
        for i,s in enumerate(self.statements):
            print "   %02d | %s" % (i,s)
        print "   NEXT: PUT(%s) = %s; %s" % (self.arch.translate_register_name(self.offsIP), self.next, self.jumpkind)
        print "}"

    @property
    def expressions(self):
        '''
        All expressions contained in the IRSB.
        '''
        expressions = [ ]
        for s in self.statements:
            expressions.extend(s.expressions)
        expressions.append(self.next)
        return expressions

    @property
    def instructions(self):
        return len([ s.addr for s in self.statements if isinstance(s, IRStmt.IMark) ])

    @property
    def size(self):
        return sum([ s.len for s in self.statements if isinstance(s, IRStmt.IMark) ])

    @property
    def operations(self):
        '''
        All operations done by the IRSB.
        '''
        ops = [ ]
        for e in self.expressions:
            if hasattr(e, 'op'):
                ops.append(e.op)
        return ops

    @property
    def all_constants(self):
        '''
        Returns all constants (including incrementing of the program counter).
        '''
        return sum((e.constants for e in self.expressions), [ ])

    @property
    def constants(self):
        '''
        The constants (excluding updates of the program counter) in the IRSB.
        '''
        return sum((s.constants for s in self.statements if not (isinstance(s, IRStmt.Put) and s.offset == self.offsIP)), [ ])

class IRTypeEnv(VEXObject):
    def __init__(self, tyenv):
        VEXObject.__init__(self)
        self.types = [ ints_to_enums[tyenv.types[t]] for t in xrange(tyenv.types_used) ]
        self.types_used = tyenv.types_used

    def __str__(self):
        return ' '.join(("t%d:%s" % (i,t)) for i,t in enumerate(self.types))

class IRCallee(VEXObject):
    def __init__(self, callee):
        VEXObject.__init__(self)
        self.regparms = callee.regparms
        self.name = ffi.string(callee.name)
        self.mcx_mask = callee.mcx_mask
        self.addr = int(ffi.cast("unsigned long long", callee.mcx_mask))

    def __str__(self):
        return self.name

class IRRegArray(VEXObject):
    def __init__(self, arr):
        VEXObject.__init__(self)
        self.base = arr.base
        self.elemTy = arr.elemTy
        self.nElems = arr.nElems

    def __str__(self):
        return "%s:%sx%d" % (self.base, self.elemTy[4:], self.nElems)

from . import IRConst
from . import IRExpr
from . import IRStmt
