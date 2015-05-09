import sys

import collections
_counts = collections.Counter()

#
# Heeeere's pyvex!
#
import cffi
ffi = cffi.FFI()
from . import vex_ffi
ffi.cdef(vex_ffi.ffi_str)
pvc = ffi.dlopen('pyvex_c/pyvex_static.so')
pvc.vex_init()
dir(pvc) # lookup all the definitions (wtf)
enums_to_ints = { _:getattr(pvc,_) for _ in dir(pvc) if isinstance(getattr(pvc,_), int) }
ints_to_enums = { getattr(pvc,_):_ for _ in dir(pvc) if isinstance(getattr(pvc,_), int) }
enum_IROp_fromstr = { _:enums_to_ints[_] for _ in enums_to_ints if _.startswith('Iop_') }

def set_iropt_level(level):
    pvc.vta.iropt_level = level

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
    #   #print "CREATING:",type(self)
    #   _counts[type(self)] += 1

    #def __del__(self):
    #   #print "DELETING:",type(self)
    #   _counts[type(self)] -= 1

class PyVEXError(Exception): pass

# various objects
class IRSB(VEXObject):
    def __init__(self, bytes, mem_addr, arch, num_inst=None, bytes_offset=None, traceflags=0): #pylint:disable=redefined-builtin
        VEXObject.__init__(self)

        if bytes_offset is not None:
            bytes = bytes[bytes_offset:]
        pvc.vta.traceflags = traceflags

        if len(bytes) == 0:
            raise PyVEXError("No bytes provided")

        vex_arch = getattr(pvc, arch.vex_arch)
        vex_end = getattr(pvc, arch.vex_endness)

        if num_inst is not None:
            c_irsb = pvc.vex_block_inst(vex_arch, vex_end, bytes, mem_addr, num_inst)
        else:
            c_irsb = pvc.vex_block_bytes(vex_arch, vex_end, bytes, mem_addr, len(bytes), 0)

        self.arch = arch
        self.statements = [ getattr(IRStmt, ints_to_enums[c_irsb.stmts[i].tag][4:])(c_irsb.stmts[i]) for i in range(c_irsb.stmts_used) ]
        self.next = IRExpr.IRExpr._translate(c_irsb.next)

        for stmt in self.statements:
            stmt.arch = self.arch
            del stmt.c_stmt
        for expr in self.expressions:
            expr.arch = self.arch
            expr.result_type = pvc.typeOfIRExpr(c_irsb.tyenv, expr.c_expr)
            del expr.c_expr

        self.tyenv = IRTypeEnv(c_irsb.tyenv)
        self.offsIP = c_irsb.offsIP
        self.stmts_used = c_irsb.stmts_used
        self.jumpkind = ints_to_enums[c_irsb.jumpkind]


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
        self.base = arr.base
        self.elemTy = arr.elemTy
        self.nElems = arr.nElems

    def __str__(self):
        return "%s:%sx%d" % (self.base, self.elemTy[4:], self.nElems)

from . import IRConst
from . import IRExpr
from . import IRStmt
