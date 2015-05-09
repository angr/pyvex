from .. import VEXObject

# IRStmt heirarchy
class IRStmt(VEXObject):
    def __init__(self, c_stmt):
        self.arch = None
        self.c_stmt = c_stmt

    @property
    def expressions(self):
        expressions = [ ]
        for _,v in self.__dict__.iteritems():
            if isinstance(v, IRExpr):
                expressions.append(v)
                expressions.extend(v.child_expressions)
        return expressions

    @property
    def constants(self):
        return sum((e.constants for e in self.expressions), [ ])

class NoOp(IRStmt):
    def __init__(self, c_stmt): #pylint:disable=unused-argument
        IRStmt.__init__(self, c_stmt)

    def __str__(self):
        return "IR-NoOp"

class IMark(IRStmt):
    def __init__(self, c_stmt):
        IRStmt.__init__(self, c_stmt)
        self.addr = c_stmt.Ist.IMark.addr
        self.len = c_stmt.Ist.IMark.len
        self.delta = c_stmt.Ist.IMark.delta

    def __str__(self):
        return "------ IMark(0x%x, %d, %d) ------" % (self.addr, self.len, self.delta)

class AbiHint(IRStmt):
    def __init__(self, c_stmt):
        IRStmt.__init__(self, c_stmt)
        self.base = IRExpr._translate(c_stmt.Ist.AbiHint.base)
        self.len = c_stmt.Ist.AbiHint.len
        self.nia = IRExpr._translate(c_stmt.Ist.AbiHint.nia)

    def __str__(self):
        return "====== AbiHint(0x%s, %d, %s) ======" % (self.base, self.len, self.nia)

class Put(IRStmt):
    def __init__(self, c_stmt):
        IRStmt.__init__(self, c_stmt)
        self.data = IRExpr._translate(c_stmt.Ist.Put.data)
        self.offset = c_stmt.Ist.Put.offset

    def __str__(self):
        return "PUT(%s) = %s" % (self.arch.translate_register_name(self.offset), self.data)

class PutI(IRStmt):
    def __init__(self, c_stmt):
        IRStmt.__init__(self, c_stmt)
        self.descr = IRRegArray(c_stmt.Ist.PutI.details.descr)

        self.ix = IRExpr._translate(c_stmt.Ist.PutI.details.ix)
        self.data = IRExpr._translate(c_stmt.Ist.PutI.details.data)
        self.bias = c_stmt.Ist.PutI.details.bias

    def __str__(self):
        return "PUTI(%s)[%s,%d] = %s" % (self.descr, self.ix, self.bias, self.data)

class WrTmp(IRStmt):
    def __init__(self, c_stmt):
        IRStmt.__init__(self, c_stmt)

        self.data = IRExpr._translate(c_stmt.Ist.WrTmp.data)
        self.tmp = c_stmt.Ist.WrTmp.tmp

    def __str__(self):
        return "t%d = %s" % (self.tmp, self.data)

class Store(IRStmt):
    def __init__(self, c_stmt):
        IRStmt.__init__(self, c_stmt)

        self.addr = IRExpr._translate(c_stmt.Ist.Store.addr)
        self.data = IRExpr._translate(c_stmt.Ist.Store.data)
        self.end = ints_to_enums[c_stmt.Ist.Store.end]

    @property
    def endness(self):
        return self.end

    def __str__(self):
        return "ST%s(%s) = %s" % (self.endness[-2:].lower(), self.addr, self.data)

class CAS(IRStmt):
    def __init__(self, c_stmt):
        IRStmt.__init__(self, c_stmt)

        self.addr = IRExpr._translate(c_stmt.Ist.CAS.details.addr)
        self.dataLo = IRExpr._translate(c_stmt.Ist.CAS.details.dataLo)
        self.dataHi = IRExpr._translate(c_stmt.Ist.CAS.details.dataHi)
        self.expdLo = IRExpr._translate(c_stmt.Ist.CAS.details.expdLo)
        self.expdHi = IRExpr._translate(c_stmt.Ist.CAS.details.expdHi)
        self.oldLo = c_stmt.Ist.CAS.details.oldLo
        self.oldHi = c_stmt.Ist.CAS.details.oldHi
        self.end = ints_to_enums[c_stmt.Ist.CAS.details.end]

    @property
    def endness(self):
        return self.end

    def __str__(self):
        return "t(%s,%s) = CAS%s(%s :: (%s,%s)->(%s,%s))" % (self.oldLo, self.oldHi, self.end[-2:].lower(), self.addr, self.expdLo, self.expdHi, self.dataLo, self.dataHi)

class LLSC(IRStmt):
    def __init__(self, c_stmt):
        IRStmt.__init__(self, c_stmt)

        self.addr = IRExpr._translate(c_stmt.Ist.LLSC.addr)
        self.storedata = IRExpr._translate(c_stmt.Ist.LLSC.storedata)
        self.result = c_stmt.Ist.LLSC.result
        self.end = ints_to_enums[c_stmt.Ist.LLSC.end]

    @property
    def endness(self):
        return self.end

    def __str__(self):
        if self.storedata is None:
            return "result = LD%s-Linked(%s)" % (self.end[-2:].lower(), self.addr)
        else:
            return "result = ( ST%s-Cond(%s) = %s )" % (self.end[-2:].lower(), self.addr, self.storedata)

class MBE(IRStmt):
    def __init__(self, c_stmt):
        IRStmt.__init__(self, c_stmt)
        self.event = ints_to_enums[c_stmt.Ist.MBE.event]

    def __str__(self):
        return "MBusEvent-" + self.event

class Dirty(IRStmt):
    def __init__(self, c_stmt):
        IRStmt.__init__(self, c_stmt)
        self.cee = IRCallee(c_stmt.Ist.Dirty.details.cee)
        self.guard = IRExpr._translate(c_stmt.Dirty.details.guard)
        self.tmp = c_stmt.Ist.Dirty.details.tmp
        self.mFx = ints_to_enums[c_stmt.Ist.Dirty.details.mFx]
        self.mAddr = IRExpr._translate(c_stmt.Dirty.details.mAddr)
        self.mSize = c_stmt.Ist.Dirty.details.mSize
        self.nFxState = c_stmt.Ist.Dirty.details.nFxState

        self.args = [ ]
        for i in range(20):
            a = c_stmt.Ist.Dirty.details.args[i]
            if a == ffi.NULL:
                break

            self.args.append(IRExpr._translate(a))

    def __str__(self):
        return "t%s = DIRTY %s %s ::: %s(%s)" % (self.tmp, self.guard, "TODO(effects)", self.cee, ','.join(str(a) for a in self.args))

    @property
    def child_expressions(self):
        expressions = sum((a.child_expressions for a in self.args), [ ])
        expressions.extend(self.args)
        expressions.append(self.guard)
        expressions.extend(self.guard.child_expressions)
        return expressions

class Exit(IRStmt):
    def __init__(self, c_stmt):
        IRStmt.__init__(self, c_stmt)
        self.guard = IRExpr._translate(c_stmt.Ist.Exit.guard)
        self.dst = IRConst._translate(c_stmt.Ist.Exit.dst)
        self.offsIP = c_stmt.Ist.Exit.offsIP
        self.jk = ints_to_enums[c_stmt.Ist.Exit.jk]

    @property
    def jumpkind(self):
        return self.jk

    def __str__(self):
        return "if (%s) { PUT(%d) = %s; %s }" % (self.guard, self.offsIP, hex(self.dst.value), self.jumpkind)

class LoadG(IRStmt):
    def __init__(self, c_stmt):
        IRStmt.__init__(self, c_stmt)

        self.addr = IRExpr._translate(c_stmt.Ist.LoadG.details.addr)
        self.alt = IRExpr._translate(c_stmt.Ist.LoadG.details.alt)
        self.guard = IRExpr._translate(c_stmt.Ist.LoadG.details.guard)
        self.dst = c_stmt.Ist.LoadG.details.dst
        self.cvt = ints_to_enums[c_stmt.Ist.LoadG.details.cvt]

        self.end = ints_to_enums[c_stmt.Ist.LoadG.details.end]

        type_in = ffi.new('int *')
        type_out = ffi.new('int *')
        pvc.typeOfIRLoadGOp(c_stmt.Ist.LoadG.details.cvt, type_in, type_out)
        self.cvt_types = (ints_to_enums[type_in], ints_to_enums[type_out])

    @property
    def endness(self):
        return self.end

    def __str__(self):
        return "t%d = if (%s) %s(LD%s(%s)) else %s" % (self.dst, self.guard, self.cvt, self.end[-2:].lower(), self.addr, self.alt)

class StoreG(IRStmt):
    def __init__(self, c_stmt):
        IRStmt.__init__(self, c_stmt)

        self.addr = IRExpr._translate(c_stmt.Ist.StoreG.details.addr)
        self.data = IRExpr._translate(c_stmt.Ist.StoreG.details.data)
        self.guard = IRExpr._translate(c_stmt.Ist.StoreG.details.guard)
        self.end = ints_to_enums[c_stmt.Ist.StoreG.details.end]

    @property
    def endness(self):
        return self.end

    def __str__(self):
        return "if (%s) ST%s(%s) = %s" % (self.guard, self.end[-2:].lower(), self.addr, self.data)

from ..IRExpr import IRExpr
from .. import IRRegArray, ints_to_enums, IRCallee, ffi, IRConst, pvc
