from .. import vex

# IRStmt heirarchy
class IRStmt(vex):
    @property
    def expressions(self):
        expressions = [ ]
        for k,v in self.__dict__.iteritems():
            if isinstance(v, IRExpr):
                expressions.append(v)
                expressions.extend(v.child_expressions)
        return expressions

    @property
    def constants(self):
        return sum((e.constants for e in self.expressions), [ ])

class NoOp(IRStmt):
    def __str__(self):
        return "IR-NoOp"

class IMark(IRStmt):
    def __str__(self):
        return "------ IMark(0x%x, %d, %d) ------" % (self.addr, self.len, self.delta)

class AbiHint(IRStmt):
    def __str__(self):
        return "====== AbiHint(0x%s, %d, %s) ======" % (self.base, self.len, self.nia)

class Put(IRStmt):
    def __str__(self):
        return "PUT(%d) = %s" % (self.offset, self.data)

class PutI(IRStmt):
    def __str__(self):
        return "PUTI(%s)[%s,%d] = %s" % (descr, ix, bias)

class WrTmp(IRStmt):
    def __str__(self):
        return "t%d = %s" % (self.tmp, self.data)

class Store(IRStmt):
    def __str__(self):
        return "ST%s(%s) = %s" % (self.endness[-2:].lower(), self.addr, self.data)

class CAS(IRStmt):
    def __str__(self):
        return "t(%s,%s) = CAS%s(%s :: (%s,%s)->(%s,%s))" % (self.oldLo, self.oldHi, self.end[-2:].lower(), self.addr, self.expdLo, self.expdHi, self.dataLo, self.dataHi)

class LLSC(IRStmt):
    def __str__(self):
        if self.storedata is None:
            return "result = LD%s-Linked(%s)" % (self.end[-2:].lower(), self.addr)
        else:
            return "result = ( ST%s-Cond(%s) = %s )" % (self.end[-2:].lower(), self.addr, self.storedata)

class MBE(IRStmt):
    def __str__(self):
        return "MBusEvent-" + self.event

class Dirty(IRStmt):
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
    def __str__(self):
        return "if (%s) goto {%s} %s" % (self.guard, self.jumpkind, hex(self.dst.value))

class LoadG(IRStmt):
    def __str__(self):
        return "t%d = if (%s) %s(LD%s(%s)) else %s" % (self.tmp, self.guard, self.cvt, self.end[-2:].lower(), self.addr, self.alt)

class StoreG(IRStmt):
    def __str__(self):
        return "if (%s) ST%s(%s) = %s" % (self.guard, self.end[-2:].lower(), self.addr, self.data)

from ..IRExpr import IRExpr
