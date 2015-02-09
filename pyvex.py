import pyvex_c
import sys

#import collections
#_counts = collections.Counter()

class vex(object):
    pass
    #def __init__(self):
    #   print "CREATING:",type(self)
    #   _counts[type(self)] += 1

    #def __del__(self):
    #   global n
    #   print "DELETING:",type(self)
    #   _counts[type(self)] -= 1

class PyVEXError(Exception): pass

# various objects
class IRSB(vex):
    def __init__(self, *args, **kwargs):
        vex.__init__(self)
        pyvex_c.init_IRSB(self, *args, **kwargs)

    def pp(self):
        print "IRSB {"
        print "   %s" % self.tyenv
        print ""
        for i,s in enumerate(self.statements):
            print "   %02d | %s" % (i,s)
        print "   NEXT: PUT(%s) = %s; %s" % (self.offsIP, self.next, self.jumpkind)
        print "}"

class IRTypeEnv(vex):
    def __str__(self):
        return ' '.join(("t%d:%s" % (i,t)) for i,t in enumerate(self.types))

class IRCallee(vex):
    def __str__(self):
        return self.name
class IRRegArray(vex):
    def __str__(self):
        return "%s:%sx%d" % (self.base, self.elemTy[4:], self.nElems)

# IRConst heirarchy
class IRConst(vex): pass
class IRConstU1(IRConst):
    def __str__(self):
        return "%d" % self.value
class IRConstU8(IRConst):
    def __str__(self):
        return "0x%02x" % self.value
class IRConstU16(IRConst):
    def __str__(self):
        return "0x%04x" % self.value
class IRConstU32(IRConst):
    def __str__(self):
        return "0x%08x" % self.value
class IRConstU64(IRConst):
    def __str__(self):
        return "0x%016x" % self.value
class IRConstF32(IRConst):
    def __str__(self):
        return "%f" % self.value
class IRConstF32i(IRConst):
    def __str__(self):
        return "%f" % self.value
class IRConstF64(IRConst):
    def __str__(self):
        return "%f" % self.value
class IRConstF64i(IRConst):
    def __str__(self):
        return "%f" % self.value
class IRConstV128(IRConst):
    def __str__(self):
        return "%x" % self.value
class IRConstV256(IRConst):
    def __str__(self):
        return "%x" % self.value

IRConst.U1 = IRConstU1
IRConst.U8 = IRConstU8
IRConst.U16 = IRConstU16
IRConst.U32 = IRConstU32
IRConst.U64 = IRConstU64
IRConst.F32 = IRConstF32
IRConst.F32i = IRConstF32i
IRConst.F64 = IRConstF64
IRConst.F64i = IRConstF64i
IRConst.V128 = IRConstV128
IRConst.V256 = IRConstV256

# IRStmt heirarchy
class IRStmt(vex): pass
class IRStmtNoOp(IRStmt):
    def __str__(self):
        return "IR-NoOp"
class IRStmtIMark(IRStmt):
    def __str__(self):
        return "------ IMark(0x%x, %d, %d) ------" % (self.addr, self.len, self.delta)
class IRStmtAbiHint(IRStmt):
    def __str__(self):
        return "====== AbiHint(0x%s, %d, %s) ======" % (self.base, self.len, self.nia)
class IRStmtPut(IRStmt):
    def __str__(self):
        return "PUT(%d) = %s" % (self.offset, self.data)
class IRStmtPutI(IRStmt):
    def __str__(self):
        return "PUTI(%s)[%s,%d] = %s" % (descr, ix, bias)
class IRStmtWrTmp(IRStmt):
    def __str__(self):
        return "t%d = %s" % (self.tmp, self.data)
class IRStmtStore(IRStmt):
    def __str__(self):
        return "ST%s(%s) = %s" % (self.endness[-2:].lower(), self.addr, self.data)
class IRStmtCAS(IRStmt):
    def __str__(self):
        return "t(%s,%s) = CAS%s(%s :: (%s,%s)->(%s,%s))" % (self.oldLo, self.oldHi, self.end[-2:].lower(), self.addr, self.expdLo, self.expdHi, self.dataLo, self.dataHi)
class IRStmtLLSC(IRStmt):
    def __str__(self):
        if self.storedata is None:
            return "result = LD%s-Linked(%s)" % (self.end[-2:].lower(), self.addr)
        else:
            return "result = ( ST%s-Cond(%s) = %s )" % (self.end[-2:].lower(), self.addr, self.storedata)
class IRStmtMBE(IRStmt):
    def __str__(self):
        return "MBusEvent-" + self.event
class IRStmtDirty(IRStmt):
    def __str__(self):
        return "t%s = DIRTY %s %s ::: %s(%s)" % (self.tmp, self.guard, "TODO(effects)", self.cee, ','.join(str(a) for a in self.args))
class IRStmtExit(IRStmt):
    def __str__(self):
        return "if (%s) goto {%s} %s" % (self.guard, self.jumpkind, hex(self.dst.value))
class IRStmtLoadG(IRStmt):
    def __str__(self):
        return "t%d = if (%s) %s(LD%s(%s)) else %s" % (self.tmp, self.guard, self.cvt, self.end[-2:].lower(), self.addr, self.alt)
class IRStmtStoreG(IRStmt):
    def __str__(self):
        return "if (%s) ST%s(%s) = %s" % (self.guard, self.end[-2:].lower(), self.addr, self.data)

IRStmt.NoOp = IRStmtNoOp
IRStmt.IMark = IRStmtIMark
IRStmt.AbiHint = IRStmtAbiHint
IRStmt.Put = IRStmtPut
IRStmt.PutI = IRStmtPutI
IRStmt.WrTmp = IRStmtWrTmp
IRStmt.Store = IRStmtStore
IRStmt.CAS = IRStmtCAS
IRStmt.LLSC = IRStmtLLSC
IRStmt.MBE = IRStmtMBE
IRStmt.Dirty = IRStmtDirty
IRStmt.Exit = IRStmtExit
IRStmt.LoadG = IRStmtLoadG
IRStmt.StoreG = IRStmtStoreG

# IRExpr heirarchy
class IRExpr(vex): pass
class IRExprBinder(IRExpr):
    def __str__(self):
        return "Binder"
class IRExprVECRET(IRExpr):
    def __str__(self):
        return "VECRET"
class IRExprBBPTR(IRExpr):
    def __str__(self):
        return "BBPTR"
class IRExprGetI(IRExpr):
    def __str__(self):
        return "GETI(%s)[%s,%s]" % (self.descr, self.ix, self.bias)
class IRExprRdTmp(IRExpr):
    def __str__(self):
        return "t%d" % self.tmp
class IRExprGet(IRExpr):
    def __str__(self):
        return "GET:%s(%d)" % (self.ty[4:], self.offset)
class IRExprQop(IRExpr):
    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))
class IRExprTriop(IRExpr):
    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))
class IRExprBinop(IRExpr):
    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))
class IRExprUnop(IRExpr):
    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))
class IRExprLoad(IRExpr):
    def __str__(self):
        return "LD%s:%s(%s)" % (self.end[-2:].lower(), self.ty[4:], self.addr)
class IRExprConst(IRExpr):
    def __str__(self):
        return str(self.con)
class IRExprITE(IRExpr):
    def __str__(self):
        return "ITE(%s,%s,%s)" % (self.cond, self.iftrue, self.iffalse)
class IRExprCCall(IRExpr):
    def __str__(self):
        return "%s(%s):%s" % (self.cee, ','.join(str(a) for a in self.args), self.retty)

IRExpr.Binder = IRExprBinder
IRExpr.VECRET = IRExprVECRET
IRExpr.BBPTR = IRExprBBPTR
IRExpr.GetI = IRExprGetI
IRExpr.RdTmp = IRExprRdTmp
IRExpr.Get = IRExprGet
IRExpr.Qop = IRExprQop
IRExpr.Triop = IRExprTriop
IRExpr.Binop = IRExprBinop
IRExpr.Unop = IRExprUnop
IRExpr.Load = IRExprLoad
IRExpr.Const = IRExprConst
IRExpr.ITE = IRExprITE
IRExpr.CCall = IRExprCCall


# and initialize!
pyvex_c.init(sys.modules[__name__])
for i in dir(pyvex_c):
    if not i.startswith('enum'):
        continue
    setattr(sys.modules[__name__], i, getattr(pyvex_c, i))
typeOfIROp = pyvex_c.typeOfIROp
