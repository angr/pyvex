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

class IRTypeEnv(vex): pass
class IRCallee(vex): pass
class IRRegArray(vex): pass

# IRConst heirarchy
class IRConst(vex): pass
class IRConstU1(IRConst): pass
class IRConstU8(IRConst): pass
class IRConstU16(IRConst): pass
class IRConstU32(IRConst): pass
class IRConstU64(IRConst): pass
class IRConstF32(IRConst): pass
class IRConstF32i(IRConst): pass
class IRConstF64(IRConst): pass
class IRConstF64i(IRConst): pass
class IRConstV128(IRConst): pass
class IRConstV256(IRConst): pass

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
class IRStmtNoOp(IRStmt): pass
class IRStmtIMark(IRStmt): pass
class IRStmtAbiHint(IRStmt): pass
class IRStmtPut(IRStmt): pass
class IRStmtPutI(IRStmt): pass
class IRStmtWrTmp(IRStmt): pass
class IRStmtStore(IRStmt): pass
class IRStmtCAS(IRStmt): pass
class IRStmtLLSC(IRStmt): pass
class IRStmtMBE(IRStmt): pass
class IRStmtDirty(IRStmt): pass
class IRStmtExit(IRStmt): pass
class IRStmtLoadG(IRStmt): pass
class IRStmtStoreG(IRStmt): pass

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
class IRExprBinder(IRExpr): pass
class IRExprVECRET(IRExpr): pass
class IRExprBBPTR(IRExpr): pass
class IRExprGetI(IRExpr): pass
class IRExprRdTmp(IRExpr): pass
class IRExprGet(IRExpr): pass
class IRExprQop(IRExpr): pass
class IRExprTriop(IRExpr): pass
class IRExprBinop(IRExpr): pass
class IRExprUnop(IRExpr): pass
class IRExprLoad(IRExpr): pass
class IRExprConst(IRExpr): pass
class IRExprITE(IRExpr): pass
class IRExprCCall(IRExpr): pass

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
