from . import VEXObject


class IRStmt(VEXObject):
    """
    IR statements in VEX represents operations with side-effects.
    """

    __slots__ = ['arch', 'tag']

    def __init__(self, c_stmt, irsb):
        VEXObject.__init__(self)
        self.arch = irsb.arch
        # self.c_stmt = c_stmt
        self.tag = ints_to_enums[c_stmt.tag]

    def pp(self):
        print self.__str__()

    @property
    def expressions(self):
        expressions = []
        for k in self.__slots__:
            v = getattr(self, k)
            if isinstance(v, IRExpr):
                expressions.append(v)
                expressions.extend(v.child_expressions)
        return expressions

    @property
    def constants(self):
        return sum((e.constants for e in self.expressions), [])

    @staticmethod
    def _translate(c_stmt, irsb):
        if c_stmt[0] == ffi.NULL:
            return None

        tag = c_stmt.tag
        try:
            stmt_class = _tag_to_class[tag]
        except KeyError:
            raise PyVEXError('Unknown/unsupported IRStmtTag %s\n' % ints_to_enums[tag])
        return stmt_class(c_stmt, irsb)


class NoOp(IRStmt):
    """
    A no-operation statement. It is usually the result of an IR optimization.
    """
    def __init__(self, c_stmt, irsb):  # pylint:disable=unused-argument
        IRStmt.__init__(self, c_stmt, irsb)

    def __str__(self):
        return "IR-NoOp"


class IMark(IRStmt):
    """
    An instruction mark. It marks the start of the statements that represent a single machine instruction (the end of
    those statements is marked by the next IMark or the end of the IRSB).  Contains the address and length of the
    instruction.
    """

    __slots__ = ['addr', 'len', 'delta']

    def __init__(self, c_stmt, irsb):
        IRStmt.__init__(self, c_stmt, irsb)
        self.addr = c_stmt.Ist.IMark.addr
        self.len = c_stmt.Ist.IMark.len
        self.delta = c_stmt.Ist.IMark.delta

    def __str__(self):
        return "------ IMark(0x%x, %d, %d) ------" % (self.addr, self.len, self.delta)


class AbiHint(IRStmt):
    """
    An ABI hint, provides specific information about this platform's ABI.
    """

    __slots__ = ['base', 'len', 'nia']

    def __init__(self, c_stmt, irsb):
        IRStmt.__init__(self, c_stmt, irsb)
        self.base = IRExpr._translate(c_stmt.Ist.AbiHint.base, irsb)
        self.len = c_stmt.Ist.AbiHint.len
        self.nia = IRExpr._translate(c_stmt.Ist.AbiHint.nia, irsb)

    def __str__(self):
        return "====== AbiHint(0x%s, %d, %s) ======" % (self.base, self.len, self.nia)


class Put(IRStmt):
    """
    Write to a guest register, at a fixed offset in the guest state.
    """

    __slots__ = ['data', 'offset']

    def __init__(self, c_stmt, irsb):
        IRStmt.__init__(self, c_stmt, irsb)
        self.data = IRExpr._translate(c_stmt.Ist.Put.data, irsb)
        self.offset = c_stmt.Ist.Put.offset

    def __str__(self):
        return "PUT(%s) = %s" % (self.arch.translate_register_name(self.offset, self.data.result_size/8), self.data)


class PutI(IRStmt):
    """
    Write to a guest register, at a non-fixed offset in the guest state.
    """

    __slots__ = ['descr', 'ix', 'data', 'bias']

    def __init__(self, c_stmt, irsb):
        IRStmt.__init__(self, c_stmt, irsb)
        self.descr = IRRegArray(c_stmt.Ist.PutI.details.descr)
        self.ix = IRExpr._translate(c_stmt.Ist.PutI.details.ix, irsb)
        self.data = IRExpr._translate(c_stmt.Ist.PutI.details.data, irsb)
        self.bias = c_stmt.Ist.PutI.details.bias

    def __str__(self):
        return "PutI(%s)[%s,%d] = %s" % (self.descr, self.ix, self.bias, self.data)


class WrTmp(IRStmt):
    """
    Assign a value to a temporary.  Note that SSA rules require each tmp is only assigned to once.  IR sanity checking
    will reject any block containing a temporary which is not assigned to exactly once.
    """

    __slots__ = ['data', 'tmp']

    def __init__(self, c_stmt, irsb):
        IRStmt.__init__(self, c_stmt, irsb)

        self.data = IRExpr._translate(c_stmt.Ist.WrTmp.data, irsb)
        self.tmp = c_stmt.Ist.WrTmp.tmp

    def __str__(self):
        return "t%d = %s" % (self.tmp, self.data)


class Store(IRStmt):
    """
    Write a value to memory..
    """

    __slots__ = ['addr', 'data', 'end']

    def __init__(self, c_stmt, irsb):
        IRStmt.__init__(self, c_stmt, irsb)

        self.addr = IRExpr._translate(c_stmt.Ist.Store.addr, irsb)
        self.data = IRExpr._translate(c_stmt.Ist.Store.data, irsb)
        self.end = ints_to_enums[c_stmt.Ist.Store.end]

    @property
    def endness(self):
        return self.end

    def __str__(self):
        return "ST%s(%s) = %s" % (self.endness[-2:].lower(), self.addr, self.data)


class CAS(IRStmt):
    """
    an atomic compare-and-swap operation.
    """

    __slots__ = ['addr', 'dataLo', 'dataHi', 'expdLo', 'expdHi', 'oldLo', 'oldHi', 'end']

    def __init__(self, c_stmt, irsb):
        IRStmt.__init__(self, c_stmt, irsb)

        self.addr = IRExpr._translate(c_stmt.Ist.CAS.details.addr, irsb)
        self.dataLo = IRExpr._translate(c_stmt.Ist.CAS.details.dataLo, irsb)
        self.dataHi = IRExpr._translate(c_stmt.Ist.CAS.details.dataHi, irsb)
        self.expdLo = IRExpr._translate(c_stmt.Ist.CAS.details.expdLo, irsb)
        self.expdHi = IRExpr._translate(c_stmt.Ist.CAS.details.expdHi, irsb)
        self.oldLo = c_stmt.Ist.CAS.details.oldLo
        self.oldHi = c_stmt.Ist.CAS.details.oldHi
        self.end = ints_to_enums[c_stmt.Ist.CAS.details.end]

    @property
    def endness(self):
        return self.end

    def __str__(self):
        return "t(%s,%s) = CAS%s(%s :: (%s,%s)->(%s,%s))" % (
        self.oldLo, self.oldHi, self.end[-2:].lower(), self.addr, self.expdLo, self.expdHi, self.dataLo, self.dataHi)


class LLSC(IRStmt):
    """
     Either Load-Linked or Store-Conditional, depending on STOREDATA. If STOREDATA is NULL then this is a Load-Linked,
     else it is a Store-Conditional.
    """

    __slots__ = ['addr', 'storedata', 'result', 'end']

    def __init__(self, c_stmt, irsb):
        IRStmt.__init__(self, c_stmt, irsb)

        self.addr = IRExpr._translate(c_stmt.Ist.LLSC.addr, irsb)
        self.storedata = IRExpr._translate(c_stmt.Ist.LLSC.storedata, irsb)
        self.result = c_stmt.Ist.LLSC.result
        self.end = ints_to_enums[c_stmt.Ist.LLSC.end]

    @property
    def endness(self):
        return self.end

    def __str__(self):
        if self.storedata is None:
            return "t%d = LD%s-Linked(%s)" % (self.result, self.end[-2:].lower(), self.addr)
        else:
            return "t%d = ( ST%s-Cond(%s) = %s )" % (self.result, self.end[-2:].lower(), self.addr, self.storedata)


class MBE(IRStmt):

    __slots__ = ['event']

    def __init__(self, c_stmt, irsb):
        IRStmt.__init__(self, c_stmt, irsb)
        self.event = ints_to_enums[c_stmt.Ist.MBE.event]

    def __str__(self):
        return "MBusEvent-" + self.event


class Dirty(IRStmt):

    __slots__ = ['cee', 'guard', 'tmp', 'mFx', 'mAddr', 'mSize', 'nFxState', 'args']

    def __init__(self, c_stmt, irsb):
        IRStmt.__init__(self, c_stmt, irsb)
        self.cee = IRCallee(c_stmt.Ist.Dirty.details.cee)
        self.guard = IRExpr._translate(c_stmt.Ist.Dirty.details.guard, irsb)
        self.tmp = c_stmt.Ist.Dirty.details.tmp
        self.mFx = ints_to_enums[c_stmt.Ist.Dirty.details.mFx]
        self.mAddr = IRExpr._translate(c_stmt.Ist.Dirty.details.mAddr, irsb)
        self.mSize = c_stmt.Ist.Dirty.details.mSize
        self.nFxState = c_stmt.Ist.Dirty.details.nFxState

        args = []
        for i in range(20):
            a = c_stmt.Ist.Dirty.details.args[i]
            if a == ffi.NULL:
                break

            args.append(IRExpr._translate(a, irsb))
        self.args = tuple(args)

    def __str__(self):
        return "t%s = DIRTY %s %s ::: %s(%s)" % (
        self.tmp, self.guard, "TODO(effects)", self.cee, ','.join(str(a) for a in self.args))

    @property
    def child_expressions(self):
        expressions = sum((a.child_expressions for a in self.args), [])
        expressions.extend(self.args)
        expressions.append(self.guard)
        expressions.extend(self.guard.child_expressions)
        return expressions


class Exit(IRStmt):
    """
    A conditional exit from the middle of an IRSB.
    """

    __slots__ = ['guard', 'dst', 'offsIP', 'jk']

    def __init__(self, c_stmt, irsb):
        IRStmt.__init__(self, c_stmt, irsb)
        self.guard = IRExpr._translate(c_stmt.Ist.Exit.guard, irsb)
        self.dst = IRConst._translate(c_stmt.Ist.Exit.dst)
        self.offsIP = c_stmt.Ist.Exit.offsIP
        self.jk = ints_to_enums[c_stmt.Ist.Exit.jk]

    @property
    def jumpkind(self):
        return self.jk

    def __str__(self):
        return "if (%s) { PUT(%s) = %s; %s }" % (
        self.guard, self.arch.translate_register_name(self.offsIP), hex(self.dst.value), self.jumpkind)

    @property
    def child_expressions(self):
        return [self.guard, self.dst] + self.guard.child_expressions


class LoadG(IRStmt):
    """
    A guarded load.
    """

    __slots__ = ['addr', 'alt', 'guard', 'dst', 'cvt', 'end', 'cvt_types']

    def __init__(self, c_stmt, irsb):
        IRStmt.__init__(self, c_stmt, irsb)

        self.addr = IRExpr._translate(c_stmt.Ist.LoadG.details.addr, irsb)
        self.alt = IRExpr._translate(c_stmt.Ist.LoadG.details.alt, irsb)
        self.guard = IRExpr._translate(c_stmt.Ist.LoadG.details.guard, irsb)
        self.dst = c_stmt.Ist.LoadG.details.dst
        self.cvt = ints_to_enums[c_stmt.Ist.LoadG.details.cvt]

        self.end = ints_to_enums[c_stmt.Ist.LoadG.details.end]

        type_in = ffi.new('IRType *')
        type_out = ffi.new('IRType *')
        pvc.typeOfIRLoadGOp(c_stmt.Ist.LoadG.details.cvt, type_out, type_in)
        type_in = ffi.cast('int *', type_in)[0]
        type_out = ffi.cast('int *', type_out)[0]
        self.cvt_types = (ints_to_enums[type_in], ints_to_enums[type_out])

    @property
    def endness(self):
        return self.end

    def __str__(self):
        return "t%d = if (%s) %s(LD%s(%s)) else %s" % (
        self.dst, self.guard, self.cvt, self.end[-2:].lower(), self.addr, self.alt)


class StoreG(IRStmt):
    """
    A guarded store.
    """

    __slots__ = ['addr', 'data', 'guard', 'end']

    def __init__(self, c_stmt, irsb):
        IRStmt.__init__(self, c_stmt, irsb)

        self.addr = IRExpr._translate(c_stmt.Ist.StoreG.details.addr, irsb)
        self.data = IRExpr._translate(c_stmt.Ist.StoreG.details.data, irsb)
        self.guard = IRExpr._translate(c_stmt.Ist.StoreG.details.guard, irsb)
        self.end = ints_to_enums[c_stmt.Ist.StoreG.details.end]

    @property
    def endness(self):
        return self.end

    def __str__(self):
        return "if (%s) ST%s(%s) = %s" % (self.guard, self.end[-2:].lower(), self.addr, self.data)


from .expr import IRExpr
from .const import IRConst
from .enums import IRRegArray, ints_to_enums, enums_to_ints, IRCallee
from .errors import PyVEXError
from . import ffi, pvc

_tag_to_class = {
    enums_to_ints['Ist_NoOp']: NoOp,
    enums_to_ints['Ist_IMark']: IMark,
    enums_to_ints['Ist_AbiHint']: AbiHint,
    enums_to_ints['Ist_Put']: Put,
    enums_to_ints['Ist_PutI']: PutI,
    enums_to_ints['Ist_WrTmp']: WrTmp,
    enums_to_ints['Ist_Store']: Store,
    enums_to_ints['Ist_LoadG']: LoadG,
    enums_to_ints['Ist_StoreG']: StoreG,
    enums_to_ints['Ist_CAS']: CAS,
    enums_to_ints['Ist_LLSC']: LLSC,
    enums_to_ints['Ist_Dirty']: Dirty,
    enums_to_ints['Ist_MBE']: MBE,
    enums_to_ints['Ist_Exit']: Exit,
}
