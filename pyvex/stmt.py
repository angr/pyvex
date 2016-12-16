from . import VEXObject


class IRStmt(VEXObject):
    """
    IR statements in VEX represents operations with side-effects.
    """

    tag = None

    def __init__(self):
        VEXObject.__init__(self)

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
    def _from_c(c_stmt):
        if c_stmt[0] == ffi.NULL:
            return None

        tag_int = c_stmt.tag
        try:
            stmt_class = _tag_to_class[tag_int]
        except KeyError:
            raise PyVEXError('Unknown/unsupported IRStmtTag %s\n' % ints_to_enums[tag_int])
        return stmt_class._from_c(c_stmt)


class NoOp(IRStmt):
    """
    A no-operation statement. It is usually the result of an IR optimization.
    """

    tag = 'Ist_NoOp'

    def __init__(self):  # pylint:disable=unused-argument
        IRStmt.__init__(self)

    def __str__(self):
        return "IR-NoOp"

    @staticmethod
    def _from_c(c_stmt):
        return NoOp()

class IMark(IRStmt):
    """
    An instruction mark. It marks the start of the statements that represent a single machine instruction (the end of
    those statements is marked by the next IMark or the end of the IRSB).  Contains the address and length of the
    instruction.
    """

    __slots__ = ['addr', 'len', 'delta']

    tag = 'Ist_IMark'

    def __init__(self, addr, length, delta):
        IRStmt.__init__(self)
        self.addr = addr
        self.len = length
        self.delta = delta

    def __str__(self):
        return "------ IMark(0x%x, %d, %d) ------" % (self.addr, self.len, self.delta)

    @staticmethod
    def _from_c(c_stmt):
        return IMark(c_stmt.Ist.IMark.addr,
                     c_stmt.Ist.IMark.len,
                     c_stmt.Ist.IMark.delta)


class AbiHint(IRStmt):
    """
    An ABI hint, provides specific information about this platform's ABI.
    """

    __slots__ = ['base', 'len', 'nia']

    tag = 'Ist_AbiHint'

    def __init__(self, base, length, nia):
        IRStmt.__init__(self)
        self.base = base
        self.len = length
        self.nia = nia

    def __str__(self):
        return "====== AbiHint(0x%s, %d, %s) ======" % (self.base, self.len, self.nia)

    @staticmethod
    def _from_c(c_stmt):
        return AbiHint(IRExpr._from_c(c_stmt.Ist.AbiHint.base),
                       c_stmt.Ist.AbiHint.len,
                       IRExpr._from_c(c_stmt.Ist.AbiHint.nia))

class Put(IRStmt):
    """
    Write to a guest register, at a fixed offset in the guest state.
    """

    __slots__ = ['data', 'offset']

    tag = 'Ist_Put'

    def __init__(self, data, offset):
        IRStmt.__init__(self)
        self.data = data
        self.offset = offset

    ## TODO: Check if result_size and arch are available before looking of arch register name
    def __str__(self, reg_name=None):
        if reg_name:
            return "PUT(%s) = %s" % (reg_name, self.data)
        else:
            return "PUT(offset=%s) = %s" % (self.offset, self.data)

    @staticmethod
    def _from_c(c_stmt):
        return Put(IRExpr._from_c(c_stmt.Ist.Put.data),
                   c_stmt.Ist.Put.offset)

class PutI(IRStmt):
    """
    Write to a guest register, at a non-fixed offset in the guest state.
    """

    __slots__ = ['descr', 'ix', 'data', 'bias']

    tag = 'Ist_PutI'

    def __init__(self, descr, ix, data, bias):
        IRStmt.__init__(self)
        self.descr = descr
        self.ix = ix
        self.data = data
        self.bias = bias

    def __str__(self):
        return "PutI(%s)[%s,%d] = %s" % (self.descr, self.ix, self.bias, self.data)

    @staticmethod
    def _from_c(c_stmt):
        return PutI(IRRegArray._from_c(c_stmt.Ist.PutI.details.descr),
                    IRExpr._from_c(c_stmt.Ist.PutI.details.ix),
                    IRExpr._from_c(c_stmt.Ist.PutI.details.data),
                    c_stmt.Ist.PutI.details.bias)

class WrTmp(IRStmt):
    """
    Assign a value to a temporary.  Note that SSA rules require each tmp is only assigned to once.  IR sanity checking
    will reject any block containing a temporary which is not assigned to exactly once.
    """

    __slots__ = ['data', 'tmp']

    tag = 'Ist_WrTmp'

    def __init__(self, tmp, data):
        IRStmt.__init__(self)

        self.tmp = tmp
        self.data = data

    def __str__(self, reg_name=None):
        # Support for named register in string representation of expr.Get
        if reg_name and isinstance(self.data, expr.Get):
            return "t%d = %s" % (self.tmp, self.data.__str__(reg_name=reg_name))
        else:
            return "t%d = %s" % (self.tmp, self.data)

    @staticmethod
    def _from_c(c_stmt):
        return WrTmp(c_stmt.Ist.WrTmp.tmp,
                     IRExpr._from_c(c_stmt.Ist.WrTmp.data))

class Store(IRStmt):
    """
    Write a value to memory..
    """

    __slots__ = ['addr', 'data', 'end']

    tag = 'Ist_Store'

    def __init__(self, addr, data, end):
        IRStmt.__init__(self)

        self.addr = addr
        self.data = data
        self.end = end

    @property
    def endness(self):
        return self.end

    def __str__(self):
        return "ST%s(%s) = %s" % (self.endness[-2:].lower(), self.addr, self.data)

    @staticmethod
    def _from_c(c_stmt):
        return Store(IRExpr._from_c(c_stmt.Ist.Store.addr),
                     IRExpr._from_c(c_stmt.Ist.Store.data),
                     ints_to_enums[c_stmt.Ist.Store.end])

class CAS(IRStmt):
    """
    an atomic compare-and-swap operation.
    """

    __slots__ = ['addr', 'dataLo', 'dataHi', 'expdLo', 'expdHi', 'oldLo', 'oldHi', 'end']

    tag = 'Ist_CAS'

    def __init__(self, addr, dataLo, dataHi, expdLo, expdHi, oldLo, oldHi, end):
        IRStmt.__init__(self)

        self.addr = addr
        self.dataLo = dataLo
        self.dataHi = dataHi
        self.expdLo = expdLo
        self.expdHi = expdHi
        self.oldLo = oldLo
        self.oldHi = oldHi
        self.end = end

    @property
    def endness(self):
        return self.end

    def __str__(self):
        return "t(%s,%s) = CAS%s(%s :: (%s,%s)->(%s,%s))" % (
        self.oldLo, self.oldHi, self.end[-2:].lower(), self.addr, self.expdLo, self.expdHi, self.dataLo, self.dataHi)

    @staticmethod
    def _from_c(c_stmt):
        return CAS(IRExpr._from_c(c_stmt.Ist.CAS.details.addr),
                   IRExpr._from_c(c_stmt.Ist.CAS.details.dataLo),
                   IRExpr._from_c(c_stmt.Ist.CAS.details.dataHi),
                   IRExpr._from_c(c_stmt.Ist.CAS.details.expdLo),
                   IRExpr._from_c(c_stmt.Ist.CAS.details.expdHi),
                   c_stmt.Ist.CAS.details.oldLo,
                   c_stmt.Ist.CAS.details.oldHi,
                   ints_to_enums[c_stmt.Ist.CAS.details.end])

class LLSC(IRStmt):
    """
     Either Load-Linked or Store-Conditional, depending on STOREDATA. If STOREDATA is NULL then this is a Load-Linked,
     else it is a Store-Conditional.
    """

    __slots__ = ['addr', 'storedata', 'result', 'end']

    tag = 'Ist_LLSC'

    def __init__(self, addr, storedata, result, end):
        IRStmt.__init__(self)

        self.addr = addr
        self.storedata = storedata
        self.result = result
        self.end = end

    @property
    def endness(self):
        return self.end

    def __str__(self):
        if self.storedata is None:
            return "t%d = LD%s-Linked(%s)" % (self.result, self.end[-2:].lower(), self.addr)
        else:
            return "t%d = ( ST%s-Cond(%s) = %s )" % (self.result, self.end[-2:].lower(), self.addr, self.storedata)

    @staticmethod
    def _from_c(c_stmt):
        return LLSC(IRExpr._from_c(c_stmt.Ist.LLSC.addr),
                    IRExpr._from_c(c_stmt.Ist.LLSC.storedata),
                    c_stmt.Ist.LLSC.result,
                    ints_to_enums[c_stmt.Ist.LLSC.end])

class MBE(IRStmt):

    __slots__ = ['event']

    tag = 'Ist_MBE'

    def __init__(self, event):
        IRStmt.__init__(self)
        self.event = event

    def __str__(self):
        return "MBusEvent-" + self.event

    @staticmethod
    def _from_c(c_stmt):
        return MBE(ints_to_enums[c_stmt.Ist.MBE.event])

class Dirty(IRStmt):

    __slots__ = ['cee', 'guard', 'args', 'tmp', 'mFx', 'mAddr', 'mSize', 'nFxState']

    tag = 'Ist_Dirty'

    def __init__(self, cee, guard, args, tmp, mFx, mAddr, mSize, nFxState):
        IRStmt.__init__(self)
        self.cee = cee
        self.guard = guard
        self.args = tuple(args)
        self.tmp = tmp
        self.mFx = mFx
        self.mAddr = mAddr
        self.mSize = mSize
        self.nFxState = nFxState

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

    @staticmethod
    def _from_c(c_stmt):
        args = []
        for i in xrange(20):
            a = c_stmt.Ist.Dirty.details.args[i]
            if a == ffi.NULL:
                break

            args.append(IRExpr._from_c(a))

        return Dirty(IRCallee._from_c(c_stmt.Ist.Dirty.details.cee),
                     IRExpr._from_c(c_stmt.Ist.Dirty.details.guard),
                     tuple(args),
                     c_stmt.Ist.Dirty.details.tmp,
                     ints_to_enums[c_stmt.Ist.Dirty.details.mFx],
                     IRExpr._from_c(c_stmt.Ist.Dirty.details.mAddr),
                     c_stmt.Ist.Dirty.details.mSize,
                     c_stmt.Ist.Dirty.details.nFxState)

class Exit(IRStmt):
    """
    A conditional exit from the middle of an IRSB.
    """

    __slots__ = ['guard', 'dst', 'offsIP', 'jk']

    tag = 'Ist_Exit'

    def __init__(self, guard, dst, jk, offsIP):
        IRStmt.__init__(self)
        self.guard = guard
        self.dst = dst
        self.offsIP = offsIP
        self.jk = jk

    @property
    def jumpkind(self):
        return self.jk

    def __str__(self, reg_name=None):
        if reg_name is None:
            return "if (%s) { PUT(offset=%d) = %#x; %s }" % (self.guard, self.offsIP, self.dst.value, self.jumpkind)
        else:
            return "if (%s) { PUT(%s) = %#x; %s }" % (self.guard, reg_name, self.dst.value, self.jumpkind)

    @property
    def child_expressions(self):
        return [self.guard, self.dst] + self.guard.child_expressions

    @staticmethod
    def _from_c(c_stmt):
        return Exit(IRExpr._from_c(c_stmt.Ist.Exit.guard),
                    IRConst._from_c(c_stmt.Ist.Exit.dst),
                    ints_to_enums[c_stmt.Ist.Exit.jk],
                    c_stmt.Ist.Exit.offsIP)

class LoadG(IRStmt):
    """
    A guarded load.
    """

    __slots__ = ['addr', 'alt', 'guard', 'dst', 'cvt', 'end', 'cvt_types']

    tag = 'Ist_LoadG'

    def __init__(self, end, cvt, dst, addr, alt, guard):
        IRStmt.__init__(self)

        self.addr = addr
        self.alt = alt
        self.guard = guard
        self.dst = dst
        self.cvt = cvt
        self.end = end

        type_in = ffi.new('IRType *')
        type_out = ffi.new('IRType *')
        pvc.typeOfIRLoadGOp(enums_to_ints[self.cvt], type_out, type_in)
        type_in = ffi.cast('int *', type_in)[0]
        type_out = ffi.cast('int *', type_out)[0]
        self.cvt_types = (ints_to_enums[type_in], ints_to_enums[type_out])

    @property
    def endness(self):
        return self.end

    def __str__(self):
        return "t%d = if (%s) %s(LD%s(%s)) else %s" % (
        self.dst, self.guard, self.cvt, self.end[-2:].lower(), self.addr, self.alt)

    @staticmethod
    def _from_c(c_stmt):
        return LoadG(ints_to_enums[c_stmt.Ist.LoadG.details.end],
                     ints_to_enums[c_stmt.Ist.LoadG.details.cvt],
                     c_stmt.Ist.LoadG.details.dst,
                     IRExpr._from_c(c_stmt.Ist.LoadG.details.addr),
                     IRExpr._from_c(c_stmt.Ist.LoadG.details.alt),
                     IRExpr._from_c(c_stmt.Ist.LoadG.details.guard))

class StoreG(IRStmt):
    """
    A guarded store.
    """

    __slots__ = ['addr', 'data', 'guard', 'end']

    tag = 'Ist_StoreG'

    def __init__(self, end, addr, data, guard):
        IRStmt.__init__(self)

        self.addr = addr
        self.data = data
        self.guard = guard
        self.end = end

    @property
    def endness(self):
        return self.end

    def __str__(self):
        return "if (%s) ST%s(%s) = %s" % (self.guard, self.end[-2:].lower(), self.addr, self.data)

    @staticmethod
    def _from_c(c_stmt):
        return StoreG(ints_to_enums[c_stmt.Ist.StoreG.details.end],
                      IRExpr._from_c(c_stmt.Ist.StoreG.details.addr),
                      IRExpr._from_c(c_stmt.Ist.StoreG.details.data),
                      IRExpr._from_c(c_stmt.Ist.StoreG.details.guard))


from .expr import IRExpr
from .const import IRConst
from .enums import IRRegArray, ints_to_enums, enums_to_ints, IRCallee
from .errors import PyVEXError
from . import ffi, pvc, expr

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
