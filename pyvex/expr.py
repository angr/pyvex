from . import VEXObject

import logging
l = logging.getLogger("pyvex.expr")

class IRExpr(VEXObject):
    """
    IR expressions in VEX represent operations without side effects.
    """

    tag = None

    def __init__(self):
        VEXObject.__init__(self)

    def pp(self):
        print self.__str__()

    @property
    def child_expressions(self):
        """
        A list of all of the expressions that this expression ends up evaluating.
        """
        expressions = [ ]
        for k in self.__slots__:
            v = getattr(self, k)
            if isinstance(v, IRExpr):
                expressions.append(v)
                expressions.extend(v.child_expressions)
        return expressions

    @property
    def constants(self):
        """
        A list of all of the constants that this expression ends up using.
        """
        constants = [ ]
        for k in self.__slots__:
            v = getattr(self, k)
            if isinstance(v, IRExpr):
                constants.extend(v.constants)
            elif isinstance(v, IRConst):
                constants.append(v)
        return constants

    def result_size(self, tyenv):
        return type_sizes[self.result_type(tyenv)]

    def result_type(self, tyenv):
        raise NotImplementedError

    @staticmethod
    def _from_c(c_expr):
        if c_expr == ffi.NULL or c_expr[0] == ffi.NULL:
            return None

        tag_int = c_expr.tag

        try:
            return tag_to_class[tag_int]._from_c(c_expr)
        except KeyError:
            raise PyVEXError('Unknown/unsupported IRExprTag %s\n' % ints_to_enums[tag_int])
    _translate = _from_c

    @staticmethod
    def _to_c(expr):
        try:
            tag_int = enums_to_ints[expr.tag]
            return tag_to_class[tag_int]._to_c(expr)
        except KeyError:
            raise PyVEXError('Unknown/unsupported IRExprTag %s\n' % expr.tag)

    def typecheck(self, tyenv):
        return self.result_type(tyenv)


class Binder(IRExpr):
    """
    Used only in pattern matching within Vex. Should not be seen outside of Vex.
    """

    __slots__ = ['binder']

    tag = 'Iex_Binder'

    def __init__(self, binder):
        IRExpr.__init__(self)
        self.binder = binder

    def __str__(self):
        return "Binder"

    @staticmethod
    def _from_c(c_expr):
        return Binder(c_expr.iex.Binder.binder)

    @staticmethod
    def _to_c(expr):
        return pvc.IRExpr_Binder(expr.binder)

    def result_type(self, tyenv):
        return 'Ity_INVALID'

class VECRET(IRExpr):

    tag = 'Iex_VECRET'

    def __init__(self):
        IRExpr.__init__(self)

    def __str__(self):
        return "VECRET"

    @staticmethod
    def _from_c(c_expr):
        return VECRET()

    @staticmethod
    def _to_c(expr):
        return pvc.IRExpr_VECRET()

    def result_type(self, tyenv):
        return 'Ity_INVALID'


class BBPTR(IRExpr):

    tag = 'Iex_BBPTR'

    def __init__(self):
        IRExpr.__init__(self)

    def __str__(self):
        return "BBPTR"

    @staticmethod
    def _from_c(c_expr):
        return BBPTR()

    @staticmethod
    def _to_c(expr):
        return pvc.IRExpr_BBPTR()

    def result_type(self, tyenv):
        return 'Ity_INVALID'


class GetI(IRExpr):
    """
    Read a guest register at a non-fixed offset in the guest state.
    """

    __slots__ = ['descr', 'ix', 'bias']

    tag = 'Iex_GetI'

    def __init__(self, descr, ix, bias):
        IRExpr.__init__(self)
        self.descr = descr
        self.ix = ix
        self.bias = bias

    @property
    def description(self):
        return self.descr

    @property
    def index(self):
        return self.ix

    def __str__(self):
        return "GetI(%s)[%s,%s]" % (self.descr, self.ix, self.bias)

    @staticmethod
    def _from_c(c_expr):
        descr = IRRegArray._from_c(c_expr.Iex.GetI.descr)
        ix = IRExpr._from_c(c_expr.Iex.GetI.ix)
        bias = c_expr.Iex.GetI.bias
        return GetI(descr, ix, bias)

    @staticmethod
    def _to_c(expr):
        return pvc.IRExpr_GetI(IRRegArray._to_c(expr.descr),
                               IRExpr._to_c(expr.ix),
                               expr.bias)

    def result_type(self, tyenv):
        return self.descr.elemTy


class RdTmp(IRExpr):
    """
    Read the value held by a temporary.
    """

    __slots__ = ['tmp']

    tag = 'Iex_RdTmp'

    def __init__(self, tmp):
        IRExpr.__init__(self)
        self.tmp = tmp

    def __str__(self):
        return "t%d" % self.tmp

    @staticmethod
    def _from_c(c_expr):
        return RdTmp(c_expr.Iex.RdTmp.tmp)

    @staticmethod
    def _to_c(expr):
        return pvc.IRExpr_RdTmp(expr.tmp)

    def result_type(self, tyenv):
        return tyenv.lookup(self.tmp)


class Get(IRExpr):
    """
    Read a guest register, at a fixed offset in the guest state.
    """

    __slots__ = ['offset', 'ty']

    tag = 'Iex_Get'

    def __init__(self, offset, ty):
        IRExpr.__init__(self)
        self.offset = offset
        self.ty = ty

    @property
    def type(self):
        return self.ty

    def __str__(self, reg_name=None):
        if reg_name:
            return "GET:%s(%s)" % (self.ty[4:], reg_name)
        else:
            return "GET:%s(offset=%s)" % (self.ty[4:], self.offset)

    @staticmethod
    def _from_c(c_expr):
        return Get(c_expr.Iex.Get.offset,
                   ints_to_enums[c_expr.Iex.Get.ty])

    @staticmethod
    def _to_c(expr):
        return pvc.IRExpr_Get(expr.offset,
                              enums_to_ints[expr.ty])

    def result_type(self, tyenv):
        return self.ty


class Qop(IRExpr):
    """
    A quaternary operation (4 arguments).
    """

    __slots__ = ['op', 'args']

    tag = 'Iex_Qop'

    def __init__(self, op, args):
        IRExpr.__init__(self)
        self.op = op
        self.args = args

    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))

    @property
    def child_expressions(self):
        expressions = sum((a.child_expressions for a in self.args), [ ])
        expressions.extend(self.args)
        return expressions

    @staticmethod
    def _from_c(c_expr):
        return Qop(ints_to_enums[c_expr.Iex.Qop.details.op],
                   [IRExpr._from_c(arg)
                    for arg in [c_expr.Iex.Qop.details.arg1,
                                c_expr.Iex.Qop.details.arg2,
                                c_expr.Iex.Qop.details.arg3,
                                c_expr.Iex.Qop.details.arg4]])

    @staticmethod
    def _to_c(expr):
        return pvc.IRExpr_Qop(enums_to_ints[expr.op],
                              *[IRExpr._to_c(arg)
                                for arg in expr.args])

    def result_type(self, tyenv):
        return op_type(self.op)

    def typecheck(self, tyenv):
        resty, (arg1ty, arg2ty, arg3ty, arg4ty) = op_arg_types(self.op)
        arg1ty_real = self.args[0].typecheck(tyenv)
        arg2ty_real = self.args[1].typecheck(tyenv)
        arg3ty_real = self.args[2].typecheck(tyenv)
        arg4ty_real = self.args[3].typecheck(tyenv)
        if arg1ty_real is None or arg2ty_real is None or arg3ty_real is None or arg4ty_real is None:
            return None

        if arg1ty_real != arg1ty:
            l.debug("First arg of %s must be %s", self.op, arg1ty)
            return None
        if arg2ty_real != arg2ty:
            l.debug("Second arg of %s must be %s", self.op, arg2ty)
            return None
        if arg3ty_real != arg3ty:
            l.debug("Third arg of %s must be %s", self.op, arg3ty)
            return None
        if arg4ty_real != arg4ty:
            l.debug("Fourth arg of %s must be %s", self.op, arg4ty)
            return None

        return resty

class Triop(IRExpr):
    """
    A ternary operation (3 arguments)
    """

    __slots__ = ['op', 'args']

    tag = 'Iex_Triop'

    def __init__(self, op, args):
        IRExpr.__init__(self)
        self.op = op
        self.args = args

    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))

    @property
    def child_expressions(self):
        expressions = sum((a.child_expressions for a in self.args), [ ])
        expressions.extend(self.args)
        return expressions

    @staticmethod
    def _from_c(c_expr):
        return Triop(ints_to_enums[c_expr.Iex.Triop.details.op],
                     [IRExpr._from_c(arg)
                      for arg in [c_expr.Iex.Triop.details.arg1,
                                  c_expr.Iex.Triop.details.arg2,
                                  c_expr.Iex.Triop.details.arg3]])

    @staticmethod
    def _to_c(expr):
        return pvc.IRExpr_Triop(enums_to_ints[expr.op],
                                *[IRExpr._to_c(arg)
                                  for arg in expr.args])

    def result_type(self, tyenv):
        return op_type(self.op)

    def typecheck(self, tyenv):
        resty, (arg1ty, arg2ty, arg3ty) = op_arg_types(self.op)
        arg1ty_real = self.args[0].typecheck(tyenv)
        arg2ty_real = self.args[1].typecheck(tyenv)
        arg3ty_real = self.args[2].typecheck(tyenv)
        if arg1ty_real is None or arg2ty_real is None or arg3ty_real is None:
            return None

        if arg1ty_real != arg1ty:
            l.debug("First arg of %s must be %s", self.op, arg1ty)
            return None
        if arg2ty_real != arg2ty:
            l.debug("Second arg of %s must be %s", self.op, arg2ty)
            return None
        if arg3ty_real != arg3ty:
            l.debug("Third arg of %s must be %s", self.op, arg3ty)
            return None

        return resty


class Binop(IRExpr):
    """
    A binary operation (2 arguments).
    """

    __slots__ = ['op', 'args']

    tag = 'Iex_Binop'

    def __init__(self, op, args):
        IRExpr.__init__(self)
        self.op = op
        self.args = args

    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))

    @property
    def child_expressions(self):
        expressions = sum((a.child_expressions for a in self.args), [ ])
        expressions.extend(self.args)
        return expressions

    @staticmethod
    def _from_c(c_expr):
        return Binop(ints_to_enums[c_expr.Iex.Binop.op],
                     [IRExpr._from_c(arg)
                      for arg in [c_expr.Iex.Binop.arg1,
                                  c_expr.Iex.Binop.arg2]])

    @staticmethod
    def _to_c(expr):
        return pvc.IRExpr_Binop(enums_to_ints[expr.op],
                                *[IRExpr._to_c(arg)
                                  for arg in expr.args])

    def result_type(self, tyenv):
        return op_type(self.op)

    def typecheck(self, tyenv):
        resty, (arg1ty, arg2ty) = op_arg_types(self.op)
        arg1ty_real = self.args[0].typecheck(tyenv)
        arg2ty_real = self.args[1].typecheck(tyenv)
        if arg1ty_real is None or arg2ty_real is None:
            return None

        if arg1ty_real != arg1ty:
            l.debug("First arg of %s must be %s", self.op, arg1ty)
            return None
        if arg2ty_real != arg2ty:
            l.debug("Second arg of %s must be %s", self.op, arg2ty)
            return None

        return resty


class Unop(IRExpr):
    """
    A unary operation (1 argument).
    """

    __slots__ = ['op', 'args']

    tag = 'Iex_Unop'

    def __init__(self, op, args):
        IRExpr.__init__(self)
        self.op = op
        self.args = args

    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))

    @property
    def child_expressions(self):
        expressions = sum((a.child_expressions for a in self.args), [ ])
        expressions.extend(self.args)
        return expressions

    @staticmethod
    def _from_c(c_expr):
        return Unop(ints_to_enums[c_expr.Iex.Unop.op],
                    [IRExpr._from_c(c_expr.Iex.Unop.arg)])

    @staticmethod
    def _to_c(expr):
        return pvc.IRExpr_Unop(enums_to_ints[expr.op],
                               IRExpr._to_c(expr.args[0]))

    def result_type(self, tyenv):
        return op_type(self.op)

    def typecheck(self, tyenv):
        resty, (arg1ty,) = op_arg_types(self.op)
        arg1ty_real = self.args[0].typecheck(tyenv)
        if arg1ty_real is None:
            return None

        if arg1ty_real != arg1ty:
            l.debug("First arg of %s must be %s", self.op, arg1ty)
            return None

        return resty


class Load(IRExpr):
    """
    A load from memory.
    """

    __slots__ = ['end', 'ty', 'addr']

    tag = 'Iex_Load'

    def __init__(self, end, ty, addr):
        IRExpr.__init__(self)
        self.end = end
        self.ty = ty
        self.addr = addr

    @property
    def endness(self):
        return self.end

    @property
    def type(self):
        return self.ty

    def __str__(self):
        return "LD%s:%s(%s)" % (self.end[-2:].lower(), self.ty[4:], self.addr)

    @staticmethod
    def _from_c(c_expr):
        return Load(ints_to_enums[c_expr.Iex.Load.end],
                    ints_to_enums[c_expr.Iex.Load.ty],
                    IRExpr._from_c(c_expr.Iex.Load.addr))

    @staticmethod
    def _to_c(expr):
        return pvc.IRExpr_Load(enums_to_ints[expr.end],
                               enums_to_ints[expr.ty],
                               IRExpr._to_c(expr.addr))

    def result_type(self, tyenv):
        return self.ty

    def typecheck(self, tyenv):
        addrty = self.addr.typecheck(tyenv)
        if addrty is None:
            return None
        if addrty != tyenv.wordty:
            l.debug("Address must be word-sized")
            return None
        return self.ty


class Const(IRExpr):
    """
    A constant expression.
    """

    __slots__ = ['con']

    tag = 'Iex_Const'

    def __init__(self, con):
        IRExpr.__init__(self)
        self.con = con

    def __str__(self):
        return str(self.con)

    @staticmethod
    def _from_c(c_expr):
        return Const(IRConst._from_c(c_expr.Iex.Const.con))

    @staticmethod
    def _to_c(expr):
        return pvc.IRExpr_Const(IRConst._to_c(expr.con))

    def result_type(self, tyenv):
        return self.con.type


class ITE(IRExpr):
    """
    An if-then-else expression.
    """

    __slots__ = ['cond', 'iffalse', 'iftrue']

    tag = 'Iex_ITE'

    def __init__(self, cond, iffalse, iftrue):
        IRExpr.__init__(self)
        self.cond = cond
        self.iffalse = iffalse
        self.iftrue = iftrue

    def __str__(self):
        return "ITE(%s,%s,%s)" % (self.cond, self.iftrue, self.iffalse)

    @staticmethod
    def _from_c(c_expr):
        return ITE(IRExpr._from_c(c_expr.Iex.ITE.cond),
                   IRExpr._from_c(c_expr.Iex.ITE.iffalse),
                   IRExpr._from_c(c_expr.Iex.ITE.iftrue))

    @staticmethod
    def _to_c(expr):
        return pvc.IRExpr_ITE(IRExpr._to_c(expr.cond),
                              IRExpr._to_c(expr.iftrue),
                              IRExpr._to_c(expr.iffalse))

    def result_type(self, tyenv):
        return self.iftrue.result_type(tyenv)

    def typecheck(self, tyenv):
        condty = self.cond.typecheck(tyenv)
        falsety = self.iffalse.typecheck(tyenv)
        truety = self.iftrue.typecheck(tyenv)

        if condty is None or falsety is None or truety is None:
            return None

        if condty != 'Ity_I1':
            l.debug("guard must be Ity_I1")
            return None

        if falsety != truety:
            l.debug("false condition must be same type as true condition")
            return None

        return falsety

class CCall(IRExpr):
    """
    A call to a pure (no side-effects) helper C function.
    """

    __slots__ = ['retty', 'cee', 'args']

    tag = 'Iex_CCall'

    def __init__(self, retty, cee, args):
        IRExpr.__init__(self)
        self.retty = retty
        self.cee = cee
        self.args = tuple(args)

    @property
    def ret_type(self):
        return self.retty

    @property
    def callee(self):
        return self.cee

    def __str__(self):
        return "%s(%s):%s" % (self.cee, ','.join(str(a) for a in self.args), self.retty)

    @property
    def child_expressions(self):
        expressions = sum((a.child_expressions for a in self.args), [ ])
        expressions.extend(self.args)
        return expressions

    @staticmethod
    def _from_c(c_expr):
        i = 0
        args = []
        while True:
            arg = c_expr.Iex.CCall.args[i]
            if arg == ffi.NULL:
                break
            args.append(IRExpr._from_c(arg))
            i += 1

        return CCall(ints_to_enums[c_expr.Iex.CCall.retty],
                     IRCallee._from_c(c_expr.Iex.CCall.cee),
                     tuple(args))

    @staticmethod
    def _to_c(expr):
        args = [IRExpr._to_c(arg) for arg in expr.args]
        return pvc.IRExpr_CCall(IRCallee._to_c(expr.cee),
                                enums_to_ints[expr.retty],
                                mkIRExprVec[len(args)](*args))

    def result_type(self, tyenv):
        return self.retty

_op_type_cache = {}

def op_type(op):
    try:
        return _op_type_cache[op]
    except KeyError:
        out_int = ffi.new('IRType *')
        unused = ffi.new('IRType *')
        pvc.typeOfPrimop(enums_to_ints[op], out_int, unused, unused, unused, unused)
        out = ints_to_enums[out_int[0]]
        _op_type_cache[op] = out
        return out

def op_arg_types(op):
    res_ty = ffi.new('IRType *')
    arg1_ty = ffi.new('IRType *')
    arg2_ty = ffi.new('IRType *')
    arg3_ty = ffi.new('IRType *')
    arg4_ty = ffi.new('IRType *')
    arg2_ty[0] = 0x1100
    arg3_ty[0] = 0x1100
    arg4_ty[0] = 0x1100

    pvc.typeOfPrimop(enums_to_ints[op], res_ty, arg1_ty, arg2_ty, arg3_ty, arg4_ty)
    if arg2_ty[0] == 0x1100:
        return (ints_to_enums[res_ty[0]],
                (ints_to_enums[arg1_ty[0]],))
    elif arg3_ty[0] == 0x1100:
        return (ints_to_enums[res_ty[0]],
                (ints_to_enums[arg1_ty[0]],
                 ints_to_enums[arg2_ty[0]],))
    elif arg4_ty[0] == 0x1100:
        return (ints_to_enums[res_ty[0]],
                (ints_to_enums[arg1_ty[0]],
                 ints_to_enums[arg2_ty[0]],
                 ints_to_enums[arg3_ty[0]],))
    else:
        return (ints_to_enums[res_ty[0]],
                (ints_to_enums[arg1_ty[0]],
                 ints_to_enums[arg2_ty[0]],
                 ints_to_enums[arg3_ty[0]],
                 ints_to_enums[arg4_ty[0]],))

from .const import IRConst
from .enums import IRCallee, IRRegArray, enums_to_ints, ints_to_enums, type_sizes
from .errors import PyVEXError
from . import ffi, pvc

tag_to_class = {
    enums_to_ints['Iex_Binder']: Binder,
    enums_to_ints['Iex_Get']: Get,
    enums_to_ints['Iex_GetI']: GetI,
    enums_to_ints['Iex_RdTmp']: RdTmp,
    enums_to_ints['Iex_Qop']: Qop,
    enums_to_ints['Iex_Triop']: Triop,
    enums_to_ints['Iex_Binop']: Binop,
    enums_to_ints['Iex_Unop']: Unop,
    enums_to_ints['Iex_Load']: Load,
    enums_to_ints['Iex_Const']: Const,
    enums_to_ints['Iex_ITE']: ITE,
    enums_to_ints['Iex_CCall']: CCall,
    enums_to_ints['Iex_BBPTR']: BBPTR,
    enums_to_ints['Iex_VECRET']: VECRET,
}

mkIRExprVec = [
    pvc.mkIRExprVec_0,
    pvc.mkIRExprVec_1,
    pvc.mkIRExprVec_2,
    pvc.mkIRExprVec_3,
    pvc.mkIRExprVec_4,
    pvc.mkIRExprVec_5,
    pvc.mkIRExprVec_6,
    pvc.mkIRExprVec_7,
    pvc.mkIRExprVec_8
]
