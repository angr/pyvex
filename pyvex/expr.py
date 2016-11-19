from . import VEXObject

class IRExpr(VEXObject):
    """
    IR expressions in VEX represent operations without side effects.
    """

    __slots__ = ['tag']

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
        if isinstance(self, (VECRET, Binder, BBPTR)):
            return 'Ity_INVALID'
        else:
            return ints_to_enums[pvc.typeOfIRExpr(tyenv, c_expr)]

    @staticmethod
    def _translate(c_expr):
        if c_expr == ffi.NULL or c_expr[0] == ffi.NULL:
            return None

        tag_int = c_expr.tag

        try:
            return tag_to_class[tag_int].from_c(c_expr)
        except KeyError:
            raise PyVEXError('Unknown/unsupported IRExprTag %s\n' % ints_to_enums[tag_int])

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
    def from_c(c_expr):
        return Binder(c_expr.iex.Binder.binder)

class VECRET(IRExpr):

    tag = 'Iex_VECRET'
    
    def __init__(self):
        IRExpr.__init__(self, c_expr)

    def __str__(self):
        return "VECRET"

    @staticmethod
    def from_c(c_expr):
        return VECRET()

class BBPTR(IRExpr):

    tag = 'Iex_BBPTR'
    
    def __init__(self):
        IRExpr.__init__(self)

    def __str__(self):
        return "BBPTR"

    @staticmethod
    def from_c(c_expr):
        return BBPTR()

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
    def from_c(c_expr):
        descr = IRRegArray(c_expr.Iex.GetI.descr)
        ix = IRExpr._translate(c_expr.Iex.GetI.ix)
        bias = c_expr.Iex.GetI.bias
        return GetI(descr, ix, bias)

class RdTmp(IRExpr):
    """
    Read the value held by a temporary.
    """

    __slots__ = ['tmp']

    tag = 'Iex_RdTmp'

    def __init__(self, tmp):
        IRExpr.__init__(self, c_expr)
        self.tmp = tmp

    def __str__(self):
        return "t%d" % self.tmp

    @staticmethod
    def from_c(c_expr):
        return RdTmp(c_expr.Iex.RdTmp.tmp)

class Get(IRExpr):
    """
    Read a guest register, at a fixed offset in the guest state.
    """

    __slots__ = ['offset', 'ty']

    tag = 'Iex_Get'
    
    def __init__(self, offset, ty):
        IRExpr.__init__(self, c_expr)
        self.offset = offset
        self.ty = ty

    @property
    def type(self):
        return self.ty

    def __str__(self):
        return "GET:%s(%s)" % (self.ty[4:], self.arch.translate_register_name(self.offset, self.result_size/8))

    @staticmethod
    def from_c(c_expr):
        return Get(c_expr.Iex.Get.offset,
                   ints_to_enums[c_expr.Iex.Get.ty])

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
    def from_c(c_expr):
        return Qop(ints_to_enums[c_expr.Iex.Qop.details.op],
                   [IRExpr._translate(arg)
                    for arg in [c_expr.Iex.Qop.details.arg1,
                                c_expr.Iex.Qop.details.arg2,
                                c_expr.Iex.Qop.details.arg3,
                                c_expr.Iex.Qop.details.arg4]])

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
    def from_c(c_expr):
        return Triop(ints_to_enums[c_expr.Iex.Triop.details.op],
                     [IRExpr._translate(arg)
                      for arg in [c_expr.Iex.Triop.details.arg1,
                                  c_expr.Iex.Triop.details.arg2,
                                  c_expr.Iex.Triop.details.arg3]])

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
    def from_c(c_expr):
        return Binop(ints_to_enums[c_expr.Iex.Binop.details.op],
                     [IRExpr._translate(arg)
                      for arg in [c_expr.Iex.Binop.details.arg1,
                                  c_expr.Iex.Binop.details.arg2]])

class Unop(IRExpr):
    """
    A unary operation (1 argument).
    """

    __slots__ = ['op', 'args']

    tag = 'Iex_Unop'

    def __init__(self, op, args):
        self.op = op
        self.args = args
    
    def __init__(self, c_expr, irsb):
        IRExpr.__init__(self, c_expr, irsb)
        self.op = ints_to_enums[c_expr.Iex.Unop.op]
        self.args = (
            IRExpr._translate(c_expr.Iex.Unop.arg, irsb),
        )

    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))

    @property
    def child_expressions(self):
        expressions = sum((a.child_expressions for a in self.args), [ ])
        expressions.extend(self.args)
        return expressions

    @staticmethod
    def from_c(c_expr):
        return Unop(ints_to_enums[c_expr.Iex.Unop.details.op],
                    [IRExpr._translate(c_expr.Iex.Unop.details.arg)])

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
    def from_c(c_expr):
        return Load(ints_to_enums[c_expr.Iex.Load.end],
                    ints_to_enums[c_expr.Iex.Load.ty]
                    IRExpr._translate(c_expr.Iex.Load.addr))

class Const(IRExpr):
    """
    A constant expression.
    """

    __slots__ = ['con']

    tag = 'Iex_Const'

    def __init__(self, con):
        self.con = con
    
    def __str__(self):
        return str(self.con)

    @staticmethod
    def from_c(c_expr):
        return Const(IRConst._translate(c_expr.Iex.Const.con))
        
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
    def from_c(c_expr):
        return ITE(IRExpr._translate(c_expr.Iex.ITE.cond),
                   IRExpr._translate(c_expr.Iex.ITE.iffalse),
                   IRExpr._translate(c_expr.Iex.ITE.iftrue))

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
    def from_c(c_expr):
        return CCall(ints_to_enums[c_expr.Iex.CCall.retty],
                     IRCallee(c_expr.Iex.CCall.cee),
                     tuple([IRExpr._translate(arg)
                            for arg in itertools.takewhile(lambda a: a != ffi.NULL,
                                                           c_expr.Iex.CCall.args)]))

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
