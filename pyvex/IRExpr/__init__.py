from .. import VEXObject

# IRExpr heirarchy
class IRExpr(VEXObject):
    def __init__(self, c_expr, irsb):
        VEXObject.__init__(self)
        self.tag = ints_to_enums[c_expr.tag]
        #self.c_expr = c_expr
        self.arch = irsb.arch

        if isinstance(self, (VECRET, Binder, BBPTR)):
            self.result_type = 'Ity_INVALID'
        else:
            self.result_type = ints_to_enums[pvc.typeOfIRExpr(irsb.c_irsb.tyenv, c_expr)]
        self.result_size = type_sizes[self.result_type]

    def pp(self):
        print self.__str__()

    @property
    def child_expressions(self):
        '''
        A list of all of the expressions that this expression ends up evaluating.
        '''
        expressions = [ ]
        for _,v in self.__dict__.iteritems():
            if isinstance(v, IRExpr):
                expressions.append(v)
                expressions.extend(v.child_expressions)
        return expressions

    @property
    def constants(self):
        '''
        A list of all of the constants that this expression ends up using.
        '''
        constants = [ ]
        for _,v in self.__dict__.iteritems():
            if isinstance(v, IRExpr):
                constants.extend(v.constants)
            elif isinstance(v, IRConst):
                constants.append(v)
        return constants

    @staticmethod
    def _translate(c_expr, irsb):
        if c_expr == ffi.NULL or c_expr[0] == ffi.NULL:
            return None

        tag = c_expr.tag

        try:
            expr_class = tag_to_class[tag]
        except KeyError:
            raise PyVEXError('Unknown/unsupported IRExprTag %s\n' % ints_to_enums[tag])
        return expr_class(c_expr, irsb)

class Binder(IRExpr):
    def __init__(self, c_expr, irsb):
        IRExpr.__init__(self, c_expr, irsb)
        self.binder = c_expr.iex.Binder.binder

    def __str__(self):
        return "Binder"

class VECRET(IRExpr):
    def __init__(self, c_expr, irsb):
        IRExpr.__init__(self, c_expr, irsb)

    def __str__(self):
        return "VECRET"

class BBPTR(IRExpr):
    def __init__(self, c_expr, irsb):
        IRExpr.__init__(self, c_expr, irsb)
        self.result_type = 'Ity_INVALID'
        self.result_size = 0

    def __str__(self):
        return "BBPTR"

class GetI(IRExpr):
    def __init__(self, c_expr, irsb):
        IRExpr.__init__(self, c_expr, irsb)
        self.descr = IRRegArray(c_expr.Iex.GetI.descr)
        self.ix = IRExpr._translate(c_expr.Iex.GetI.ix, irsb)
        self.bias = c_expr.Iex.GetI.bias

    @property
    def description(self):
        return self.descr

    @property
    def index(self):
        return self.ix

    def __str__(self):
        return "GetI(%s)[%s,%s]" % (self.descr, self.ix, self.bias)

class RdTmp(IRExpr):
    def __init__(self, c_expr, irsb):
        IRExpr.__init__(self, c_expr, irsb)
        self.tmp = c_expr.Iex.RdTmp.tmp

    def __str__(self):
        return "t%d" % self.tmp

class Get(IRExpr):
    def __init__(self, c_expr, irsb):
        IRExpr.__init__(self, c_expr, irsb)
        self.offset = c_expr.Iex.Get.offset
        self.ty = ints_to_enums[c_expr.Iex.Get.ty]

    @property
    def type(self):
        return self.ty

    def __str__(self):
        return "GET:%s(%s)" % (self.ty[4:], self.arch.translate_register_name(self.offset))

class Qop(IRExpr):
    def __init__(self, c_expr, irsb):
        IRExpr.__init__(self, c_expr, irsb)
        self.op = ints_to_enums[c_expr.Iex.Qop.details.op]
        self.args = (
            IRExpr._translate(c_expr.Iex.Qop.details.arg1, irsb),
            IRExpr._translate(c_expr.Iex.Qop.details.arg2, irsb),
            IRExpr._translate(c_expr.Iex.Qop.details.arg3, irsb),
            IRExpr._translate(c_expr.Iex.Qop.details.arg4, irsb),
        )

    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))

    @property
    def child_expressions(self):
        expressions = sum((a.child_expressions for a in self.args), [ ])
        expressions.extend(self.args)
        return expressions

class Triop(IRExpr):
    def __init__(self, c_expr, irsb):
        IRExpr.__init__(self, c_expr, irsb)
        self.op = ints_to_enums[c_expr.Iex.Triop.details.op]
        self.args = (
            IRExpr._translate(c_expr.Iex.Triop.details.arg1, irsb),
            IRExpr._translate(c_expr.Iex.Triop.details.arg2, irsb),
            IRExpr._translate(c_expr.Iex.Triop.details.arg3, irsb),
        )

    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))

    @property
    def child_expressions(self):
        expressions = sum((a.child_expressions for a in self.args), [ ])
        expressions.extend(self.args)
        return expressions

class Binop(IRExpr):
    def __init__(self, c_expr, irsb):
        IRExpr.__init__(self, c_expr, irsb)
        self.op = ints_to_enums[c_expr.Iex.Binop.op]
        self.args = (
            IRExpr._translate(c_expr.Iex.Binop.arg1, irsb),
            IRExpr._translate(c_expr.Iex.Binop.arg2, irsb),
        )

    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))

    @property
    def child_expressions(self):
        expressions = sum((a.child_expressions for a in self.args), [ ])
        expressions.extend(self.args)
        return expressions

class Unop(IRExpr):
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

class Load(IRExpr):
    def __init__(self, c_expr, irsb):
        IRExpr.__init__(self, c_expr, irsb)
        self.end = ints_to_enums[c_expr.Iex.Load.end]
        self.ty = ints_to_enums[c_expr.Iex.Load.ty]
        self.addr = IRExpr._translate(c_expr.Iex.Load.addr, irsb)

    @property
    def endness(self):
        return self.end

    @property
    def type(self):
        return self.ty

    def __str__(self):
        return "LD%s:%s(%s)" % (self.end[-2:].lower(), self.ty[4:], self.addr)

class Const(IRExpr):
    def __init__(self, c_expr, irsb):
        IRExpr.__init__(self, c_expr, irsb)
        self.con = IRConst._translate(c_expr.Iex.Const.con)

    def __str__(self):
        return str(self.con)

class ITE(IRExpr):
    def __init__(self, c_expr, irsb):
        IRExpr.__init__(self, c_expr, irsb)
        self.cond = IRExpr._translate(c_expr.Iex.ITE.cond, irsb)
        self.iffalse = IRExpr._translate(c_expr.Iex.ITE.iffalse, irsb)
        self.iftrue = IRExpr._translate(c_expr.Iex.ITE.iftrue, irsb)

    def __str__(self):
        return "ITE(%s,%s,%s)" % (self.cond, self.iftrue, self.iffalse)

class CCall(IRExpr):
    def __init__(self, c_expr, irsb):
        IRExpr.__init__(self, c_expr, irsb)
        self.retty = ints_to_enums[c_expr.Iex.CCall.retty]
        self.cee = IRCallee(c_expr.Iex.CCall.cee)

        self.args = [ ]
        for i in range(20):
            a = c_expr.Iex.CCall.args[i]
            if a == ffi.NULL:
                break

            self.args.append(IRExpr._translate(a, irsb))
        self.args = tuple(self.args)

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

from ..IRConst import IRConst
from .. import IRCallee, IRRegArray, enums_to_ints, ints_to_enums, PyVEXError, ffi, pvc, type_sizes

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
