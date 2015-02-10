from .. import vex

# IRExpr heirarchy
class IRExpr(vex):
    @property
    def child_expressions(self):
        '''
        A list of all of the expressions that this expression ends up evaluating.
        '''
        expressions = [ ]
        for k,v in self.__dict__.iteritems():
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
        for k,v in self.__dict__.iteritems():
            if isinstance(v, IRExpr):
                constants.extend(v.constants)
            elif isinstance(v, IRConst):
                constants.append(v)
        return constants

class Binder(IRExpr):
    def __str__(self):
        return "Binder"

class VECRET(IRExpr):
    def __str__(self):
        return "VECRET"

class BBPTR(IRExpr):
    def __str__(self):
        return "BBPTR"

class GetI(IRExpr):
    def __str__(self):
        return "GETI(%s)[%s,%s]" % (self.descr, self.ix, self.bias)

class RdTmp(IRExpr):
    def __str__(self):
        return "t%d" % self.tmp

class Get(IRExpr):
    def __str__(self):
        return "GET:%s(%d)" % (self.ty[4:], self.offset)

class Qop(IRExpr):
    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))

    @property
    def child_expressions(self):
        expressions = sum((a.child_expressions for a in self.args), [ ])
        expressions.extend(self.args)
        return expressions

class Triop(IRExpr):
    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))

    @property
    def child_expressions(self):
        expressions = sum((a.child_expressions for a in self.args), [ ])
        expressions.extend(self.args)
        return expressions

class Binop(IRExpr):
    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))

    @property
    def child_expressions(self):
        expressions = sum((a.child_expressions for a in self.args), [ ])
        expressions.extend(self.args)
        return expressions

class Unop(IRExpr):
    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))

    @property
    def child_expressions(self):
        expressions = sum((a.child_expressions for a in self.args), [ ])
        expressions.extend(self.args)
        return expressions

class Load(IRExpr):
    def __str__(self):
        return "LD%s:%s(%s)" % (self.end[-2:].lower(), self.ty[4:], self.addr)

class Const(IRExpr):
    def __str__(self):
        return str(self.con)

class ITE(IRExpr):
    def __str__(self):
        return "ITE(%s,%s,%s)" % (self.cond, self.iftrue, self.iffalse)

class CCall(IRExpr):
    def __str__(self):
        return "%s(%s):%s" % (self.cee, ','.join(str(a) for a in self.args), self.retty)

    @property
    def child_expressions(self):
        expressions = sum((a.child_expressions for a in self.args), [ ])
        expressions.extend(self.args)
        return expressions

from ..IRConst import IRConst
