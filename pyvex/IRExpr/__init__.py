from .. import vex

# IRExpr heirarchy
class IRExpr(vex):
    @property
    def child_expressions(self):
        expressions = [ ]
        for k,v in self.__dict__.iteritems():
            if isinstance(v, IRExpr):
                expressions.append(v)
                expressions.extend(v.child_expressions)
        return expressions

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

class Triop(IRExpr):
    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))

class Binop(IRExpr):
    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))

class Unop(IRExpr):
    def __str__(self):
        return "%s(%s)" % (self.op[4:], ','.join(str(a) for a in self.args))

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
