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

    @property
    def expressions(self):
        expressions = [ ]
        for s in self.statements:
            expressions.extend(s.expressions)
        expressions.append(self.next)
        return expressions

    @property
    def operations(self):
        ops = [ ]
        for e in self.expressions:
            if hasattr(e, 'op'):
                ops.append(e.op)
        return ops

class IRTypeEnv(vex):
    def __str__(self):
        return ' '.join(("t%d:%s" % (i,t)) for i,t in enumerate(self.types))

class IRCallee(vex):
    def __str__(self):
        return self.name
class IRRegArray(vex):
    def __str__(self):
        return "%s:%sx%d" % (self.base, self.elemTy[4:], self.nElems)

from . import IRConst
from . import IRExpr
from . import IRStmt

# and initialize!
pyvex_c.init(sys.modules[__name__])
for i in dir(pyvex_c):
    if not i.startswith('enum'):
        continue
    setattr(sys.modules[__name__], i, getattr(pyvex_c, i))
typeOfIROp = pyvex_c.typeOfIROp
