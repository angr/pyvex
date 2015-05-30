from .. import VEXObject

# IRConst heirarchy
class IRConst(VEXObject):
    type = None

    def __init__(self, c_expr):
        VEXObject.__init__(self)
        self.tag = ints_to_enums[c_expr.tag]

    def pp(self):
        print self.__str__()

    @property
    def size(self):
        return type_sizes[self.type]

    @staticmethod
    def _translate(c_expr):
        if c_expr[0] == ffi.NULL:
            return None

        tag = c_expr.tag

        try:
            return tag_to_class[tag](c_expr)
        except KeyError:
            raise PyVEXError('Unknown/unsupported IRExprTag %s\n' % ints_to_enums[tag])

class U1(IRConst):
    type = 'Ity_I1'

    def __init__(self, c_expr):
        IRConst.__init__(self, c_expr)
        self.value = c_expr.Ico.U1

    def __str__(self):
        return "%d" % self.value

class U8(IRConst):
    type = 'Ity_I8'

    def __init__(self, c_expr):
        IRConst.__init__(self, c_expr)
        self.value = c_expr.Ico.U8

    def __str__(self):
        return "0x%02x" % self.value

class U16(IRConst):
    type = 'Ity_I16'

    def __init__(self, c_expr):
        IRConst.__init__(self, c_expr)
        self.value = c_expr.Ico.U16

    def __str__(self):
        return "0x%04x" % self.value

class U32(IRConst):
    type = 'Ity_I32'

    def __init__(self, c_expr):
        IRConst.__init__(self, c_expr)
        self.value = c_expr.Ico.U32

    def __str__(self):
        return "0x%08x" % self.value

class U64(IRConst):
    type = 'Ity_I64'

    def __init__(self, c_expr):
        IRConst.__init__(self, c_expr)
        self.value = c_expr.Ico.U64

    def __str__(self):
        return "0x%016x" % self.value

class F32(IRConst):
    type = 'Ity_F32'

    def __init__(self, c_expr):
        IRConst.__init__(self, c_expr)
        self.value = c_expr.Ico.F32

    def __str__(self):
        return "%f" % self.value

class F32i(IRConst):
    type = 'Ity_F32'

    def __init__(self, c_expr):
        IRConst.__init__(self, c_expr)
        self.value = c_expr.Ico.F32

    def __str__(self):
        return "%f" % self.value

class F64(IRConst):
    type = 'Ity_F64'

    def __init__(self, c_expr):
        IRConst.__init__(self, c_expr)
        self.value = c_expr.Ico.F64

    def __str__(self):
        return "%f" % self.value

class F64i(IRConst):
    type = 'Ity_F64'

    def __init__(self, c_expr):
        IRConst.__init__(self, c_expr)
        self.value = c_expr.Ico.F64

    def __str__(self):
        return "%f" % self.value

class V128(IRConst):
    type = 'Ity_V128'

    def __init__(self, c_expr):
        IRConst.__init__(self, c_expr)
        self.value = c_expr.Ico.V128

    def __str__(self):
        return "%x" % self.value

class V256(IRConst):
    type = 'Ity_V256'

    def __init__(self, c_expr):
        IRConst.__init__(self, c_expr)
        self.value = c_expr.Ico.V256

    def __str__(self):
        return "%x" % self.value

from .. import ints_to_enums, enums_to_ints, PyVEXError, ffi, type_sizes

tag_to_class = {
    enums_to_ints['Ico_U1']: U1,
    enums_to_ints['Ico_U8']: U8,
    enums_to_ints['Ico_U16']: U16,
    enums_to_ints['Ico_U32']: U32,
    enums_to_ints['Ico_U64']: U64,
    enums_to_ints['Ico_F32']: F32,
    enums_to_ints['Ico_F32i']: F32i,
    enums_to_ints['Ico_F64']: F64,
    enums_to_ints['Ico_F64i']: F64i,
    enums_to_ints['Ico_V128']: V128,
    enums_to_ints['Ico_V256']: V256,
}
