from .. import VEXObject

# IRConst heirarchy
class IRConst(VEXObject):
    def __init__(self):
        VEXObject.__init__(self)

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
    def __init__(self, c_expr):
        IRConst.__init__(self)
        self.value = c_expr.Ico.U1

    def __str__(self):
        return "%d" % self.value

class U8(IRConst):
    def __init__(self, c_expr):
        IRConst.__init__(self)
        self.value = c_expr.Ico.U8

    def __str__(self):
        return "0x%02x" % self.value

class U16(IRConst):
    def __init__(self, c_expr):
        IRConst.__init__(self)
        self.value = c_expr.Ico.U16

    def __str__(self):
        return "0x%04x" % self.value

class U32(IRConst):
    def __init__(self, c_expr):
        IRConst.__init__(self)
        self.value = c_expr.Ico.U32

    def __str__(self):
        return "0x%08x" % self.value

class U64(IRConst):
    def __init__(self, c_expr):
        IRConst.__init__(self)
        self.value = c_expr.Ico.U64

    def __str__(self):
        return "0x%016x" % self.value

class F32(IRConst):
    def __init__(self, c_expr):
        IRConst.__init__(self)
        self.value = c_expr.Ico.F32

    def __str__(self):
        return "%f" % self.value

class F32i(IRConst):
    def __init__(self, c_expr):
        IRConst.__init__(self)
        self.value = c_expr.Ico.F32i

    def __str__(self):
        return "%f" % self.value

class F64(IRConst):
    def __init__(self, c_expr):
        IRConst.__init__(self)
        self.value = c_expr.Ico.F64

    def __str__(self):
        return "%f" % self.value

class F64i(IRConst):
    def __init__(self, c_expr):
        IRConst.__init__(self)
        self.value = c_expr.Ico.F64i

    def __str__(self):
        return "%f" % self.value

class V128(IRConst):
    def __init__(self, c_expr):
        IRConst.__init__(self)
        self.value = c_expr.Ico.V128

    def __str__(self):
        return "%x" % self.value

class V256(IRConst):
    def __init__(self, c_expr):
        IRConst.__init__(self)
        self.value = c_expr.Ico.V256

    def __str__(self):
        return "%x" % self.value

from .. import ints_to_enums, enums_to_ints, PyVEXError, ffi

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
