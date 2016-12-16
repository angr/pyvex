from . import VEXObject

# IRConst hierarchy
class IRConst(VEXObject):

    __slots__ = ['value']

    type = None
    tag = None

    def __init__(self):
        VEXObject.__init__(self)

    def pp(self):
        print self.__str__()

    @property
    def size(self):
        return type_sizes[self.type]

    @staticmethod
    def _from_c(c_const):
        if c_const[0] == ffi.NULL:
            return None

        tag_int = c_const.tag

        try:
            return tag_to_class[tag_int]._from_c(c_const)
        except KeyError:
            raise PyVEXError('Unknown/unsupported IRConstTag %s\n' % ints_to_enums[tag_int])
    _translate = _from_c

    @staticmethod
    def _to_c(const):
        # libvex throws an exception when constructing a U1 with a value other than 0 or 1
        if const.tag == 'Ico_U1' and not const.value in (0, 1):
            raise PyVEXError('Invalid U1 value: %d' % const.value)

        try:
            return tag_to_ctor[const.tag](const.value)
        except KeyError:
            raise PyVEXError('Unknown/unsupported IRConstTag %s]n' % const.tag)


class U1(IRConst):
    type = 'Ity_I1'
    tag = 'Ico_U1'

    def __init__(self, value):
        IRConst.__init__(self)
        self.value = value

    def __str__(self):
        return "%d" % self.value

    @staticmethod
    def _from_c(c_const):
        return U1(c_const.Ico.U1)

class U8(IRConst):
    type = 'Ity_I8'
    tag = 'Ico_U8'

    def __init__(self, value):
        IRConst.__init__(self)
        self.value = value

    def __str__(self):
        return "0x%02x" % self.value

    @staticmethod
    def _from_c(c_const):
        return U8(c_const.Ico.U8)

class U16(IRConst):
    type = 'Ity_I16'
    tag = 'Ico_U16'

    def __init__(self, value):
        IRConst.__init__(self)
        self.value = value

    def __str__(self):
        return "0x%04x" % self.value

    @staticmethod
    def _from_c(c_const):
        return U16(c_const.Ico.U16)

class U32(IRConst):
    type = 'Ity_I32'
    tag = 'Ico_U32'

    def __init__(self, value):
        IRConst.__init__(self)
        self.value = value

    def __str__(self):
        return "0x%08x" % self.value

    @staticmethod
    def _from_c(c_const):
        return U32(c_const.Ico.U32)

class U64(IRConst):
    type = 'Ity_I64'
    tag = 'Ico_U64'

    def __init__(self, value):
        IRConst.__init__(self)
        self.value = value

    def __str__(self):
        return "0x%016x" % self.value

    @staticmethod
    def _from_c(c_const):
        return U64(c_const.Ico.U64)

class F32(IRConst):
    type = 'Ity_F32'
    tag = 'Ico_F32'

    def __init__(self, value):
        IRConst.__init__(self)
        self.value = value

    def __str__(self):
        return "%f" % self.value

    @staticmethod
    def _from_c(c_const):
        return F32(c_const.Ico.F32)

class F32i(IRConst):
    type = 'Ity_F32'
    tag = 'Ico_F32i'

    def __init__(self, value):
        IRConst.__init__(self)
        self.value = value

    def __str__(self):
        return "%f" % self.value

    @staticmethod
    def _from_c(c_const):
        return F32i(c_const.Ico.F32)

class F64(IRConst):
    type = 'Ity_F64'
    tag = 'Ico_F64'

    def __init__(self, value):
        IRConst.__init__(self)
        self.value = value

    def __str__(self):
        return "%f" % self.value

    @staticmethod
    def _from_c(c_const):
        return F64(c_const.Ico.F64)

class F64i(IRConst):
    type = 'Ity_F64'
    tag = 'Ico_F64i'

    def __init__(self, value):
        IRConst.__init__(self)
        self.value = value

    def __str__(self):
        return "%f" % self.value

    @staticmethod
    def _from_c(c_const):
        return F64i(c_const.Ico.F64)

class V128(IRConst):
    type = 'Ity_V128'
    tag = 'Ico_V128'

    def __init__(self, value):
        IRConst.__init__(self)
        self.value = value

    def __str__(self):
        return "%x" % self.value

    @staticmethod
    def _from_c(c_const):
        return V128(c_const.Ico.V128)

class V256(IRConst):
    type = 'Ity_V256'
    tag = 'Ico_V256'

    def __init__(self, value):
        IRConst.__init__(self)
        self.value = value

    def __str__(self):
        return "%x" % self.value

    @staticmethod
    def _from_c(c_const):
        return V256(c_const.Ico.V256)

from .enums import ints_to_enums, enums_to_ints, type_sizes
from .errors import PyVEXError
from . import ffi, pvc

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

tag_to_ctor = {
    'Ico_U1': pvc.IRConst_U1,
    'Ico_U8': pvc.IRConst_U8,
    'Ico_U16': pvc.IRConst_U16,
    'Ico_U32': pvc.IRConst_U32,
    'Ico_U64': pvc.IRConst_U64,
    'Ico_F32': pvc.IRConst_F32,
    'Ico_F32i': pvc.IRConst_F32i,
    'Ico_F64': pvc.IRConst_F64,
    'Ico_F64i': pvc.IRConst_F64i,
    'Ico_V128': pvc.IRConst_V128,
    'Ico_V256': pvc.IRConst_V256,
}
