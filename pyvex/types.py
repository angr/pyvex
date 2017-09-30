from __future__ import print_function
import re

from .errors import PyVEXError

# IRConst hierarchy
class IRConst(object):

    __slots__ = ['value']

    type = None
    tag = None
    c_constructor = None

    @property
    def size(self):
        return get_type_size(self.type)

    @staticmethod
    def _from_c(c_const):
        if c_const[0] == ffi.NULL:
            return None

        tag = get_enum_from_int(c_const.tag)

        try:
            return tag_to_const_class(tag)._from_c(c_const)
        except KeyError:
            raise PyVEXError('Unknown/unsupported IRConstTag %s\n' % tag)
    _translate = _from_c

    @classmethod
    def _to_c(cls, const):
        # libvex throws an exception when constructing a U1 with a value other than 0 or 1
        if const.tag == 'Ico_U1' and not const.value in (0, 1):
            raise PyVEXError('Invalid U1 value: %d' % const.value)

        try:
            return cls.c_constructor(const.value)
        except KeyError:
            raise PyVEXError('Unknown/unsupported IRConstTag %s]n' % const.tag)

def vex_int_class(size):
    try:
        return class_cache[size]
    except KeyError:
        class VexInt(IRConst):
            type = 'Ity_I%d' % size
            tag = 'Ico_U%d' % size
            op_format = str(size)
            size = size

            def __init__(self, value):
                IRConst.__init__(self)
                self.value = value

            def __str__(self):
                return '(0x%x :: %s)' % (self.value, self.type)
        VexInt.__name__ = 'U%d' % size
        class_cache[size] = VexInt
        return VexInt

class TypeMeta(type):
    def __getattr__(self, name):
        match = re.match(r'U(\d+)$', name)
        if match:
            width = int(match.group(1))
            return vex_int_class(width)

class Type(object):
    __metaclass__ =

    U1 = U1
    U8 = U8
    U16 = U16
    U32 = U32
    U64 = U64
    F32 = F32
    F64 = F64
    V128 = V128
    V256 = V256
    pass

class U1(IRConst):
    type = 'Ity_I1'
    tag = 'Ico_U1'
    op_format = '1'
    c_constructor = pvc.IRConst_U1
    size = 1

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
    op_format = '8'
    c_constructor = pvc.IRConst_U8
    size = 8

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
    op_format = '16'
    c_constructor = pvc.IRConst_U16
    size = 16

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
    op_format = '32'
    c_constructor = pvc.IRConst_U32
    size = 32

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
    op_format = '64'
    c_constructor = pvc.IRConst_U64
    size = 64

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
    op_format = 'F32'
    c_constructor = pvc.IRConst_F32
    size = 32

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
    op_format = 'F32'
    c_constructor = pvc.IRConst_F32i
    size = 32

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
    op_format = 'F64'
    c_constructor = pvc.IRConst_F64
    size = 64

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
    op_format = 'F64'
    c_constructor = pvc.IRConst_F64i
    size = 64

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
    op_format = 'V128'
    c_constructor = pvc.IRConst_V128
    size = 128

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
    op_format = 'V256'
    c_constructor = pvc.IRConst_V256
    size = 256

    def __init__(self, value):
        IRConst.__init__(self)
        self.value = value

    def __str__(self):
        return "%x" % self.value

    @staticmethod
    def _from_c(c_const):
        return V256(c_const.Ico.V256)
