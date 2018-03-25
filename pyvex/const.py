from __future__ import print_function
from past.builtins import xrange
import re

from . import VEXObject, ffi, pvc
from .enums import get_enum_from_int
from .errors import PyVEXError

# IRConst hierarchy
class IRConst(VEXObject):

    __slots__ = ['value']

    type = None
    tag = None
    c_constructor = None

    def pp(self):
        print(self.__str__())

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

class U1(IRConst):
    type = 'Ity_I1'
    tag = 'Ico_U1'
    op_format = '1'
    c_constructor = pvc.IRConst_U1

    def __init__(self, value):
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

    def __init__(self, value):
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

    def __init__(self, value):
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

    def __init__(self, value):
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

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "0x%016x" % self.value

    @staticmethod
    def _from_c(c_const):
        return U64(c_const.Ico.U64)

# Integer Type Imagination
class_cache = { 1 : U1, 8 : U8, 16 : U16, 32 : U32, 64 : U64 }

def vex_int_class(size):
    try:
        return class_cache[size]
    except KeyError:
        class VexInt(IRConst):
            type = 'Ity_I%d' % size
            tag = 'Ico_U%d' % size
            op_format = str(size)

            def __init__(self, value):
                IRConst.__init__(self)
                self.value = value

            def __str__(self):
                return '(0x%x :: %s)' % (self.value, self.type)
        VexInt.__name__ = 'U%d' % size
        class_cache[size] = VexInt
        return VexInt

class F32(IRConst):
    type = 'Ity_F32'
    tag = 'Ico_F32'
    op_format = 'F32'
    c_constructor = pvc.IRConst_F32

    def __init__(self, value):
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

    def __init__(self, value):
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

    def __init__(self, value):
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

    def __init__(self, value):
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

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "%x" % self.value

    # vex doesn't store a full 128 bit constant, instead it stores 1 bit per 8 bits of data
    # and duplicates each bit 8 times
    @staticmethod
    def _from_c(c_const):
        base_const = c_const.Ico.V128
        real_const = 0
        for i in xrange(16):
            if (base_const >> i) & 1 == 1:
                real_const |= 0xff << (8 * i)
        return V128(real_const)

class V256(IRConst):
    type = 'Ity_V256'
    tag = 'Ico_V256'
    op_format = 'V256'
    c_constructor = pvc.IRConst_V256

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "%x" % self.value

    # see above
    @staticmethod
    def _from_c(c_const):
        base_const = c_const.Ico.V256
        real_const = 0
        for i in xrange(32):
            if (base_const >> i) & 1 == 1:
                real_const |= 0xff << (8 * i)
        return V256(real_const)

predefined_types = [ U1, U8, U16, U32, U64, F32, F32i, F64, F64i, V128, V256 ]
predefined_types_map = { c.type : c for c in predefined_types }
predefined_classes_map = { c.tag : c for c in predefined_types }

# precompiled regexes
int_ty_re = re.compile(r'Ity_I\d+')
int_tag_re = re.compile(r'Ico_U\d+')
tag_size_re = re.compile(r'Ico_[UFV](?P<size>\d+)i?')


def is_int_ty(ty):
    m = int_ty_re.match(ty)
    return m is not None

def is_int_tag(tag):
    m = int_tag_re.match(tag)
    return m is not None

def get_tag_size(tag):
    m = tag_size_re.match(tag)
    if m is None:
        raise ValueError('Tag %s does not have size' % tag)
    return int(m.group('size'))


type_str_re = re.compile(r'Ity_[IFDV](?P<size>\d+)')
type_tag_str_re = re.compile(r'[IFDV]?(?P<size>\d+)[SU]?')

def get_type_size(ty):
    """
    Returns the size, in BITS, of a VEX type specifier
    e.g., Ity_I16 -> 16

    :param ty:
    :return:
    """
    m = type_str_re.match(ty)
    if m is None:
        raise ValueError('Type %s does not have size' % ty)
    return int(m.group('size'))


def get_type_spec_size(ty):
    """
    Get the width of a "type specifier"
    like I16U
    or F16
    or just 16
    (Yes, this really just takes the int out.  If we must special-case, do it here.
    :param tyspec:
    :return:
    """
    m = type_tag_str_re.match(ty)
    if m is None:
        raise ValueError('Type specifier %s does not have size' % ty)
    return int(m.group('size'))


def ty_to_const_class(ty):
    try:
        return predefined_types_map[ty]
    except KeyError:
        if is_int_ty(ty):
            size = get_type_size(ty)
            return vex_int_class(size)
        else:
            raise ValueError('Type %s does not exist' % ty)


def tag_to_const_class(tag):
    try:
        return predefined_classes_map[tag]
    except KeyError:
        if is_int_tag(tag):
            size = get_tag_size(tag)
            return vex_int_class(size)
        else:
            raise ValueError('Tag %s does not exist' % tag)
