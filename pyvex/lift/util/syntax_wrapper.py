import functools

from .vex_helper import IRSBCustomizer, Type, JumpKind, RoundingMode
import pyvex
from pyvex.expr import IRExpr, Const, RdTmp, Unop, Binop, Triop, Qop, Load, CCall, Get
from pyvex.const import is_int_ty, is_float_ty, is_decimal_float_ty, is_simd_ty

def checkparams(rhstype=None):
    def decorator(fn):
        @functools.wraps(fn)
        def inner_decorator(self, *args, **kwargs):
            irsb_cs = {a.irsb_c for a in list(args) if isinstance(a, VexValue)}  # pylint: disable=no-member
            irsb_cs.add(self.irsb_c)
            assert len(irsb_cs) == 1, 'All VexValues must belong to the same irsb_c'
            args = list(args)
            for arg in args:
                if isinstance(arg, int) or isinstance(arg, float):
                    thetype = rhstype if rhstype else self.ty
                    args[args.index(arg)] = VexValue.Constant(self.irsb_c, arg, thetype)
                elif not isinstance(arg, VexValue):
                    raise Exception('Cannot convert param %s' % str(arg))
            args = tuple(args)
            return fn(self, *args, **kwargs)
        return inner_decorator
    return decorator

def vvifyresults(f):
    @functools.wraps(f)
    def decor(self, *args, **kwargs):
        returned = f(self, *args, **kwargs)
        if not isinstance(returned, VexValue):
            returned = VexValue(self.irsb_c, returned)
        return returned
    return decor

DEFAULT_ROUNDING_MODE = RoundingMode.to_nearest

def set_default_rounding_mode(new_rounding_mode):
    global DEFAULT_ROUNDING_MODE
    DEFAULT_ROUNDING_MODE = new_rounding_mode

methods_to_foward = [
        '__add__',
        '__radd__',
        '__rsub__',
        '__rmul__',
        '__rdiv__',
        '__rfloordiv__',
        '__truediv__',
        '__rtruediv__',
        '__ror__',
        '__rxor__',
        '__rand__',
        '__rmod__',
        '__rlshift__',
        '__rrshift__',
        '__floordiv__',
        '__sub__',
        '__mul__',
        '__div__',
        '__neg__',
        '__abs__',
        '__gt__',
        '__lt__',
        '__eq__',
        '__getitem__',
        '__setitem__',
        '__and__',
        '__ne__',
        '__invert__',
        '__le__',
        '__ge__',
        '__lshift__',
        '__mod__',
        '__or__',
        '__pos__',
        '__rshift__',
        '__xor__'
]

class VexValue(object):
    def __init__(self, irsb_c, rdt, **kwargs):
        ty = irsb_c.get_type(rdt)
        if is_int_ty(ty):
            self.wrapped = VexValueInt(irsb_c, rdt, **kwargs)
        elif is_float_ty(ty):
            self.wrapped = VexValueFloat(irsb_c, rdt, **kwargs)
        elif is_decimal_float_ty(ty):
            raise NotImplementedError('VexValue does not currently support decimal floats')
        elif is_simd_ty(ty):
            raise NotImplementedError('VexValue does not currently support simd vectors')
        else:
            raise ValueError('Unknown type %s' % ty)

    @classmethod
    def Constant(cls, irsb_c, val, ty):
        """
        Creates a constant as a VexValue
        :param irsb_c: The IRSBCustomizer to use
        :param val: The value, as an integer
        :param ty: The type of the resulting VexValue
        :return: a VexValue
        """
        assert not (isinstance(val, VexValue) or isinstance(val, IRExpr))
        rdt = irsb_c.mkconst(val, ty)
        return cls(irsb_c, rdt)

    def __getattr__(self, name):
        return getattr(self.wrapped, name)

def _create_forwarder_method(methodname):
    def forward(self, *args, **kwargs):
        return getattr(self.wrapped, methodname)(*args, **kwargs)
    return forward

for methodname in methods_to_foward:
    method = _create_forwarder_method(methodname)
    setattr(VexValue, methodname, method)

class VexValueAny(object):
    @property
    def ty(self):
        return self.irsb_c.get_type(self.rdt)

    @property
    def width(self):
        return pyvex.get_type_size(self.ty)

    @property
    def value(self):
        if isinstance(self.rdt, Const):
            return self.rdt.con.value
        else:
            raise ValueError("Non-constant VexValue has no value property")

    @checkparams()
    @vvifyresults
    def __radd__(self, left):
        return self + left

    @checkparams()
    @vvifyresults
    def __rsub__(self, left):
        return left - self

    @checkparams()
    @vvifyresults
    def __rmul__(self, left):
        return left * self

    @checkparams()
    @vvifyresults
    def __rdiv__(self, left):
        return left / self

    @checkparams()
    @vvifyresults
    def __rfloordiv__(self, left):
        return left // self

    @checkparams()
    @vvifyresults
    def __truediv__(self, right):
        return self / right

    @checkparams()
    @vvifyresults
    def __rtruediv__(self, left):
        return left.__truediv__(self)

    @checkparams()
    @vvifyresults
    def __ror__(self, left):
        return self | left

    @checkparams()
    @vvifyresults
    def __rxor__(self, left):
        return self ^ left

    @checkparams()
    @vvifyresults
    def __rand__(self, left):
        return left & self

    @checkparams()
    @vvifyresults
    def __rmod__(self, left):
        return left % self

    @checkparams()
    @vvifyresults
    def __rlshift__(self, left):
        return left << self

    @checkparams()
    @vvifyresults
    def __rrshift__(self, left):
        return left >> self

    @checkparams()
    @vvifyresults
    def __floordiv__(self, right):
        return self / right

class VexValueFloat(VexValueAny):
    def __init__(self, irsb_c, rdt, **kwargs):
        self.irsb_c = irsb_c
        self.rdt = rdt

        try:
            self.rounding_mode = kwargs['rounding_mode']
            if isinstance(self.rounding_mode, Const):
                self.rounding_mode = self.rounding_mode.con.value
        except KeyError:
            self.rounding_mode = DEFAULT_ROUNDING_MODE
        self.rounding_mode_vv = self.rounding_num_to_vex_const(self.rounding_mode)

    def rounding_num_to_vex_const(self, rounding_num):
        return VexValue.Constant(self.irsb_c, rounding_num, Type.int_32)

    @property
    def ty(self):
        return self.irsb_c.get_type(self.rdt)

    @property
    def width(self):
        return pyvex.get_type_size(self.ty)

    @property
    def value():
        pass

    @property
    def round_nearest(self):
        rounding_mode = self.rounding_num_to_vex_const(RoundingMode.to_nearest)
        return VexValue(self.irsb_c, self.rdt, rounding_mode=rounding_mode.rdt)

    @property
    def round_neg_inf(self):
        rounding_mode = self.rounding_num_to_vex_const(RoundingMode.to_neg_inf)
        return VexValue(self.irsb_c, self.rdt, rounding_mode=rounding_mode.rdt)

    @property
    def round_pos_inf(self):
        rounding_mode = self.rounding_num_to_vex_const(RoundingMode.to_pos_inf)
        return VexValue(self.irsb_c, self.rdt, rounding_mode=rounding_mode.rdt)

    @property
    def round_zero(self):
        rounding_mode = self.rounding_num_to_vex_const(RoundingMode.to_zero)
        return VexValue(self.irsb_c, self.rdt, rounding_mode=rounding_mode.rdt)

    @checkparams()
    @vvifyresults
    def __add__(self, right):
        if self.rounding_mode != right.rounding_mode:
            raise ValueError('Cannot add VexValues with different rounding modes')
        return self.irsb_c.op_f_add(self.rounding_mode_vv.rdt, self.rdt, right.rdt)

    @checkparams()
    @vvifyresults
    def __sub__(self, right):
        if self.rounding_mode != right.rounding_mode:
            raise ValueError('Cannot subtract VexValues with different rounding modes')
        return self.irsb_c.op_f_sub(self.rounding_mode_vv.rdt, self.rdt, right.rdt)

    @checkparams()
    @vvifyresults
    def __mul__(self, right):
        if self.rounding_mode != right.rounding_mode:
            raise ValueError('Cannot multiply VexValues with different rounding modes')
        return self.irsb_c.op_f_mul(self.rounding_mode_vv.rdt, self.rdt, right.rdt)

    @checkparams()
    @vvifyresults
    def __div__(self, right):
        if self.rounding_mode != right.rounding_mode:
            raise ValueError('Cannot divide VexValues with different rounding modes')
        return self.irsb_c.op_f_div(self.rounding_mode_vv.rdt, self.rdt, right.rdt)

    @checkparams()
    @vvifyresults
    def __neg__(self):
        return self.irsb_c.op_neg(self.rdt)

    @checkparams()
    @vvifyresults
    def __abs__(self):
        return self.irsb_c.op_abs(self.rdt)

    @checkparams()
    @vvifyresults
    def cast_to(self, ty):
        return self.irsb_c.cast_to(self.rdt, ty, rounding_mode=self.rounding_mode.rdt)

    @checkparams()
    @vvifyresults
    def cmp(self, right):
        return self.irsb_c.op_cmp(self.rdt, right.rdt)

    @checkparams()
    @vvifyresults
    def __gt__(self, right): # The strange cmp result constants are Intel's encoding which VEX uses
        return (~(self.cmp(right) == 0x00))[0]

    @checkparams()
    @vvifyresults
    def __lt__(self, right):
        return (~(self.cmp(right) == 0x01))[0]

    @checkparams()
    @vvifyresults
    def __eq__(self, right):
        return (~(self.cmp(right) == 0x40))[0]

    @checkparams()
    @vvifyresults
    def unordered(self, right):
        return (~(self.cmp(right) == 0x45))[0]

    @checkparams()
    @vvifyresults
    def sqrt(self):
        return self.irsb_c.op_sqrt(self.rounding_mode_vv.rdt, self.rdt)

class VexValueInt(VexValueAny):
    def __init__(self, irsb_c, rdt, signed=False):
        self.irsb_c = irsb_c
        self.rdt = rdt
        self._is_signed = signed

    @property
    def unsigned(self):
        return VexValue(self.irsb_c, self.rdt, False)

    @property
    def signed(self):
        return VexValue(self.irsb_c, self.rdt, True)

    @vvifyresults
    def widen_unsigned(self, ty):
        return self.irsb_c.op_widen_int_unsigned(self.rdt, ty)

    @vvifyresults
    def cast_to(self, ty, signed=False, high=False):
        return self.irsb_c.cast_to(self.rdt, ty, signed=signed, high=high)

    @vvifyresults
    def widen_signed(self, ty):
        return self.irsb_c.op_widen_int_signed(self.rdt, ty)

    @vvifyresults
    def narrow_high(self, ty):
        return self.irsb_c.op_narrow_int(self.rdt, ty, high_half=True)

    @vvifyresults
    def narrow_low(self, ty):
        return self.irsb_c.op_narrow_int(self.rdt, ty, high_half=False)

    # TODO at some point extend this to Vex nonconstants
    def __getitem__(self, idx):
        getb = lambda i: VexValue(self.irsb_c, self.irsb_c.get_bit(self.rdt, i))
        makeconstant = lambda x: VexValue.Constant(self.irsb_c, x, Type.int_8).rdt
        if not isinstance(idx, slice):
            actualindex = slice(idx).indices(self.width)[1]
            return getb(makeconstant(actualindex))
        else:
            return [getb(makeconstant(i)) for i in range(*idx.indices(self.width))]

    def __setitem__(self, idx, bval):
        setted = self.set_bit(idx, bval)
        self.__init__(setted.irsb_c, setted.rdt)

    @checkparams()
    @vvifyresults
    def set_bit(self, idx, bval):
        typedidx = idx.cast_to(Type.int_8)
        return self.irsb_c.set_bit(self.rdt, idx.rdt, bval.rdt)

    @checkparams()
    @vvifyresults
    def set_bits(self, idxsandvals):
        return self.irsb_c.set_bits(self.rdt, [(i.cast_to(Type.int_8).rdt, b.rdt) for i, b in idxsandvals])

    @checkparams()
    @vvifyresults
    def ite(self, iftrue, iffalse):
        onebitcond = self.cast_to(Type.int_1)
        return self.irsb_c.ite(onebitcond.rdt, iftrue.rdt, iffalse.rdt)

    @checkparams()
    @vvifyresults
    def __add__(self, right):
        return self.irsb_c.op_add(self.rdt, right.rdt)

    @checkparams()
    @vvifyresults
    def __sub__(self, right):
        return self.irsb_c.op_sub(self.rdt, right.rdt)

    @checkparams()
    @vvifyresults
    def __div__(self, right):
        if self._is_signed:
            return self.irsb_c.op_sdiv(self.rdt, right.rdt)
        else:
            return self.irsb_c.op_udiv(self.rdt, right.rdt)

    @checkparams()
    @vvifyresults
    def __and__(self, right):
        return self.irsb_c.op_and(self.rdt, right.rdt)

    @checkparams()
    @vvifyresults
    def __eq__(self, right):
        return self.irsb_c.op_cmp_eq(self.rdt, right.rdt)

    @checkparams()
    @vvifyresults
    def __ne__(self, other):
        return self.irsb_c.op_cmp_ne(self.rdt, other.rdt)

    @checkparams()
    @vvifyresults
    def __invert__(self):
        return self.irsb_c.op_not(self.rdt)

    @checkparams()
    @vvifyresults
    def __le__(self, right):
        if self._is_signed:
            return self.irsb_c.op_cmp_sle(self.rdt, right.rdt)
        else:
            return self.irsb_c.op_cmp_ule(self.rdt, right.rdt)

    @checkparams()
    @vvifyresults
    def __gt__(self, other):
        if self._is_signed:
            return self.irsb_c.op_cmp_sgt(self.rdt, other.rdt)
        else:
            return self.irsb_c.op_cmp_ugt(self.rdt, other.rdt)

    @checkparams()
    @vvifyresults
    def __ge__(self, right):
        if self._is_signed:
            return self.irsb_c.op_cmp_sge(self.rdt, right.rdt)
        else:
            return self.irsb_c.op_cmp_uge(self.rdt, right.rdt)

    @checkparams(rhstype=Type.int_8)
    @vvifyresults
    def __lshift__(self, right):
        return self.irsb_c.op_shl(self.rdt, right.rdt)

    @checkparams()
    @vvifyresults
    def __lt__(self, right):
        if self._is_signed:
            return self.irsb_c.op_cmp_slt(self.rdt, right.rdt)
        else:
            return self.irsb_c.op_cmp_ult(self.rdt, right.rdt)

    @checkparams()
    @vvifyresults
    def __mod__(self, right):
        return self.irsb_c.op_mod(self.rdt, right.rdt)

    @checkparams()
    @vvifyresults
    def __mul__(self, right):
        if is_float_ty(self.ty) and is_float_ty(right.ty):
            if self.rounding_mode != right.rounding_mode:
                raise ValueError('Cannot multiply floats with different rounding modes')
            return self.irsb_c.op_umul(self.rdt, right.rdt, rounding_mode=self.rounding_mode)
        else:
            if self._is_signed:
                return self.irsb_c.op_smul(self.rdt, right.rdt)
            else:
                return self.irsb_c.op_umul(self.rdt, right.rdt)

    @checkparams()
    @vvifyresults
    def __neg__(self):
        if not self._is_signed:
            raise Exception('Number is unsigned, cannot change sign!')
        else:
            return self.rdt * -1

    @checkparams()
    @vvifyresults
    def __or__(self, right):
        return self.irsb_c.op_or(self.rdt, right.rdt)

    @checkparams()
    @vvifyresults
    def __pos__(self):
        return self

    @checkparams(rhstype=Type.int_8)
    @vvifyresults
    def __rshift__(self, right):
        return self.irsb_c.op_shr(self.rdt, right.rdt)

    @checkparams()
    @vvifyresults
    def __xor__ (self, right):
        return self.irsb_c.op_xor(self.rdt, right.rdt)
