import archinfo
import pyvex
from pyvex.lift.util.vex_helper import IRSBCustomizer
from pyvex.lift.util import *
import nose

def create_irsb_c():
    irsb = pyvex.IRSB(None, 0, archinfo.ArchX86())
    return irsb, IRSBCustomizer(irsb)

def test_addition():
    irsb, irsb_c = create_irsb_c()
    a = VexValue.Constant(irsb_c, 1.0, Type.ieee_float_32)
    b = VexValue.Constant(irsb_c, 2.0, Type.ieee_float_32)
    c = a + b
    nose.tools.assert_equals(len(irsb.statements), 1)
    stmt = irsb.statements[0]
    nose.tools.assert_is_instance(stmt, pyvex.stmt.WrTmp)
    nose.tools.assert_is_instance(stmt.data, pyvex.expr.Triop)
    nose.tools.assert_equal(stmt.data.op, 'Iop_AddF32')
    children = stmt.data.child_expressions
    nose.tools.assert_equals(len(children), 3)
    nose.tools.assert_equals(children[0].con.value, 0)
    nose.tools.assert_equals(children[1].con.value, 1.0)
    nose.tools.assert_equals(children[2].con.value, 2.0)
    nose.tools.assert_is_instance(children[0].con, pyvex.const.U32)
    nose.tools.assert_is_instance(children[1].con, pyvex.const.F32)
    nose.tools.assert_is_instance(children[2].con, pyvex.const.F32)

def test_subtraction():
    irsb, irsb_c = create_irsb_c()
    a = VexValue.Constant(irsb_c, 1.0, Type.ieee_float_32)
    b = VexValue.Constant(irsb_c, 2.0, Type.ieee_float_32)
    c = b - a
    nose.tools.assert_equals(len(irsb.statements), 1)
    stmt = irsb.statements[0]
    nose.tools.assert_is_instance(stmt, pyvex.stmt.WrTmp)
    nose.tools.assert_is_instance(stmt.data, pyvex.expr.Triop)
    nose.tools.assert_equal(stmt.data.op, 'Iop_SubF32')
    children = stmt.data.child_expressions
    nose.tools.assert_equals(len(children), 3)
    nose.tools.assert_equals(children[0].con.value, 0)
    nose.tools.assert_equals(children[1].con.value, 2.0)
    nose.tools.assert_equals(children[2].con.value, 1.0)
    nose.tools.assert_is_instance(children[0].con, pyvex.const.U32)
    nose.tools.assert_is_instance(children[1].con, pyvex.const.F32)
    nose.tools.assert_is_instance(children[2].con, pyvex.const.F32)

def test_multiplication():
    irsb, irsb_c = create_irsb_c()
    a = VexValue.Constant(irsb_c, 1.0, Type.ieee_float_32)
    b = VexValue.Constant(irsb_c, 2.0, Type.ieee_float_32)
    c = a * b
    nose.tools.assert_equals(len(irsb.statements), 1)
    stmt = irsb.statements[0]
    nose.tools.assert_is_instance(stmt, pyvex.stmt.WrTmp)
    nose.tools.assert_is_instance(stmt.data, pyvex.expr.Triop)
    nose.tools.assert_equal(stmt.data.op, 'Iop_MulF32')
    children = stmt.data.child_expressions
    nose.tools.assert_equals(len(children), 3)
    nose.tools.assert_equals(children[0].con.value, 0)
    nose.tools.assert_equals(children[1].con.value, 1.0)
    nose.tools.assert_equals(children[2].con.value, 2.0)
    nose.tools.assert_is_instance(children[0].con, pyvex.const.U32)
    nose.tools.assert_is_instance(children[1].con, pyvex.const.F32)
    nose.tools.assert_is_instance(children[2].con, pyvex.const.F32)

def test_divide():
    irsb, irsb_c = create_irsb_c()
    a = VexValue.Constant(irsb_c, 1.0, Type.ieee_float_32)
    b = VexValue.Constant(irsb_c, 2.0, Type.ieee_float_32)
    c = a / b
    nose.tools.assert_equals(len(irsb.statements), 1)
    stmt = irsb.statements[0]
    nose.tools.assert_is_instance(stmt, pyvex.stmt.WrTmp)
    nose.tools.assert_is_instance(stmt.data, pyvex.expr.Triop)
    nose.tools.assert_equal(stmt.data.op, 'Iop_DivF32')
    children = stmt.data.child_expressions
    nose.tools.assert_equals(len(children), 3)
    nose.tools.assert_equals(children[0].con.value, 0)
    nose.tools.assert_equals(children[1].con.value, 1.0)
    nose.tools.assert_equals(children[2].con.value, 2.0)
    nose.tools.assert_is_instance(children[0].con, pyvex.const.U32)
    nose.tools.assert_is_instance(children[1].con, pyvex.const.F32)
    nose.tools.assert_is_instance(children[2].con, pyvex.const.F32)

def test_negate():
    irsb, irsb_c = create_irsb_c()
    a = VexValue.Constant(irsb_c, 1.0, Type.ieee_float_32)
    c = - a
    nose.tools.assert_equals(len(irsb.statements), 1)
    stmt = irsb.statements[0]
    nose.tools.assert_is_instance(stmt, pyvex.stmt.WrTmp)
    nose.tools.assert_is_instance(stmt.data, pyvex.expr.Unop)
    nose.tools.assert_equal(stmt.data.op, 'Iop_NegF32')
    children = stmt.data.child_expressions
    nose.tools.assert_equals(len(children), 1)
    nose.tools.assert_equals(children[0].con.value, 1.0)
    nose.tools.assert_is_instance(children[0].con, pyvex.const.F32)

def test_abs():
    irsb, irsb_c = create_irsb_c()
    a = VexValue.Constant(irsb_c, 1.0, Type.ieee_float_32)
    c = abs(a)
    nose.tools.assert_equals(len(irsb.statements), 1)
    stmt = irsb.statements[0]
    nose.tools.assert_is_instance(stmt, pyvex.stmt.WrTmp)
    nose.tools.assert_is_instance(stmt.data, pyvex.expr.Unop)
    nose.tools.assert_equal(stmt.data.op, 'Iop_AbsF32')
    children = stmt.data.child_expressions
    nose.tools.assert_equals(len(children), 1)
    nose.tools.assert_equals(children[0].con.value, 1.0)
    nose.tools.assert_is_instance(children[0].con, pyvex.const.F32)

def test_sqrt():
    irsb, irsb_c = create_irsb_c()
    a = VexValue.Constant(irsb_c, 1.0, Type.ieee_float_32)
    c = a.sqrt()
    nose.tools.assert_equals(len(irsb.statements), 1)
    stmt = irsb.statements[0]
    nose.tools.assert_is_instance(stmt, pyvex.stmt.WrTmp)
    nose.tools.assert_is_instance(stmt.data, pyvex.expr.Binop)
    nose.tools.assert_equal(stmt.data.op, 'Iop_SqrtF32')
    children = stmt.data.child_expressions
    nose.tools.assert_equals(len(children), 2)
    nose.tools.assert_equals(children[0].con.value, 0)
    nose.tools.assert_equals(children[1].con.value, 1.0)
    nose.tools.assert_is_instance(children[0].con, pyvex.const.U32)
    nose.tools.assert_is_instance(children[1].con, pyvex.const.F32)

def test_gt():
    irsb, irsb_c = create_irsb_c()
    a = VexValue.Constant(irsb_c, 1.0, Type.ieee_float_32)
    b = VexValue.Constant(irsb_c, 2.0, Type.ieee_float_32)
    c = b > a
    nose.tools.assert_equals(len(irsb.statements), 6)

def test_casting():
    irsb, irsb_c = create_irsb_c()
    a = VexValue.Constant(irsb_c, 1.0, Type.ieee_float_32)
    b = VexValue.Constant(irsb_c, 2.0, Type.ieee_float_32)
    c = a.round_zero + b.round_zero
    stmt = irsb.statements[0]
    children = stmt.data.child_expressions
    nose.tools.assert_equals(children[0].con.value, 3)

def test_casting_failure():
    irsb, irsb_c = create_irsb_c()
    a = VexValue.Constant(irsb_c, 1.0, Type.ieee_float_32)
    b = VexValue.Constant(irsb_c, 2.0, Type.ieee_float_32)
    def adder(x1, x2):
        a.round_zero + b.round_pos_inf
    nose.tools.assert_raises(ValueError, adder, a, b)

def test_default_rounding_mode():
    try:
        irsb, irsb_c = create_irsb_c()
        set_default_rounding_mode(RoundingMode.to_pos_inf)
        a = VexValue.Constant(irsb_c, 1.0, Type.ieee_float_32)
        b = VexValue.Constant(irsb_c, 2.0, Type.ieee_float_32)
        c = a + b
        stmt = irsb.statements[0]
        children = stmt.data.child_expressions
        nose.tools.assert_equals(children[0].con.value, RoundingMode.to_pos_inf)
    finally:
        set_default_rounding_mode(RoundingMode.to_nearest)

if __name__ == '__main__':
    allnames = globals().copy()
    for func_name, func in globals().copy().iteritems():
        if str(func_name).startswith('test_') and hasattr(func, '__call__'):
            func()
