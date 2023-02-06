from typing import Optional

from pyvex.block import IRSB
from pyvex.expr import Binop, Const, Get, Qop, RdTmp, Triop, Unop
from pyvex.stmt import IMark, NoOp, Put, Store, WrTmp

from .vex_helper import IRSBCustomizer


def _flatten_and_get_expr(irsb_old, irsb_c, old_to_new_tmp, expr):
    if isinstance(expr, Const):
        return expr
    elif isinstance(expr, RdTmp):
        return RdTmp.get_instance(old_to_new_tmp[expr.tmp])
    elif isinstance(expr, Get):
        return RdTmp.get_instance(irsb_c.mktmp(expr))
    else:
        assert expr.__class__ in [
            Unop,
            Binop,
            Triop,
            Qop,
        ], f"Flattening expressions of type {expr.__class__} is not supported yet."
        expr_args = [_flatten_and_get_expr(irsb_old, irsb_c, old_to_new_tmp, expr_arg) for expr_arg in expr.args]
        return RdTmp.get_instance(irsb_c.mktmp(expr.__class__(expr.op, expr_args)))


def irsb_postproc_flatten(irsb_old: IRSB, irsb_new: Optional[IRSB] = None) -> IRSB:
    """

    :param irsb_old: The IRSB to be flattened
    :param irsb_new: the IRSB to rewrite the instructions of irsb_old to. If it is None a new empty IRSB will be created
    :return: the flattened IRSB
    """
    irsb_new = irsb_new if irsb_new is not None else IRSB(None, irsb_old.addr, irsb_old.arch)
    irsb_c = IRSBCustomizer(irsb_new)
    old_to_new_tmp = {}

    for i, statement in enumerate(irsb_old.statements):
        if isinstance(statement, WrTmp):
            flat_expr = _flatten_and_get_expr(irsb_old, irsb_c, old_to_new_tmp, statement.data)
            if isinstance(flat_expr, RdTmp):
                tmp_new = flat_expr.tmp
            else:
                tmp_new = irsb_c.mktmp(flat_expr)
            old_to_new_tmp[statement.tmp] = tmp_new  # register our new tmp mapping

        elif isinstance(statement, Put):
            flat_expr = _flatten_and_get_expr(irsb_old, irsb_c, old_to_new_tmp, statement.data)
            irsb_c.put(flat_expr, statement.offset)

        elif isinstance(statement, Store):
            flat_expr = _flatten_and_get_expr(irsb_old, irsb_c, old_to_new_tmp, statement.data)
            irsb_c.store(statement.addr, flat_expr, statement.end)

        elif isinstance(statement, IMark):
            irsb_c.imark(statement.addr, statement.len, statement.delta)

        elif isinstance(statement, NoOp):
            irsb_c.noop()

    irsb_new.next = irsb_old.next
    irsb_new.jumpkind = irsb_old.jumpkind

    assert irsb_new == irsb_c.irsb
    assert irsb_new.typecheck()
    return irsb_new
