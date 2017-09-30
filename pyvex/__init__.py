"""
PyVEX provides an interface that translates binary code into the VEX intermediate represenation (IR).
For an introduction to VEX, take a look here: https://docs.angr.io/docs/ir.html
"""

from .vex_ffi import ffi_str as _ffi_str
ffi = cffi.FFI()

import logging
logging.getLogger("pyvex").addHandler(logging.NullHandler())

# pylint: disable=wildcard-import
from .enums import *
from . import stmt, expr, const
from .block import *
from .expr import get_op_retty
from .const import tag_to_const_class
from .lift import lift

# aliases....
IRStmt = stmt
IRExpr = expr
IRConst = const
