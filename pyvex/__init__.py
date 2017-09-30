"""
PyVEX provides an interface that translates binary code into the VEX intermediate represenation (IR).
For an introduction to VEX, take a look here: https://docs.angr.io/docs/ir.html
"""

import logging
logging.getLogger("pyvex").addHandler(logging.NullHandler())

# pylint: disable=wildcard-import
from .enums import *
from . import stmt, expr, const
from .block import *
from .expr import get_op_retty
from .types import Type
from .jumpkinds import Jumpkind
from .endianness import Endian

# aliases....
IRStmt = stmt
IRExpr = expr
IRConst = const
