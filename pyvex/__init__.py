"""
PyVEX provides an interface that translates binary code into the VEX intermediate represenation (IR).
For an introduction to VEX, take a look here: https://docs.angr.io/advanced-topics/ir
"""
from typing import NewType, Any

__version__ = (8, 20, 6, 1)

if bytes is str:
    raise Exception("This module is designed for python 3 only. Please install an older version to use python 2.")

import os
import sys
import cffi
import pkg_resources
from .vex_ffi import ffi_str as _ffi_str
ffi = cffi.FFI()

import logging
logging.getLogger("pyvex").addHandler(logging.NullHandler())


def _find_c_lib():
    # Load the c library for calling into VEX
    if sys.platform in ('win32', 'cygwin'):
        library_file = 'pyvex.dll'
    elif sys.platform == 'darwin':
        library_file = "libpyvex.dylib"
    else:
        library_file = "libpyvex.so"

    pyvex_path = pkg_resources.resource_filename(__name__, os.path.join('lib', library_file))

    ffi.cdef(_ffi_str)
    # RTLD_GLOBAL used for sim_unicorn.so
    lib = ffi.dlopen(pyvex_path)
    if not lib.vex_init():
        raise ImportError("libvex failed to initialize")
    # this looks up all the definitions (wtf)
    dir(lib)
    return lib

pvc = _find_c_lib() # type: Any # This should be properly typed, but this seems non trivial

# pylint: disable=wildcard-import
from .enums import *
from . import stmt, expr, const
from .block import IRSB, IRTypeEnv
from .expr import get_op_retty
from .const import tag_to_const_class, get_type_size, get_type_spec_size
from .lifting import lift, lifters
from .errors import PyVEXError

# aliases....
IRStmt = stmt
IRExpr = expr
IRConst = const
