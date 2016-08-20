"""
Python bindings for Valgrind's VEX IR.
"""
import os
import sys
import cffi
import pkg_resources

from .vex_ffi import ffi_str as _ffi_str
ffi = cffi.FFI()

def _find_c_lib():
    # Load the c library for calling into VEX
    if sys.platform == 'darwin':
        library_file = "libpyvex.dylib"
    else:
        library_file = "libpyvex.so"

    pyvex_path = pkg_resources.resource_filename(__name__, os.path.join('lib', library_file))

    ffi.cdef(_ffi_str)
    # RTLD_GLOBAL used for sim_unicorn.so
    lib = ffi.dlopen(pyvex_path)
    lib.vex_init()
    # this looks up all the definitions (wtf)
    dir(lib)
    return lib

pvc = _find_c_lib()


def set_iropt_level(lvl):
    """
    Set the VEX optimization level to `lvl`. Valid values are 0, 1 and 2.

    0 performs no optimization, 1 performs basic optimizations, and 2 performs loop unrolling, among other things.
    """
    pvc.vex_control.iropt_level = lvl

def enable_debug(debug):
    """
    Set the debug flag to `debug`. Valid values are True. False, 0 and 1.

    False/0 disables debugging output, True/1 enables it.
    """

    if debug is True:
        debug = 1
    elif debug is False:
        debug = 0
    pvc.enable_debug(debug)

# pylint: disable=wildcard-import
from .enums import *
from .block import *
from . import stmt, expr, const

# aliases....
IRStmt = stmt
IRExpr = expr
IRConst = const
