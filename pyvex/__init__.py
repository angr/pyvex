"""
Python bindings for Valgrind's VEX IR.
"""
import os
import sys
import cffi

from .vex_ffi import ffi_str as _ffi_str
ffi = cffi.FFI()

def _find_c_lib():
    # Load the c library for calling into VEX
    if sys.platform == 'darwin':
        library_file = "pyvex_static.dylib"
    else:
        library_file = "pyvex_static.so"

    pyvex_paths = [os.path.join(os.path.dirname(__file__), '..', 'pyvex_c', library_file),
                    os.path.join(sys.prefix, 'lib', library_file)]

    sigh = os.path.abspath(__file__)
    prev_sigh = '$'
    while sigh != prev_sigh:
        prev_sigh = sigh
        sigh = os.path.dirname(sigh)
        pyvex_paths.append(os.path.join(sigh, 'lib', library_file))

    pyvex_path = None
    for path in pyvex_paths:
        if os.path.exists(path):
            pyvex_path = path
            break
    else:
        raise ImportError("unable to find pyvex_static.so")

    ffi.cdef(_ffi_str)
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

from .enums import *
from .block import *
from . import stmt, expr, const
