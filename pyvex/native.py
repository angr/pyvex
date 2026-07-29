import importlib.resources
import sys
from typing import Any

import cffi

from .vex_ffi import ffi_str as _ffi_str

ffi = cffi.FFI()


def _find_c_lib():
    # Load the c library for calling into VEX
    if sys.platform in ("win32", "cygwin"):
        library_file = "pyvex.dll"
    elif sys.platform == "darwin":
        library_file = "libpyvex.dylib"
    else:
        library_file = "libpyvex.so"

    pyvex_path = str(importlib.resources.files("pyvex") / "lib" / library_file)
    ffi.cdef(_ffi_str)
    # RTLD_GLOBAL used for sim_unicorn.so
    lib = ffi.dlopen(pyvex_path)

    if not lib.vex_init():
        raise ImportError("libvex failed to initialize")
    # this looks up all the definitions (wtf)
    dir(lib)
    return lib


pvc: Any = _find_c_lib()  # This should be properly typed, but this seems non trivial
