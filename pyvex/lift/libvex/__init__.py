import os
import sys
import cffi
import pkg_resources

from .vex_ffi import ffi_str as _ffi_str
ffi = cffi.FFI()

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
    lib.vex_init()
    # this looks up all the definitions (wtf)
    dir(lib)
    return lib

pvc = _find_c_lib()

from .libvex import LibVEXLifter
