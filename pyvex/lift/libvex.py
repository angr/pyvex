import threading

from . import Lifter, register
from .. import pvc, ffi

_libvex_lock = threading.Lock()

SUPPORTED = {'X86', 'AMD64', 'MIPS32', 'MIPS64', 'ARM', 'ARMEL', 'ARMHF', 'AARCH64', 'PPC32', 'PPC64'}

class LibVEXLifter(Lifter):
    REQUIRE_DATA_C = True

    def lift(self):
        if self.irsb.arch.name not in SUPPORTED:
            return False

        try:
            _libvex_lock.acquire()
            self.irsb.arch.vex_archinfo['hwcache_info']['caches'] = ffi.NULL

            pvc.vta.traceflags = self.traceflags
            vex_arch = getattr(pvc, self.irsb.arch.vex_arch)

            if self.num_inst is not None:
                c_irsb = pvc.vex_block_inst(vex_arch, self.irsb.arch.vex_archinfo, self.data + self.bytes_offset, self.irsb._addr, self.num_inst)
            else:
                c_irsb = pvc.vex_block_bytes(vex_arch, self.irsb.arch.vex_archinfo, self.data + self.bytes_offset, self.irsb._addr, self.num_bytes, 1)


            if c_irsb == ffi.NULL:
                self._error = ffi.string(pvc.last_error) if pvc.last_error != ffi.NULL else "libvex: unknown error"
                return False

            self.irsb._from_c(c_irsb)
        finally:
            _libvex_lock.release()
            # We must use a pickle value, CData objects are not pickeable so not ffi.NULL
            self.irsb.arch.vex_archinfo['hwcache_info']['caches'] = None

        return True

register(LibVEXLifter)
