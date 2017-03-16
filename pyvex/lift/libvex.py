import threading
import logging
l = logging.getLogger('pyvex.lift.libvex')
l.setLevel(20) # Shut up

from . import Lifter, register
from .. import pvc, ffi

_libvex_lock = threading.Lock()

SUPPORTED = {'X86', 'AMD64', 'MIPS32', 'MIPS64', 'ARM', 'ARMEL', 'ARMHF', 'AARCH64', 'PPC32', 'PPC64'}

class LibVEXLifter(Lifter):
    REQUIRE_DATA_C = True

    def lift(self):
        if self.irsb.arch.name not in SUPPORTED:
            return False

        if self.traceflags != 0 and l.getEffectiveLevel() > 20:
            l.setLevel(20)

        try:
            _libvex_lock.acquire()
            self.irsb.arch.vex_archinfo['hwcache_info']['caches'] = ffi.NULL

            pvc.log_level = l.getEffectiveLevel()
            vex_arch = getattr(pvc, self.irsb.arch.vex_arch)

            if self.max_inst is None: self.max_inst = 99
            if self.max_bytes is None: self.max_bytes = 5000
            c_irsb = pvc.vex_lift(vex_arch, self.irsb.arch.vex_archinfo, self.data + self.bytes_offset, self.irsb._addr, self.max_inst, self.max_bytes, self.opt_level, self.traceflags, self.allow_lookback)

            log_str = str(ffi.buffer(pvc.msg_buffer, pvc.msg_current_size)) if pvc.msg_buffer != ffi.NULL else None

            if c_irsb == ffi.NULL:
                self._error = "libvex: unkown error" if log_str is None else log_str
                return False
            else:
                if log_str is not None:
                    l.info(log_str)

            self.irsb._from_c(c_irsb)
        finally:
            _libvex_lock.release()
            # We must use a pickle value, CData objects are not pickeable so not ffi.NULL
            self.irsb.arch.vex_archinfo['hwcache_info']['caches'] = None

        return True

register(LibVEXLifter)
