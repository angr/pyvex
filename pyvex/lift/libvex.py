import threading
import logging
l = logging.getLogger('pyvex.lift.libvex')
l.setLevel(20) # Shut up

from .. import stmt
from . import Lifter, register, LiftingException
from .. import pvc, ffi

_libvex_lock = threading.Lock()

SUPPORTED = {'X86', 'AMD64', 'MIPS32', 'MIPS64', 'ARM', 'ARMEL', 'ARMHF', 'AARCH64', 'PPC32', 'PPC64'}

VEX_MAX_INSTRUCTIONS = 99
VEX_MAX_BYTES = 400

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

            if self.bytes_offset is None: self.bytes_offset = 0
            c_irsb = pvc.vex_lift(vex_arch, self.irsb.arch.vex_archinfo, self.data + self.bytes_offset, self.irsb._addr, VEX_MAX_INSTRUCTIONS, VEX_MAX_BYTES, self.opt_level, self.traceflags, self.allow_lookback)

            log_str = str(ffi.buffer(pvc.msg_buffer, pvc.msg_current_size)) if pvc.msg_buffer != ffi.NULL else None

            if c_irsb == ffi.NULL:
                raise LiftingException("libvex: unkown error" if log_str is None else log_str)
            else:
                if log_str is not None:
                    l.info(log_str)

            self.irsb._from_c(c_irsb)
            last_statement = self.irsb.statements[-1]
            if isinstance(last_statement, stmt.IMark) and last_statement.len == 0:
                self.irsb.statements = self.irsb.statements[:-1]
            if self.irsb.size == 0:
                raise LiftingException("libvex: could not decode any instructions")
        finally:
            _libvex_lock.release()
            # We must use a pickle value, CData objects are not pickeable so not ffi.NULL
            self.irsb.arch.vex_archinfo['hwcache_info']['caches'] = None

register(LibVEXLifter)
