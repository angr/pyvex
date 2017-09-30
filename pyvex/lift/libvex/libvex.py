import threading
import logging
l = logging.getLogger('pyvex.lift.libvex')
l.setLevel(20) # Shut up

from .. import stmt
from .. import Lifter, register, LiftingException
from .. import pvc, ffi
import archinfo

_libvex_lock = threading.Lock()

import IPython; IPython.embed()
SUPPORTED = [archinfo.ArchX86,
             archinfo.ArchAMD64,
             archinfo.ArchMIPS32,
             archinfo.ArchMIPS64,
             archinfo.ArchARM,
             archinfo.ArchARMEL,
             archinfo.ArchARMHF,
             archinfo.ArchAMD64,
             archinfo.ArchPPC32,
             archinfo.ArchPPC64]

VEX_MAX_INSTRUCTIONS = 99
VEX_MAX_BYTES = 400

class LibVEXLifter(Lifter):
    REQUIRE_DATA_C = True

    def lift(self):
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
            for i in range(len(self.irsb.statements))[::-1]:
                s = self.irsb.statements[i]
                if isinstance(s, stmt.IMark) and s.len == 0:
                    self.irsb.statements = self.irsb.statements[:i]
                    break
            if self.irsb.size == 0:
                raise LiftingException("libvex: could not decode any instructions")
        finally:
            _libvex_lock.release()
            # We must use a pickle value, CData objects are not pickeable so not ffi.NULL
            self.irsb.arch.vex_archinfo['hwcache_info']['caches'] = None

for a in SUPPORTED:
    register(LibVEXLifter, a)
