import threading
import logging
l = logging.getLogger('pyvex.lift.libvex')
l.setLevel(20) # Shut up

from .. import stmt
from . import Lifter, register, LiftingException
from .. import pvc, ffi
from ..enums import default_vex_archinfo, vex_endness_from_string
import archinfo

_libvex_lock = threading.Lock()

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

    def _construct_c_arch(self):
        c_arch = default_vex_archinfo()
        if self.arch.endness == 'Iend_BE':
            c_arch['endness'] = vex_endness_from_string('VexEndnessBE')
        if isinstance(self.arch, archinfo.ArchX86):
            c_arch['x86_cr0'] = 0xFFFFFFFF
        c_arch['hwcache_info']['caches'] = ffi.NULL
        return c_arch

    def lift(self):
        if self.traceflags != 0 and l.getEffectiveLevel() > 20:
            l.setLevel(20)

        try:
            _libvex_lock.acquire()

            pvc.log_level = l.getEffectiveLevel()
            vex_arch = getattr(pvc, self.irsb.arch.vex_arch)

            if self.bytes_offset is None:
                self.bytes_offset = 0

            c_arch = self._construct_c_arch()

            c_irsb = pvc.vex_lift(vex_arch, c_arch, self.data + self.bytes_offset, self.irsb._addr, VEX_MAX_INSTRUCTIONS, VEX_MAX_BYTES, self.opt_level, self.traceflags, self.allow_lookback)

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

for a in SUPPORTED:
    register(LibVEXLifter, a)
