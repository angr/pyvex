import threading
import logging
l = logging.getLogger('pyvex.lift.libvex')
l.setLevel(20) # Shut up

from .. import stmt
from . import Lifter, register, LiftingException
from .. import pvc, ffi
from ..enums import default_vex_archinfo, vex_endness_from_string

_libvex_lock = threading.Lock()

SUPPORTED = {'X86', 'AMD64', 'MIPS32', 'MIPS64', 'ARM', 'ARMEL', 'ARMHF', 'AARCH64', 'PPC32', 'PPC64'}

VEX_MAX_INSTRUCTIONS = 99
VEX_MAX_BYTES = 5000

class LibVEXLifter(Lifter):
    REQUIRE_DATA_C = True

    @staticmethod
    def get_vex_log():
        return str(ffi.buffer(pvc.msg_buffer, pvc.msg_current_size)) if pvc.msg_buffer != ffi.NULL else None

    def lift(self):
        if self.traceflags != 0 and l.getEffectiveLevel() > 20:
            l.setLevel(20)

        try:
            _libvex_lock.acquire()

            pvc.log_level = l.getEffectiveLevel()
            vex_arch = getattr(pvc, self.irsb.arch.vex_arch)

            if self.bytes_offset is None:
                self.bytes_offset = 0

            if self.max_bytes is None or self.max_bytes > VEX_MAX_BYTES:
                max_bytes = VEX_MAX_BYTES
            else:
                max_bytes = self.max_bytes

            if self.max_inst is None or self.max_inst > VEX_MAX_INSTRUCTIONS:
                max_inst = VEX_MAX_INSTRUCTIONS
            else:
                max_inst = self.max_inst

            def create_irsb(inst_cutoff, bytes_cutoff):
                self.irsb.arch.vex_archinfo['hwcache_info']['caches'] = ffi.NULL
                c_irsb = pvc.vex_lift(vex_arch,
                                        self.irsb.arch.vex_archinfo,
                                        self.data + self.bytes_offset,
                                        self.irsb._addr,
                                        max_inst - inst_cutoff,
                                        max_bytes - bytes_cutoff,
                                        self.opt_level,
                                        self.traceflags,
                                        self.allow_lookback)
                log_str = self.get_vex_log()
                if c_irsb == ffi.NULL:
                    raise LiftingException("libvex: unkown error" if log_str is None else log_str)
                else:
                    if log_str is not None:
                        l.info(log_str)
                return c_irsb

            def create_from_c(c_irsb):
                newEmpty = self.irsb.empty_block(self.irsb.arch, self.irsb.addr)
                newEmpty._from_c(c_irsb)
                return newEmpty

            shouldExtendBytes = (VEX_MAX_BYTES >= max_bytes)
            shouldExtendInsts = (VEX_MAX_INSTRUCTIONS >= max_inst)

            trial_irsb = create_from_c(create_irsb(1, 1))
            might_be_byte_cutoff = (trial_irsb.size == max_bytes - 1)
            might_be_inst_cutoff = (trial_irsb.instructions == max_inst - 1)
            if (might_be_byte_cutoff or might_be_inst_cutoff):
                self.irsb = create_from_c(create_irsb(0, 0))
                if (self.irsb.size != trial_irsb.size):
                    self.irsb.jumpkind = 'Ijk_NoDecode'
                    self.irsb.next = 0
            else:
                self.irsb = trial_irsb

            for i in range(len(self.irsb.statements))[::-1]:
                s = self.irsb.statements[i]
                if isinstance(s, stmt.IMark) and s.len == 0:
                    self.irsb.statements = self.irsb.statements[:i]
                    break
            if self.irsb.size == 0:
                l.debug('raising lifting exception')
                raise LiftingException("libvex: could not decode any instructions")
        finally:
            _libvex_lock.release()
            self.irsb.arch.vex_archinfo['hwcache_info']['caches'] = None

for arch_name in SUPPORTED:
    register(LibVEXLifter, arch_name)
