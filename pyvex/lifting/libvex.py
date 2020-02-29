import threading
import logging
l = logging.getLogger('pyvex.lifting.libvex')
l.setLevel(20) # Shut up

from .. import stmt
from . import Lifter, register, LiftingException
from .. import pvc, ffi
from ..enums import default_vex_archinfo, vex_endness_from_string

_libvex_lock = threading.Lock()

SUPPORTED = {'X86', 'AMD64', 'MIPS32', 'MIPS64', 'ARM', 'ARMEL', 'ARMHF', 'ARMCortexM', 'AARCH64', 'PPC32', 'PPC64', 'S390X'}

VEX_MAX_INSTRUCTIONS = 99
VEX_MAX_BYTES = 5000


class VexRegisterUpdates:
    VexRegUpd_INVALID = 0x700
    VexRegUpdSpAtMemAccess = 0x701
    VexRegUpdUnwindregsAtMemAccess = 0x702
    VexRegUpdAllregsAtMemAccess = 0x703
    VexRegUpdAllregsAtEachInsn = 0x704
    VexRegUpdLdAllregsAtEachInsn = 0x705


class LibVEXLifter(Lifter):

    __slots__ = ()

    REQUIRE_DATA_C = True

    @staticmethod
    def get_vex_log():
        return bytes(ffi.buffer(pvc.msg_buffer, pvc.msg_current_size)).decode() if pvc.msg_buffer != ffi.NULL else None

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

            strict_block_end = self.strict_block_end
            if strict_block_end is None:
                strict_block_end = True

            collect_data_refs = self.collect_data_refs
            if collect_data_refs is None:
                collect_data_refs = False

            if self.cross_insn_opt:
                px_control = VexRegisterUpdates.VexRegUpdUnwindregsAtMemAccess
            else:
                px_control = VexRegisterUpdates.VexRegUpdLdAllregsAtEachInsn

            self.irsb.arch.vex_archinfo['hwcache_info']['caches'] = ffi.NULL
            lift_r = pvc.vex_lift(vex_arch,
                                  self.irsb.arch.vex_archinfo,
                                  self.data + self.bytes_offset,
                                  self.irsb.addr,
                                  max_inst,
                                  max_bytes,
                                  self.opt_level,
                                  self.traceflags,
                                  self.allow_arch_optimizations,
                                  strict_block_end,
                                  collect_data_refs,
                                  px_control,
                                  )
            log_str = self.get_vex_log()
            if lift_r == ffi.NULL:
                raise LiftingException("libvex: unknown error" if log_str is None else log_str)
            else:
                if log_str is not None:
                    l.info(log_str)

            self.irsb._from_c(lift_r, skip_stmts=self.skip_stmts)
            if self.irsb.size == 0:
                l.debug('raising lifting exception')
                raise LiftingException("libvex: could not decode any instructions @ 0x%x" % self.addr)
        finally:
            _libvex_lock.release()
            self.irsb.arch.vex_archinfo['hwcache_info']['caches'] = None


for arch_name in SUPPORTED:
    register(LibVEXLifter, arch_name)
