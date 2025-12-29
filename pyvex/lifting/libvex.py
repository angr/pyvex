import logging
import threading
from typing import TYPE_CHECKING

from pyvex.block import IRSB
from pyvex.errors import LiftingException
from pyvex.native import ffi, pvc
from pyvex.types import CLiftSource, LibvexArch

from .lifter import Lifter

log = logging.getLogger("pyvex.lifting.libvex")

_libvex_lock = threading.Lock()

LIBVEX_SUPPORTED_ARCHES = {
    "X86",
    "AMD64",
    "MIPS32",
    "MIPS64",
    "ARM",
    "ARMEL",
    "ARMHF",
    "ARMCortexM",
    "AARCH64",
    "PPC32",
    "PPC64",
    "S390X",
    "RISCV64",
}

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

    def _parameters_check_and_get_px_control(self) -> int:
        if self.bytes_offset is None:
            self.bytes_offset = 0

        if self.max_bytes is None or self.max_bytes > VEX_MAX_BYTES:
            self.max_bytes = VEX_MAX_BYTES

        if self.max_inst is None or self.max_inst > VEX_MAX_INSTRUCTIONS:
            self.max_inst = VEX_MAX_INSTRUCTIONS

        if self.strict_block_end is None:
            self.strict_block_end = True

        if self.cross_insn_opt:
            px_control = VexRegisterUpdates.VexRegUpdUnwindregsAtMemAccess
        else:
            px_control = VexRegisterUpdates.VexRegUpdLdAllregsAtEachInsn

        return px_control

    def _lift(self):
        if TYPE_CHECKING:
            assert isinstance(self.irsb.arch, LibvexArch)
            assert isinstance(self.data, CLiftSource)
        try:
            _libvex_lock.acquire()

            pvc.log_level = log.getEffectiveLevel()
            vex_arch = getattr(pvc, self.irsb.arch.vex_arch, None)
            assert vex_arch is not None

            px_control = self._parameters_check_and_get_px_control()

            self.irsb.arch.vex_archinfo["hwcache_info"]["caches"] = ffi.NULL
            lift_r = pvc.vex_lift(
                vex_arch,
                self.irsb.arch.vex_archinfo,
                self.data + self.bytes_offset,
                self.irsb.addr,
                self.max_inst,
                self.max_bytes,
                self.opt_level,
                self.traceflags,
                self.allow_arch_optimizations,
                self.strict_block_end,
                1 if self.collect_data_refs else 0,
                1 if self.load_from_ro_regions else 0,
                1 if self.const_prop else 0,
                px_control,
                self.bytes_offset,
                True
            )
            log_str = self.get_vex_log()
            if lift_r == ffi.NULL:
                raise LiftingException("libvex: unknown error" if log_str is None else log_str)
            else:
                if log_str is not None:
                    log.debug(log_str)

            self.irsb._from_c(lift_r, skip_stmts=self.skip_stmts)
            if self.irsb.size == 0:
                log.debug("raising lifting exception")
                raise LiftingException("libvex: could not decode any instructions @ 0x%x" % self.addr)
        finally:
            _libvex_lock.release()
            self.irsb.arch.vex_archinfo["hwcache_info"]["caches"] = None

    def _lift_multi(self) -> None:

        if TYPE_CHECKING:
            assert isinstance(self.arch, LibvexArch)
            assert isinstance(self.data, CLiftSource)

        # lift_results = pvc.VEXLiftResult * [ffi.NULL] * self.max_blocks
        lift_results = ffi.new("VEXLiftResult[]", self.max_blocks)


        try:
            _libvex_lock.acquire()
            self.arch.vex_archinfo["hwcache_info"]["caches"] = ffi.NULL

            vex_arch = getattr(pvc, self.arch.vex_arch, None)
            assert vex_arch is not None

            px_control = self._parameters_check_and_get_px_control()

            r: int = pvc.vex_lift_multi(
                vex_arch,
                self.arch.vex_archinfo,
                self.addr,
                self.data + self.bytes_offset,
                self.max_blocks,
                self.max_inst,
                self.max_bytes,
                self.opt_level,
                self.traceflags,
                1 if self.allow_arch_optimizations else 0,
                1 if self.strict_block_end else 0,
                1 if self.collect_data_refs else 0,
                1 if self.load_from_ro_regions else 0,
                1 if self.const_prop else 0,
                px_control,
                self.bytes_offset,
                self.arch.branch_delay_slot,
                lift_results,
            )


            log_str = self.get_vex_log()
            if r == -1:
                raise LiftingException("libvex: unknown error" if log_str is None else log_str)
            else:
                if log_str is not None:
                    log.debug(log_str)

            self.irsbs: list[IRSB] = [None] * r
            for i in range(r):
                self.irsbs[i] = IRSB.empty_block(self.arch, lift_results[i].inst_addrs[0])  # Assuming inst_addrs[0] gives the firs address of the block
                self.irsbs[i]._from_c(lift_results[i], skip_stmts=self.skip_stmts)

        finally:
            _libvex_lock.release()
            self.arch.vex_archinfo["hwcache_info"]["caches"] = None
