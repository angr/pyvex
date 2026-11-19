import logging
import threading
from typing import TYPE_CHECKING

from pyvex.errors import LiftingException
from pyvex.native import ffi, pvc
from pyvex.types import CLiftSource, LibvexArch

from .lift_function import Lifter

log = logging.getLogger("pyvex.lifting.libvex")

_libvex_lock = threading.Lock()

LIBVEX_SUPPORTED_ARCHES = {
    "X86",
    "AMD64",
    "MIPS32",
    "MIPS64",
    "MIPSN32",
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

    @staticmethod
    def _lift_decodable_prefix(vex_lift, max_inst):
        """
        Lift the longest run of instructions at the start of a block that libVEX failed to lift as a whole.

        If libVEX panics on the n-th instruction, lifting up to n - 1 instructions succeeds and lifting n or more fails,
        so the longest run that lifts can be found with a binary search over the instruction limit.

        :param vex_lift:    A function that lifts the block with the given instruction limit.
        :param max_inst:    The instruction limit that the block failed to lift with.
        :return:            The lift result, or NULL if not even the first instruction can be lifted.
        """
        if max_inst <= 1:
            return ffi.NULL
        # libVEX most often fails on the very first instruction, e.g., when lift() resumes lifting at the instruction
        # that a previous lift failed on. Rule that out with a single lift before searching.
        lift_r = vex_lift(1)
        if lift_r == ffi.NULL:
            return lift_r
        lifted, failed = 1, max_inst
        latest_failed = False
        while failed - lifted > 1:
            n = (lifted + failed) // 2
            latest_failed = vex_lift(n) == ffi.NULL
            if latest_failed:
                failed = n
            else:
                lifted = n
        if latest_failed:
            # Every lift reuses the same result buffer, so the last successful lift has been overwritten
            lift_r = vex_lift(lifted)
        return lift_r

    def _lift(self):
        if TYPE_CHECKING:
            assert isinstance(self.irsb.arch, LibvexArch)
            assert isinstance(self.data, CLiftSource)
        arch_vex_archinfo = self.vex_archinfo if self.vex_archinfo is not None else self.irsb.arch.vex_archinfo
        # Do not mutate the (possibly shared) arch object: libvex needs an explicit NULL for the cache pointer, so hand
        # it a copy with that field filled in instead.
        vex_archinfo = dict(arch_vex_archinfo)
        vex_archinfo["hwcache_info"] = {**arch_vex_archinfo["hwcache_info"], "caches": ffi.NULL}
        try:
            _libvex_lock.acquire()

            pvc.log_level = log.getEffectiveLevel()
            vex_arch = getattr(pvc, self.irsb.arch.vex_arch, None)
            assert vex_arch is not None

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

            if self.cross_insn_opt:
                px_control = VexRegisterUpdates.VexRegUpdUnwindregsAtMemAccess
            else:
                px_control = VexRegisterUpdates.VexRegUpdLdAllregsAtEachInsn

            data = self.data + self.bytes_offset

            def vex_lift(inst_limit):
                return pvc.vex_lift(
                    vex_arch,
                    vex_archinfo,
                    data,
                    self.irsb.addr,
                    inst_limit,
                    max_bytes,
                    self.opt_level,
                    self.traceflags,
                    self.allow_arch_optimizations,
                    strict_block_end,
                    1 if self.collect_data_refs else 0,
                    1 if self.load_from_ro_regions else 0,
                    1 if self.const_prop else 0,
                    px_control,
                    self.bytes_offset,
                )

            lift_r = vex_lift(max_inst)
            log_str = self.get_vex_log()
            partial = False
            if lift_r == ffi.NULL:
                # libVEX discards the whole block when it panics (e.g., an internal assertion fails) while decoding an
                # instruction, even if every instruction before it decoded fine. Lift those instructions on their own
                # and report the instruction that libVEX failed on as undecodable.
                lift_r = self._lift_decodable_prefix(vex_lift, max_inst)
                if lift_r == ffi.NULL:
                    raise LiftingException("libvex: unknown error" if log_str is None else log_str)
                partial = True
            elif log_str is not None:
                log.debug(log_str)

            self.irsb._from_c(lift_r, skip_stmts=self.skip_stmts)
            if partial:
                self.irsb.jumpkind = "Ijk_NoDecode"
                self.irsb.default_exit_target = None
                log.debug(
                    "libvex failed to lift the block @ %#x, lifted only its first %d instructions: %s",
                    self.addr,
                    self.irsb.instructions,
                    log_str,
                )
            if self.irsb.size == 0:
                log.debug("raising lifting exception")
                raise LiftingException("libvex: could not decode any instructions @ 0x%x" % self.addr)
        finally:
            _libvex_lock.release()
