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
VEX_MAX_BYTES = 400

class LibVEXLifter(Lifter):
    REQUIRE_DATA_C = True

    def lift(self):
        if self.traceflags != 0 and l.getEffectiveLevel() > 20:
            l.setLevel(20)

        if self.arch.name not in SUPPORTED:
            raise LiftingException('Cannot lift arch %s' % self.arch.name)

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
                log_str = str(ffi.buffer(pvc.msg_buffer, pvc.msg_current_size)) if pvc.msg_buffer != ffi.NULL else None
                if c_irsb == ffi.NULL:
                    raise LiftingException("libvex: unkown error" if log_str is None else log_str)
                else:
                    if log_str is not None:
                        l.info(log_str)
                return c_irsb

            def create_from_c(c_irsb):
                newEmpty = self.irsb.emptyBlock(self.irsb.arch, self.irsb.addr)
                newEmpty._from_c(c_irsb)
                return newEmpty

            shouldExtendBytes = (VEX_MAX_BYTES == max_bytes)
            shouldExtendInsts = (VEX_MAX_INSTRUCTIONS == max_inst)

            if (shouldExtendBytes or shouldExtendInsts):
                bytes_shortage = 1 if shouldExtendBytes else 0
                insts_shortage = 1 if shouldExtendInsts else 0
                extended_c_irsb = create_irsb(0, 0)
                l.debug('Lifting extended block')
                extended_irsb = create_from_c(extended_c_irsb)
                if extended_irsb.instructions < 2:
                    c_irsb = extended_c_irsb
                    self.irsb._from_c(c_irsb)
                else:
                    l.debug('Lifting shortened block for insts_shortage %d and bytes_shortage %d'
                                                                        % (insts_shortage, bytes_shortage))
                    shortened_c_irsb = create_irsb(insts_shortage, bytes_shortage)

                    self.irsb._from_c(shortened_c_irsb)
                    c_irsb = shortened_c_irsb
                    if self.irsb.size != extended_irsb.size:
                        self.irsb.jumpkind = 'Ijk_NoDecode'
                        self.irsb.next = 0
            else:
                l.debug('Lifting standard block')
                c_irsb = create_irsb(0, 0)
                self.irsb._from_c(c_irsb)

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

register(LibVEXLifter)

