import logging
from .. import const
from ..expr import Const

l = logging.getLogger('pyvex.lift')

lifters = []
postprocessors = []

class LiftingException(Exception):
    pass

class Lifter(object):
    """
    A lifter is a class of methods for processing a block.
    """
    REQUIRE_DATA_C = False
    REQUIRE_DATA_PY = False

    def __init__(self, arch, addr):
        self.arch = arch
        self.addr = addr

    def _lift(self,
             data,
             bytes_offset=None,
             max_bytes=None,
             max_inst=None,
             opt_level=1,
             traceflags=None,
             allow_lookback=None):
        """
        Create an irsb from data

        All of the lifters will be used in the order that they are registered
        whenever an instruction cannot be decoded until one is able to decode it
        """
        irsb = IRSB.emptyBlock(self.arch, self.addr)
        self.data = data
        self.bytes_offset = bytes_offset
        self.opt_level = opt_level
        self.traceflags = traceflags
        self.allow_lookback = allow_lookback
        self.max_inst = max_inst
        self.max_bytes = max_bytes
        self.irsb = irsb
        self.lift()
        return self.irsb

class Postprocessor(object):

    def __init__(self, irsb):
        self.irsb = irsb

    def postprocess(self):
        """
        Modify the irsb

        All of the postprocessors will be used in the order that they are registered
        """
        pass

def lift(irsb, arch, addr, data, max_bytes=None, max_inst=None, bytes_offset=None, opt_level=1, traceflags=False):
    final_irsb = IRSB.emptyBlock(arch, addr)
    if isinstance(data, (str, bytes)):
        py_data = data
        c_data = None
        allow_lookback = False
    else:
        c_data = data
        py_data = None
        allow_lookback = True

    for lifter in lifters:
        try:
            u_data = data
            if lifter.REQUIRE_DATA_C:
                if c_data is None:
                    u_data = ffi.new('unsigned char [%d]' % (len(py_data) + 8), py_data + b'\0' * 8)
                    max_bytes = len(py_data)
                else:
                    u_data = c_data
            elif lifter.REQUIRE_DATA_PY:
                if py_data is None:
                    if max_bytes is None:
                        l.debug('Cannot create py_data from c_data when no max length is given')
                        continue
                    u_data = ffi.buffer(c_data, max_bytes)[:]
                else:
                    u_data = py_data
            next_irsb_part = lifter(arch, addr)._lift(u_data, bytes_offset, max_bytes, max_inst, opt_level, traceflags, allow_lookback)
            l.debug('block lifted by %s' % str(lifter))
            l.debug(str(next_irsb_part))
            final_irsb.extend(next_irsb_part)
            break
        except LiftingException as e:
            l.debug('Lifting Exception: %s' % e.message)
            continue
    else:
        final_irsb.jumpkind = 'Ijk_NoDecode'
        final_irsb.next = Const(const.vex_int_class(final_irsb.arch.bits)(final_irsb._addr))
        irsb._from_py(final_irsb)
        return

    if final_irsb.jumpkind == 'Ijk_NoDecode':
        addr += next_irsb_part.size
        if max_bytes is not None:
            max_bytes -= next_irsb_part.size
        if isinstance(data, (str, bytes)):
            data_left = data[next_irsb_part.size:]
        else:
            data_left = data + next_irsb_part.size
        if max_inst is not None:
            max_inst -= next_irsb_part.instructions
        if max_bytes > 0 and (max_inst is None or max_inst > 0):
            more_irsb = final_irsb.emptyBlock(final_irsb.arch, final_irsb.addr)
            lift(more_irsb, arch, addr, data_left, max_bytes, max_inst, bytes_offset, opt_level, traceflags)
            final_irsb.extend(more_irsb)

    for postprocessor in postprocessors:
        try:
            postprocessor(final_irsb).postprocess()
        except LiftingException:
            continue
    irsb._from_py(final_irsb)

def register(lifter):
    if issubclass(lifter, Lifter):
        lifters.append(lifter)
    if issubclass(lifter, Postprocessor):
        postprocessors.append(lifter)

from .. import ffi
from ..errors import PyVEXError

from .libvex import LibVEXLifter
from .fixes import FixesPostProcessor
from ..block import IRSB
