from ..block import IRSB
import logging

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
             opt_level=1,
             traceflags=None,
             allow_lookback=None):
        """
        Create an irsb from data

        All of the lifters will be used in the order that they are registered
        whenever an instruction cannot be decoded until one is able to decode it
        """
        irsb = IRSB(self.arch, self.addr)
        self.data = data
        self.bytes_offset = bytes_offset
        self.opt_level = opt_level
        self.traceflags = traceflags
        self.allow_lookback = allow_lookback
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

def lift(arch, addr, data, bytes_offset=None, opt_level=1, traceflags=False, allow_lookback=False):
    final_irsb = IRSB(arch, addr)
    if isinstance(data, (str, bytes)):
        py_data = data
        c_data = None
        allow_lookback = False
    else:
        c_data = data
        py_data = None
        allow_lookback = True

    for lifter, registered_arch in lifters:
        if isinstance(registered_arch):
            continue
        try:
            u_data = data
            if lifter.REQUIRE_DATA_C:
                if c_data is None:
                    c_data = ffi.new('unsigned char [%d]' % (len(data) + 8), data + '\0' * 8)
                u_data = c_data
            elif lifter.REQUIRE_DATA_PY:
                if py_data is None:
                    py_data = str(ffi.buffer(data, len(data)))
                u_data = py_data
            next_irsb_part = lifter(arch, addr)._lift(u_data, bytes_offset, opt_level, traceflags, allow_lookback)
            l.debug("Lifted IRSB: ")
            l.debug(next_irsb_part._pp_str())
            final_irsb.extend(next_irsb_part)
            break
        except LiftingException:
            continue
    else:
        raise Exception('Cannot find lifter for arch %s' % arch)

    if final_irsb.jumpkind == 'Ijk_NoDecode':
        addr += next_irsb_part.size
        data_left = data[next_irsb_part.size:]
        if len(data_left) > 0:
            more_irsb = lift(arch, addr, data_left, bytes_offset, opt_level, traceflags, allow_lookback)
            final_irsb.extend(more_irsb)

    for postprocessor in postprocessors[type(arch)]:
        postprocessor(final_irsb).postprocess()
    return final_irsb

def register(lifter, arch):
    if issubclass(lifter, Lifter):
        lifters.append((lifter, arch))
    if issubclass(lifter, Postprocessor):
        postprocessors.append((lifter, arch))

from .. import ffi
from ..errors import PyVEXError

from .libvex import LibVEXLifter
from .fixes import FixesPostProcessor
