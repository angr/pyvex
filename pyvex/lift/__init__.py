import logging

l = logging.getLogger('pyvex.lift')
l.setLevel(logging.DEBUG)

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
        allow_lookback = False
    else:
        if max_bytes is None:
            raise Exception('Cannot pass c buffer without length')
        py_data = ffi.string(data, max_bytes)
        allow_lookback = True

    for lifter, registered_arch in lifters:
        if not isinstance(arch, registered_arch):
            continue
        try:
            u_data = data
            if lifter.REQUIRE_DATA_C:
                u_data = ffi.new('unsigned char [%d]' % (len(py_data) + 8), py_data + '\0' * 8)
            elif lifter.REQUIRE_DATA_PY:
                u_data = py_data
            next_irsb_part = lifter(arch, addr)._lift(u_data, bytes_offset, max_bytes, max_inst, opt_level, traceflags, allow_lookback)
            l.debug("Lifted IRSB: ")
            l.debug(next_irsb_part._pp_str())
            final_irsb.extend(next_irsb_part)
            print '[+] Lifted using lifter %s' % str(lifter)
            break
        except LiftingException:
            continue
    else:
        import ipdb; ipdb.set_trace()
        raise Exception('Cannot find lifter for arch %s' % arch)

    if final_irsb.jumpkind == 'Ijk_NoDecode':
        addr += next_irsb_part.size
        data_left = py_data[next_irsb_part.size:]
        if max_inst is not None:
            max_inst -= next_irsb_part.instructions
        if len(data_left) > 0 and max_inst > 0:
            more_irsb = lift(arch, addr, data_left, len(data_left), max_inst, bytes_offset, opt_level, traceflags, allow_lookback)
            final_irsb.extend(more_irsb)

    for postprocessor, registered_arch in postprocessors:
        if not isinstance(arch, registered_arch):
            continue
        postprocessor(final_irsb).postprocess()
    irsb._from_py(final_irsb)

def register(lifter, arch):
    if issubclass(lifter, Lifter):
        lifters.append((lifter, arch))
    if issubclass(lifter, Postprocessor):
        postprocessors.append((lifter, arch))

from .. import ffi
from ..errors import PyVEXError

from .libvex import LibVEXLifter
from .fixes import FixesPostProcessor
from ..block import IRSB
