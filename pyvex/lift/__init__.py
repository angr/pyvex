lifters = []
postprocessors = []


class Lifter(object):
    """
    A lifter is a class of methods for processing a block.
    """
    REQUIRE_DATA_C = False
    REQUIRE_DATA_PY = False

    def __init__(self, irsb, data, num_inst, num_bytes, bytes_offset, traceflags):
        self.irsb = irsb
        self.data = data
        self.num_inst = num_inst
        self.num_bytes = num_bytes
        self.bytes_offset = bytes_offset
        self.traceflags = traceflags

        self._error = None  # you might want to use this

    # pylint: disable=no-self-use

    def lift(self):
        """
        Populate the fields of the empty IRSB passed in. Return whether or not successful.

        Only the first successful lifter will be used.
        """
        return False

    def error(self):
        """
        Return the error message from an unsuccessful lift. If the error is just "unsupported
        architecture", just return None.
        """
        return self._error

    def postprocess(self):
        """
        Postprocess the populated IRSB passed in.
        """
        pass

# num_bytes should always be provided
# num_inst might be none
def lift(irsb, data, num_bytes, num_inst, bytes_offset, traceflags):
    if not num_bytes and not isinstance(data, (str, bytes)):
        raise PyVEXError("C-backed bytes must have the length specified by num_bytes")
    if not num_bytes:
        num_bytes = len(data)

    if num_bytes == 0:
        raise PyVEXError("No bytes provided")

    errors = []

    if isinstance(data, (str, bytes)):
        py_data = data
        c_data = None
    else:
        c_data = data
        py_data = None

    for lifter in lifters:
        u_data = data
        if lifter.REQUIRE_DATA_C:
            if c_data is None:
                c_data = ffi.new('unsigned char [%d]' % (len(data) + 8), data + '\0' * 8)
            u_data = c_data
        elif lifter.REQUIRE_DATA_PY:
            if py_data is None:
                py_data = str(ffi.buffer(data, num_bytes))
            u_data = py_data

        # Setting it up with an instance per lift like this allows us thread safety, hypothetically
        # this could be done more efficiently with thread-local vars
        lifter_inst = lifter(irsb, u_data, num_inst, num_bytes, bytes_offset, traceflags)
        if lifter_inst.lift():
            break
        else:
            err = lifter_inst.error()
            if err is not None:
                errors.append(err)
    else:
        if len(errors) == 0:
            raise PyVEXError('No lifters for architecture %s!' % irsb.arch.name)
        raise PyVEXError('\n\n'.join(errors))

    for lifter in postprocessors:
        u_data = data
        if lifter.REQUIRE_DATA_C:
            if c_data is None:
                c_data = ffi.new('unsigned char [%d]' % (len(data) + 8), data + '\0' * 8)
            u_data = c_data
        elif lifter.REQUIRE_DATA_PY:
            if py_data is None:
                py_data = str(ffi.buffer(data, num_bytes))
            u_data = py_data
        lifter_inst = lifter(irsb, u_data, num_inst, num_bytes, bytes_offset, traceflags)
        lifter_inst.postprocess()

def register(lifter):
    if lifter.lift is not Lifter.lift:
        lifters.append(lifter)
    if lifter.postprocess is not Lifter.postprocess:
        postprocessors.append(lifter)

from .. import ffi
from ..errors import PyVEXError

from .libvex import LibVEXLifter
from .fixes import FixesPostProcessor
