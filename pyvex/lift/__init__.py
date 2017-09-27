lifters = []
postprocessors = []


class Lifter(object):
    """
    A lifter is a class of methods for processing a block.
    """
    REQUIRE_DATA_C = False
    REQUIRE_DATA_PY = False

    def __init__(self,
            irsb,
            data,
            max_inst,
            max_bytes,
            bytes_offset,
            opt_level,
            traceflags,
            allow_lookback):
        self.irsb = irsb
        self.data = data
        self.max_inst = max_inst
        self.max_bytes = max_bytes
        self.bytes_offset = bytes_offset
        self.opt_level = opt_level
        self.traceflags = traceflags
        self.allow_lookback = allow_lookback

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

# max_bytes should always be provided
# max_inst might be none
def lift(irsb, data, max_bytes, max_inst, bytes_offset, opt_level, traceflags):
    if not max_bytes and not isinstance(data, (str, bytes)):
        raise PyVEXError("C-backed bytes must have the length specified by max_bytes")
    if not max_bytes:
        max_bytes = len(data)

    if max_bytes == 0:
        raise PyVEXError("No bytes provided")

    errors = []

    if isinstance(data, (str, bytes)):
        py_data = data
        c_data = None
        allow_lookback = False
    else:
        c_data = data
        py_data = None
        allow_lookback = True

    for lifter in lifters:
        u_data = data
        if lifter.REQUIRE_DATA_C:
            if c_data is None:
                c_data = ffi.new('unsigned char [%d]' % (len(data) + 8), data + b'\0' * 8)
            u_data = c_data
        elif lifter.REQUIRE_DATA_PY:
            if py_data is None:
                py_data = str(ffi.buffer(data, max_bytes))
            u_data = py_data

        # Setting it up with an instance per lift like this allows us thread safety, hypothetically
        # this could be done more efficiently with thread-local vars
        lifter_inst = lifter(irsb, u_data, max_inst, max_bytes, bytes_offset, opt_level, traceflags, allow_lookback)
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
                py_data = str(ffi.buffer(data, max_bytes))
            u_data = py_data
        lifter_inst = lifter(irsb, u_data, max_inst, max_bytes, bytes_offset, opt_level, traceflags, allow_lookback)
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
