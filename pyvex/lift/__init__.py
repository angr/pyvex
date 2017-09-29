from ..block import IRSB

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
        self.irsb = IRSB(arch, addr)

    #  def __call__(self, *args, **kwargs):
    #      self.lift(*args, **kwargs)

    def lift(self,
             data,
             max_bytes=None,
             max_inst=None,
             bytes_offset=None,
             opt_level=1,
             traceflags,
             allow_lookback):
        """
        Populate the fields of the empty IRSB passed in. Return whether or not successful.

        Only the first successful lifter will be used.
        """
        return False

class Postprocessor(object):
    def __init__(self, irsb):
        self.irsb = irsb

    #  def __call__(self, *args, **kwargs):
    #      self.postprocess(*args, **kwargs)

    def postprocess(self):
        """
        Modify the irsb

        All of the postprocessors will be used in the order that they are registered
        """
        pass

def lift(arch, addr, data, max_bytes, max_inst, bytes_offset, opt_level, traceflags):
    final_irsb = IRSB(arch, addr)
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
                    c_data = ffi.new('unsigned char [%d]' % (len(data) + 8), data + '\0' * 8)
                u_data = c_data
            elif lifter.REQUIRE_DATA_PY:
                if py_data is None:
                    py_data = str(ffi.buffer(data, max_bytes))
                u_data = py_data
            next_irsb_part = lifter(arch, addr).lift(u_data, **kwargs)
            break
        except LiftingException:
            continue
    else:
        raise Exception('Cannot find lifter for arch %s' % arch)

    if final_irsb.jumpkind == 'Ijk_NoDecode':
        addr += next_irsb_part.size
        data_left = data[next_irsb_part.size:]
        max_bytes -= next_irsb_part.size
        max_inst -= next_irsb_part.instructions
        if max_bytes > 0 and max_inst > 0 and len(data_left) > 0:
            final_irsb.extend(lift(arch, addr, max_bytes, max_inst, bytes_offset, opt_level, traceflags))

    for postprocessor in postprocessors:
        postprocessor(final_irsb).postprocess()
    return final_irsb

def register(lifter):
    if isinstance(lifter, Lifter):
        lifters.append(lifter)
    if isinstance(lifter, Postprocessor):
        postprocessors.append(lifter)

from .. import ffi
from ..errors import PyVEXError

from .libvex import LibVEXLifter
from .fixes import FixesPostProcessor
#
#  def register(lifter):
#      if lifter.lift is not Lifter.lift:
#          lifters.append(lifter)
#      if lifter.postprocess is not Lifter.postprocess:
#          postprocessors.append(lifter)
#
#
#  def _lift_part(arch, addr, data, max_bytes, max_inst, bytes_offset, opt_level, traceflags):
#      irsb = IRSB(arch, addr)
#      for lifter in lifters:
#          u_data = data
#          if lifter.REQUIRE_DATA_C:
#              if c_data is None:
#                  c_data = ffi.new('unsigned char [%d]' % (len(data) + 8), data + '\0' * 8)
#              u_data = c_data
#          elif lifter.REQUIRE_DATA_PY:
#              if py_data is None:
#                  py_data = str(ffi.buffer(data, max_bytes))
#              u_data = py_data
#
#          # Setting it up with an instance per lift like this allows us thread safety, hypothetically
#          # this could be done more efficiently with thread-local vars
#          lifter_inst = lifter(irsb, u_data, max_inst, max_bytes, bytes_offset, opt_level, traceflags, allow_lookback)
#          if lifter_inst.lift():
#              break
#          else:
#              err = lifter_inst.error()
#              if err is not None:
#                  errors.append(err)
#      else:
#          if len(errors) == 0:
#              raise PyVEXError('No lifters for architecture %s!' % irsb.arch.name)
#          raise PyVEXError('\n\n'.join(errors))
#      return irsb
#
#  # max_bytes should always be provided
#  # max_inst might be none
#  def lift(arch, addr, data, max_bytes, max_inst, bytes_offset, opt_level, traceflags):
#      if not max_bytes and not isinstance(data, (str, bytes)):
#          raise PyVEXError("C-backed bytes must have the length specified by max_bytes")
#      if not max_bytes:
#          max_bytes = len(data)
#
#      if max_bytes == 0:
#          raise PyVEXError("No bytes provided")
#
#      errors = []
#      final_irsb = IRSB(arch, addr)
#
#      if isinstance(data, (str, bytes)):
#          py_data = data
#          c_data = None
#          allow_lookback = False
#      else:
#          c_data = data
#          py_data = None
#          allow_lookback = True
#
#      while (final_irsb.jumpkind is None or final_irsb.jumpkind == 'Ijk_NoDecode') and max_bytes > 0 and (max_inst is None or max_inst > 0):
#          _lift_part(addr, arch, data, max_bytes, max_inst, bytes_offset, opt_level, traceflags)
#          final_irsb.extend(template)
#          addr += template.size
#          max_bytes -= template.size
#          max_inst -= template.instructions
#
#      for lifter in postprocessors:
#          u_data = data
#          if lifter.REQUIRE_DATA_C:
#              if c_data is None:
#                  c_data = ffi.new('unsigned char [%d]' % (len(data) + 8), data + '\0' * 8)
#              u_data = c_data
#          elif lifter.REQUIRE_DATA_PY:
#              if py_data is None:
#                  py_data = str(ffi.buffer(data, max_bytes))
#              u_data = py_data
#          lifter_inst = lifter(final_irsb, u_data, max_inst, max_bytes, bytes_offset, opt_level, traceflags, allow_lookback)
#          lifter_inst.postprocess()
#      return final_irsb
#
