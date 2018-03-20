from collections import defaultdict
import logging
from .. import const
from ..expr import Const
from ..errors import PyVEXError

l = logging.getLogger('pyvex.lift')

lifters = defaultdict(list)
postprocessors = defaultdict(list)


class LiftingException(Exception):
    pass


def lift(irsb, arch, addr, data, max_bytes=None, max_inst=None, bytes_offset=None, opt_level=1, traceflags=False):
    """
    Recursively lifts blocks using the registered lifters and postprocessors. Tries each lifter in the order in
    which they are registered on the data to lift.

    If a lifter raises a LiftingException on the data, it is skipped.
    If it succeeds and returns a block with a jumpkind of Ijk_NoDecode, all of the lifters are tried on the rest
    of the data and if they work, their output is appended to the first block.

    :param irsb:            The IRSB to set to the lifted block (overriden by the lifted block)
    :type irsb:             :class:`IRSB`
    :param arch:            The arch to lift the data as.
    :type arch:             :class:`archinfo.Arch`
    :param addr:            The starting address of the block. Effects the IMarks.
    :param data:            The bytes to lift as either a python string of bytes or a cffi buffer object.
    :param max_bytes:       The maximum number of bytes to lift. If set to None, no byte limit is used.
    :param max_inst:        The maximum number of instructions to lift. If set to None, no instruction limit is used.
    :param bytes_offset:    The offset into `data` to start lifting at.
    :param opt_level:       The level of optimization to apply to the IR, 0-2. 2 is maximum optimization, 0 is no optimization.
    :param traceflags:      The libVEX traceflags, controlling VEX debug prints.

    .. note:: Explicitly specifying the number of instructions to lift (`max_inst`) may not always work
              exactly as expected. For example, on MIPS, it is meaningless to lift a branch or jump
              instruction without its delay slot. VEX attempts to Do The Right Thing by possibly decoding
              fewer instructions than requested. Specifically, this means that lifting a branch or jump
              on MIPS as a single instruction (`max_inst=1`) will result in an empty IRSB, and subsequent
              attempts to run this block will raise `SimIRSBError('Empty IRSB passed to SimIRSB.')`.

    .. note:: If no instruction and byte limit is used, pyvex will continue lifting the block until the block
              ends properly or until it runs out of data to lift.
    """
    if max_bytes is not None and max_bytes <= 0:
        raise PyVEXError("cannot lift block with no data (max_bytes <= 0)")

    if not data:
        raise PyVEXError("cannot lift block with no data (data is empty)")

    final_irsb = IRSB.empty_block(arch, addr)

    if isinstance(data, (str, bytes)):
        py_data = data
        c_data = None
        allow_lookback = False
    else:
        c_data = data
        py_data = None
        allow_lookback = True

    for lifter in lifters[arch.name]:
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
            #l.debug('block lifted by %s' % str(lifter))
            #l.debug(str(next_irsb_part))
            final_irsb.extend(next_irsb_part)
            break
        except LiftingException as ex:
            l.debug('Lifting Exception: %s', ex.message)
            continue
    else:
        final_irsb.jumpkind = 'Ijk_NoDecode'
        final_irsb.next = Const(const.vex_int_class(final_irsb.arch.bits)(final_irsb._addr))
        final_irsb.invalidate_direct_next()
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
            more_irsb = final_irsb.empty_block(final_irsb.arch, final_irsb.addr)
            lift(more_irsb, arch, addr, data_left, max_bytes, max_inst, bytes_offset, opt_level, traceflags)
            final_irsb.extend(more_irsb)

    for postprocessor in postprocessors[arch.name]:
        try:
            postprocessor(final_irsb).postprocess()
        except LiftingException:
            continue
    irsb._from_py(final_irsb)


def register(lifter, arch_name):
    """
    Registers a Lifter or Postprocessor to be used by pyvex. Lifters are are given priority based on the order
    in which they are registered. Postprocessors will be run in registration order.

    :param lifter:       The Lifter or Postprocessor to register
    :vartype lifter:     :class:`Lifter` or :class:`Postprocessor`
    """
    if issubclass(lifter, Lifter):
        l.debug("Registering lifter %s for architecture %s.", lifter.__name__, arch_name)
        lifters[arch_name].append(lifter)
    if issubclass(lifter, Postprocessor):
        l.debug("Registering postprocessor %s for architecture %s.", lifter.__name__, arch_name)
        postprocessors[arch_name].append(lifter)


from .. import ffi
from .lifter import Lifter
from .post_processor import Postprocessor
from .libvex import LibVEXLifter
from .fixes import FixesPostProcessor
from ..block import IRSB
