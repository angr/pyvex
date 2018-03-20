
from ..block import IRSB


class Lifter(object):
    """
    A lifter is a class of methods for processing a block.

    :ivar data:            The bytes to lift as either a python string of bytes or a cffi buffer object.
    :ivar bytes_offset:    The offset into `data` to start lifting at.
    :ivar max_bytes:       The maximum number of bytes to lift. If set to None, no byte limit is used.
    :ivar max_inst:        The maximum number of instructions to lift. If set to None, no instruction limit is used.
    :ivar opt_level:       The level of optimization to apply to the IR, 0-2. Most likely will be ignored in any lifter
                           other then LibVEX.
    :ivar traceflags:      The libVEX traceflags, controlling VEX debug prints. Most likely will be ignored in any lifter
                           other than LibVEX.
    :ivar allow_lookback:  Should the LibVEX arm-thumb lifter be allowed to look before the current instruction pointer.
                           Most likely will be ignored in any lifter other than LibVEX.
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
        Wrapper around the `lift` method on Lifters. Should not be overridden in child classes.

        :param data:            The bytes to lift as either a python string of bytes or a cffi buffer object.
        :param bytes_offset:    The offset into `data` to start lifting at.
        :param max_bytes:       The maximum number of bytes to lift. If set to None, no byte limit is used.
        :param max_inst:        The maximum number of instructions to lift. If set to None, no instruction limit is used.
        :param opt_level:       The level of optimization to apply to the IR, 0-2. Most likely will be ignored in any lifter
                                other then LibVEX.
        :param traceflags:      The libVEX traceflags, controlling VEX debug prints. Most likely will be ignored in any
                                lifter other than LibVEX.
        :param allow_lookback:  Should the LibVEX arm-thumb lifter be allowed to look before the current instruction pointer.
                                Most likely will be ignored in any lifter other than LibVEX.
        """
        irsb = IRSB.empty_block(self.arch, self.addr)
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

    def lift(self):
        """
        Lifts the data using the information passed into _lift. Should be overridden in child classes.

        Should set the lifted IRSB to self.irsb.
        If a lifter raises a LiftingException on the data, this signals that the lifter cannot lift this data and arch
        and the lifter is skipped.
        If a lifter can lift any amount of data, it should lift it and return the lifted block with a jumpkind of
        Ijk_NoDecode, signalling to pyvex that other lifters should be used on the undecodable data.

        """
        raise NotImplementedError
