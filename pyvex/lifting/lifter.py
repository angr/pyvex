
from ..block import IRSB

# pylint:disable=attribute-defined-outside-init


class Lifter:

    __slots__ = ('data', 'bytes_offset', 'opt_level', 'traceflags', 'allow_arch_optimizations', 'strict_block_end',
                 'collect_data_refs', 'max_inst', 'max_bytes', 'skip_stmts', 'irsb', 'arch', 'addr', 'cross_insn_opt',
                 'load_from_ro_regions', )

    """
    A lifter is a class of methods for processing a block.

    :ivar data:             The bytes to lift as either a python string of bytes or a cffi buffer object.
    :ivar bytes_offset:     The offset into `data` to start lifting at.
    :ivar max_bytes:        The maximum number of bytes to lift. If set to None, no byte limit is used.
    :ivar max_inst:         The maximum number of instructions to lift. If set to None, no instruction limit is used.
    :ivar opt_level:        The level of optimization to apply to the IR, 0-2. Most likely will be ignored in any lifter
                            other then LibVEX.
    :ivar traceflags:       The libVEX traceflags, controlling VEX debug prints. Most likely will be ignored in any lifter
                            other than LibVEX.
    :ivar allow_arch_optimizations:   Should the LibVEX lifter be allowed to perform lift-time preprocessing optimizations
                            (e.g., lookback ITSTATE optimization on THUMB)
                            Most likely will be ignored in any lifter other than LibVEX.
    :ivar strict_block_end: Should the LibVEX arm-thumb split block at some instructions, for example CB{N}Z.
    :ivar skip_stmts:       Should LibVEX ignore statements.
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
              allow_arch_optimizations=None,
              strict_block_end=None,
              skip_stmts=False,
              collect_data_refs=False,
              cross_insn_opt=True,
              load_from_ro_regions=False):
        """
        Wrapper around the `lift` method on Lifters. Should not be overridden in child classes.

        :param data:                The bytes to lift as either a python string of bytes or a cffi buffer object.
        :param bytes_offset:        The offset into `data` to start lifting at.
        :param max_bytes:           The maximum number of bytes to lift. If set to None, no byte limit is used.
        :param max_inst:            The maximum number of instructions to lift. If set to None, no instruction limit is used.
        :param opt_level:           The level of optimization to apply to the IR, 0-2. Most likely will be ignored in any lifter
                                    other then LibVEX.
        :param traceflags:          The libVEX traceflags, controlling VEX debug prints. Most likely will be ignored in any
                                    lifter other than LibVEX.
        :param allow_arch_optimizations:   Should the LibVEX lifter be allowed to perform lift-time preprocessing optimizations
                            (e.g., lookback ITSTATE optimization on THUMB)
                            Most likely will be ignored in any lifter other than LibVEX.
        :param strict_block_end:    Should the LibVEX arm-thumb split block at some instructions, for example CB{N}Z.
        :param skip_stmts:          Should the lifter skip transferring IRStmts from C to Python.
        :param collect_data_refs:   Should the LibVEX lifter collect data references in C.
        :param cross_insn_opt:      If cross-instruction-boundary optimizations are allowed or not.
        """
        irsb = IRSB.empty_block(self.arch, self.addr)
        self.data = data
        self.bytes_offset = bytes_offset
        self.opt_level = opt_level
        self.traceflags = traceflags
        self.allow_arch_optimizations = allow_arch_optimizations
        self.strict_block_end = strict_block_end
        self.collect_data_refs = collect_data_refs
        self.max_inst = max_inst
        self.max_bytes = max_bytes
        self.skip_stmts = skip_stmts
        self.irsb = irsb
        self.cross_insn_opt = cross_insn_opt
        self.load_from_ro_regions = load_from_ro_regions
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
        raise NotImplementedError()
