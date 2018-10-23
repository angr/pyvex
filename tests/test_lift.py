import nose
import archinfo
from pyvex import IRSB, lift, ffi
from pyvex.lifting.util import Instruction, GymratLifter, JumpKind
from pyvex.errors import PyVEXError

def test_partial_lift():
    """This tests that gymrat correctly handles the case where an
    instruction is longer than the remaining input.
    """
    class NOP(Instruction):
        name = "nop"
        bin_format = "0000111100001111"

        def compute_result(self, *args):
            pass

    class NOPLifter(GymratLifter):
        instrs = [NOP]

    lifter = NOPLifter(archinfo.ArchAMD64(), 0)
    # this should not throw an exception
    block = lifter._lift("\x0F\x0Fa")
    nose.tools.assert_equal(block.size, 2)
    nose.tools.assert_equal(block.instructions, 1)
    nose.tools.assert_equal(block.jumpkind, JumpKind.NoDecode)


def test_skipstmts_toomanyexits():

    # https://github.com/angr/pyvex/issues/153

    old_exit_limit = IRSB.MAX_EXITS
    IRSB.MAX_EXITS = 32

    bytes_ = bytes.fromhex("0DF1B00B2EAB94E8030008938BE803000DF1C0089AE8030083E80300019B0DF1F00A339AE669E26193E8030085E8030098E8030083E80300069B95E8030088E80300A26993E803004A92002363622362A361E362A36238AC029A069484E8030012AC0998299328932B9303C885E8030092E8030084E803009AE8030082E803002A460A9D26993E910B9941910D9942910C992A93409548AD439194E803008AE8030027983F9927913F909BE803000DF5887B269335938BE803000DF58C7B089903C98BE8030098E8030084E8030095E8030088E803004B993391329394E80300349337933693069C059B4C93049B4E9350ABCDF834C1CDF83CE185E8030094E803004B9683E8030015A94498C4F7E2EA")
    arch = archinfo.arch_from_id("ARMEL")
    # Lifting the first four bytes will not cause any problem. Statements should be skipped as expected
    b = IRSB(bytes_[:34], 0xC6951, arch, opt_level=1, bytes_offset=5, skip_stmts=True)
    nose.tools.assert_greater(len(b.exit_statements), 0)
    nose.tools.assert_false(b.has_statements, None)

    # Lifting the entire block will cause the number of exit statements go beyond the limit (currently 32). PyVEX will
    # automatically relift this block without skipping the statements
    b = IRSB(bytes_, 0xC6951, arch, opt_level=1, bytes_offset=5, skip_stmts=True)
    nose.tools.assert_is_not(b.statements, None)
    nose.tools.assert_greater(len(b.exit_statements), 32)

    # Restore the setting
    IRSB.MAX_EXITS = old_exit_limit

def test_max_bytes():
    data = bytes.fromhex('909090909090c3')
    arch = archinfo.ArchX86()
    nose.tools.assert_equal(lift(data, 0x1000, arch, max_bytes=None).size, len(data))
    nose.tools.assert_equal(lift(data, 0x1000, arch, max_bytes=len(data) - 1).size, len(data) - 1)
    nose.tools.assert_equal(lift(data, 0x1000, arch, max_bytes=len(data) + 1).size, len(data))

    data2 = ffi.from_buffer(data)
    nose.tools.assert_raises(PyVEXError, lift, data2, 0x1000, arch)
    nose.tools.assert_equal(lift(data2, 0x1000, arch, max_bytes=len(data)).size, len(data))
    nose.tools.assert_equal(lift(data2, 0x1000, arch, max_bytes=len(data) - 1).size, len(data) - 1)

if __name__ == '__main__':
    test_partial_lift()
    test_skipstmts_toomanyexits()
    test_max_bytes()
