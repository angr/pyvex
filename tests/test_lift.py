import nose
import archinfo
from pyvex.lifting.util import *

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

if __name__ == '__main__':
    test_partial_lift()
