import pyvex
import archinfo
from pyvex.block import IRSB
import nose.tools
import sys

def test_cache_invalidation_on_extend():
    b = pyvex.block.IRSB('\x50', 0, archinfo.ArchX86())
    nose.tools.assert_equal(b.size, 1)
    nose.tools.assert_equal(b.instructions, 1)
    toappend = pyvex.block.IRSB('\x51', 0, archinfo.ArchX86())
    toappend.jumpkind = 'Ijk_Invalid'
    toappend._direct_next = None # Invalidate the cache because I manually changed the jumpkind
    nose.tools.assert_equal(toappend.direct_next, False)
    b.extend(toappend)
    nose.tools.assert_equal(b.size, 2)
    nose.tools.assert_equal(b.instructions, 2)
    nose.tools.assert_equal(b.direct_next, False)

def run_all():
    g = globals()
    for k, v in g.iteritems():
        if k.startswith('test_') and hasattr(v, '__call__'):
            v()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
