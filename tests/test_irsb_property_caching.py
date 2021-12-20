from future.utils import iteritems
import pyvex
import archinfo
from pyvex.block import IRSB
import sys


def test_cache_invalidation_on_extend():
    b = pyvex.block.IRSB(b"\x50", 0, archinfo.ArchX86())
    assert b.size == 1
    assert b.instructions == 1
    toappend = pyvex.block.IRSB(b"\x51", 0, archinfo.ArchX86())
    toappend.jumpkind = "Ijk_Invalid"
    toappend._direct_next = (
        None  # Invalidate the cache because I manually changed the jumpkind
    )
    assert not toappend.direct_next
    b.extend(toappend)
    assert b.size == 2
    assert b.instructions == 2
    assert not b.direct_next


def run_all():
    g = globals()
    for k, v in iteritems(g):
        if k.startswith("test_") and hasattr(v, "__call__"):
            v()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        globals()["test_" + sys.argv[1]]()
    else:
        run_all()
