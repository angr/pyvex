# pylint: disable=missing-class-docstring,no-self-use
import unittest

import archinfo

import pyvex


class TestCacheInvalidationOnExtend(unittest.TestCase):
    def test_cache_invalidation_on_extend(self):
        b = pyvex.block.IRSB(b"\x50", 0, archinfo.ArchX86())
        assert b.size == 1
        assert b.instructions == 1
        toappend = pyvex.block.IRSB(b"\x51", 0, archinfo.ArchX86())
        toappend.jumpkind = "Ijk_Invalid"
        toappend._direct_next = None  # Invalidate the cache because I manually changed the jumpkind
        assert not toappend.direct_next
        b.extend(toappend)
        assert b.size == 2
        assert b.instructions == 2
        assert not b.direct_next


if __name__ == "__main__":
    unittest.main()
