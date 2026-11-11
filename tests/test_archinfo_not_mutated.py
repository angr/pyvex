import copy

import pyvex
from pyvex import lift
from pyvex.enums import default_vex_archinfo


class _FrozenDict(dict):
    """A dict that refuses any modification after construction."""

    def _refuse(self, *args, **kwargs):
        raise AssertionError("vex_archinfo must not be mutated during a lift")

    __setitem__ = __delitem__ = update = pop = popitem = clear = setdefault = _refuse


def _frozen_archinfo():
    archinfo = default_vex_archinfo()
    archinfo["hwcache_info"] = _FrozenDict(archinfo["hwcache_info"])
    return _FrozenDict(archinfo)


def test_lift_does_not_mutate_arch_vex_archinfo():
    arch = pyvex.ARCH_AMD64
    original = arch.vex_archinfo
    before = copy.deepcopy(original)
    arch.vex_archinfo = _frozen_archinfo()
    try:
        irsb = lift(b"\x90\xc3", 0x1000, arch)
        assert irsb.size == 2
    finally:
        arch.vex_archinfo = original
    assert original == before


def test_lift_does_not_mutate_overridden_vex_archinfo():
    archinfo = _frozen_archinfo()
    irsb = lift(b"\x90\xc3", 0x1000, pyvex.ARCH_AMD64, vex_archinfo=archinfo)
    assert irsb.size == 2
    assert archinfo["hwcache_info"]["caches"] is None
