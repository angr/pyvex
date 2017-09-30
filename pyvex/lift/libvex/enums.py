from bidict import bidict, ValueDuplicationError

from . import pvc, ffi

class IRCallee(object):
    """
    Describes a helper function to call.
    """

    __slots__ = ['regparms', 'name', 'mcx_mask', 'addr']

    def __init__(self, regparms, name, addr, mcx_mask):
        self.regparms = regparms
        self.name = name
        self.addr = addr
        self.mcx_mask = mcx_mask

    def __str__(self):
        return self.name

    @staticmethod
    def _from_c(c_callee):
        return IRCallee(c_callee.regparms,
                        ffi.string(c_callee.name),
                        int(ffi.cast("unsigned long long", c_callee.addr)),
                        c_callee.mcx_mask)

    @staticmethod
    def _to_c(callee):
        c_callee = pvc.mkIRCallee(callee.regparms,
                                  callee.name,
                                  ffi.cast("void *", callee.addr))
        c_callee.mcx_mask = callee.mcx_mask
        return c_callee


class IRRegArray(object):
    """
    A section of the guest state that we want te be able to index at run time, so as to be able to describe indexed or
    rotating register files on the guest.

    :ivar int base:     The offset into the state that this array starts
    :ivar str elemTy:   The types of the elements in this array, as VEX enum strings
    :ivar int nElems:   The number of elements in this array
    """

    __slots__ = ['base', 'elemTy', 'nElems']

    def __init__(self, base, elemTy, nElems):
        self.base = base
        self.elemTy = elemTy
        self.nElems = nElems

    def __str__(self):
        return "%s:%sx%d" % (self.base, self.elemTy[4:], self.nElems)

    @staticmethod
    def _from_c(c_arr):
        return IRRegArray(c_arr.base,
                          ints_to_enums[c_arr.elemTy],
                          c_arr.nElems)

    @staticmethod
    def _to_c(arr):
        return pvc.mkIRRegArray(arr.base,
                                get_int_from_enum(arr.elemTy),
                                arr.nElems)
def get_enum_from_int(i):
    return ints_to_enums[i]

def get_int_from_enum(e):
    return enums_to_ints[e]

enums_to_ints = bidict()

will_be_overwritten = ['Ircr_GT', 'Ircr_LT']
for attr in dir(pvc):
    if attr[0] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' and hasattr(pvc, attr) and isinstance(getattr(pvc, attr), int):
        enum_int = getattr(pvc, attr)
        try:
            enums_to_ints[attr] = enum_int
        except ValueDuplicationError:
            if attr in will_be_overwritten:
                to_overwite = enums_to_ints.inv[enum_int]
                l.warning('Overwriting enum %s with enum %s. This is expected.' % (to_overwite, attr))
                enum_int.force_put(attr, enum_int)

def vex_endness_from_string(endness_str):
    return getattr(pvc, endness_str)

def default_vex_archinfo():
    return {
        'hwcaps': 0,
        'endness': vex_endness_from_string('VexEndnessLE'),
        'ppc_icache_line_szB': 0,
        'ppc_dcbz_szB': 0,
        'ppc_dcbzl_szB': 0,
        'arm64_dMinLine_lg2_szB': 0,
        'arm64_iMinLine_lg2_szB': 0,
        'hwcache_info': {
            'num_levels': 0,
            'num_caches': 0,
            'caches': None,
            'icaches_maintain_coherence': True,
        },
        'x86_cr0': 0xffffffff
    }
