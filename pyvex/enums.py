import collections
from . import pvc, ffi

_counts = collections.Counter()

class VEXObject(object):
    """
    The base class for Vex types.
    """

    __slots__ = [ ]

    # def __init__(self):
    #   print "CREATING:",type(self)
    #   _counts[type(self)] += 1

    # def __del__(self):
    #   print "DELETING:",type(self)
    #   _counts[type(self)] -= 1

class IRCallee(VEXObject):
    """
    Describes a helper function to call.
    """

    __slots__ = ['regparms', 'name', 'mcx_mask', 'addr']

    def __init__(self, callee):
        VEXObject.__init__(self)
        self.regparms = callee.regparms
        self.name = ffi.string(callee.name)
        self.mcx_mask = callee.mcx_mask
        self.addr = int(ffi.cast("unsigned long long", callee.mcx_mask))

    def __str__(self):
        return self.name


class IRRegArray(VEXObject):
    """
    A section of the guest state that we want te be able to index at run time, so as to be able to describe indexed or
    rotating register files on the guest.

    :ivar int base:     The offset into the state that this array starts
    :ivar str elemTy:   The types of the elements in this array, as VEX enum strings
    :ivar int nElems:   The number of elements in this array
    """

    __slots__ = ['base', 'elemTy', 'nElems']

    def __init__(self, arr):
        VEXObject.__init__(self)
        self.base = arr.base
        self.elemTy = ints_to_enums[arr.elemTy]
        self.nElems = arr.nElems

    def __str__(self):
        return "%s:%sx%d" % (self.base, self.elemTy[4:], self.nElems)

enums_to_ints = {_: getattr(pvc, _) for _ in dir(pvc) if hasattr(pvc, _) and isinstance(getattr(pvc, _), int)}
ints_to_enums = {getattr(pvc, _): _ for _ in dir(pvc) if hasattr(pvc, _) and isinstance(getattr(pvc, _), int)}
enum_IROp_fromstr = {_: enums_to_ints[_] for _ in enums_to_ints if _.startswith('Iop_')}
type_sizes = {
    'Ity_INVALID': None,
    'Ity_I1': 1,
    'Ity_I8': 8,
    'Ity_I16': 16,
    'Ity_I32': 32,
    'Ity_I64': 64,
    'Ity_I128': 128,
    'Ity_F16': 16,
    'Ity_F32': 32,
    'Ity_F64': 64,
    'Ity_F128': 128,
    'Ity_D32': 32,
    'Ity_D64': 64,
    'Ity_D128': 128,
    'Ity_V128': 128,
    'Ity_V256': 256
}

def _get_op_type(op):
    irsb = pvc.emptyIRSB()
    t = pvc.newIRTemp(irsb.tyenv, pvc.Ity_I8)
    e = pvc.IRExpr_Unop(enums_to_ints[op], pvc.IRExpr_RdTmp(t))
    return ints_to_enums[pvc.typeOfIRExpr(irsb.tyenv, e)]


_op_types = {_: _get_op_type(_) for _ in enums_to_ints if
             _.startswith('Iop_') and _ != 'Iop_INVALID' and _ != 'Iop_LAST'}

def typeOfIROp(op):
    return _op_types[op]


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

