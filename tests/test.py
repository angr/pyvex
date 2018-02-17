import pyvex
import nose
import random
import resource
import gc
import copy

from archinfo import ArchAMD64, ArchARM, ArchPPC32, ArchX86, Endness

def test_memory():
    arches = [ ArchX86(), ArchPPC32(endness=Endness.BE), ArchAMD64(), ArchARM() ]
    # we're not including ArchMIPS32 cause it segfaults sometimes

    for i in xrange(10000):
        try:
            s = hex(random.randint(2**100,2**100*16))[2:]
            a = random.choice(arches)
            p = pyvex.IRSB(data=s, mem_addr=0, arch=a)
        except pyvex.PyVEXError:
            pass

    kb_start = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    for i in xrange(40000):
        try:
            s = hex(random.randint(2**100,2**100*16))[2:]
            a = random.choice(arches)
            p = pyvex.IRSB(data=s, mem_addr=0, arch=a)
        except pyvex.PyVEXError:
            pass
    del p
    gc.collect()

    kb_end = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    # allow a 2mb leeway
    nose.tools.assert_less(kb_end - kb_start, 2000)

################
### IRCallee ###
################

def test_ircallee():
    callee = pyvex.IRCallee(3, "test_name", 1234, 0xFFFFFF)
    nose.tools.assert_equals(callee.name, "test_name")
    nose.tools.assert_equals(callee.regparms, 3)
    nose.tools.assert_equals(callee.addr, 1234)
    nose.tools.assert_equals(callee.mcx_mask, 0xFFFFFF)

############
### IRSB ###
############

def test_irsb_empty():
    nose.tools.assert_raises(Exception, pyvex.IRSB)
    nose.tools.assert_raises(Exception, pyvex.IRSB, data='', arch=ArchAMD64(), mem_addr=0)

def test_irsb_arm():
    irsb = pyvex.IRSB(data='\x33\xff\x2f\xe1', mem_addr=0, arch=ArchARM())
    nose.tools.assert_equal(sum([ 1 for i in irsb.statements if type(i) == pyvex.IRStmt.IMark ]), 1)

def test_irsb_popret():
    irsb = pyvex.IRSB(data='\x5d\xc3', mem_addr=0, arch=ArchAMD64())
    stmts = irsb.statements
    irsb.pp()

    nose.tools.assert_greater(len(stmts), 0)
    nose.tools.assert_equal(irsb.jumpkind, "Ijk_Ret")
    nose.tools.assert_equal(irsb.offsIP, 184)

    cursize = len(irsb.tyenv.types)
    nose.tools.assert_greater(cursize, 0)
    print irsb.statements[10].data
    print irsb.statements[10].data.tmp
    print irsb.tyenv.types[irsb.statements[10].data.tmp]
    nose.tools.assert_equal(irsb.tyenv.lookup(irsb.statements[10].data.tmp), 'Ity_I64')

def test_two_irsb():
    irsb1 = pyvex.IRSB(data='\x5d\xc3', mem_addr=0, arch=ArchAMD64())
    irsb2 = pyvex.IRSB(data='\x5d\x5d\x5d\x5d', mem_addr=0, arch=ArchAMD64())

    stmts1 = irsb1.statements
    stmts2 = irsb2.statements

    nose.tools.assert_not_equal(len(stmts1), len(stmts2))

def test_irsb_deepCopy():
    irsb = pyvex.IRSB(data='\x5d\xc3', mem_addr=0, arch=ArchAMD64())
    stmts = irsb.statements

    irsb2 = copy.deepcopy(irsb)
    stmts2 = irsb2.statements
    nose.tools.assert_equal(len(stmts), len(stmts2))

def test_irsb_addStmt():
    irsb = pyvex.IRSB(data='\x5d\xc3', mem_addr=0, arch=ArchAMD64())
    stmts = irsb.statements

    irsb2 = copy.deepcopy(irsb)
    irsb2.statements = []
    nose.tools.assert_equal(len(irsb2.statements), 0)

    for n, i in enumerate(stmts):
        nose.tools.assert_equal(len(irsb2.statements), n)
        irsb2.statements.append(copy.deepcopy(i))

    irsb2.pp()

def test_irsb_tyenv():
    irsb = pyvex.IRSB(data='\x5d\xc3', mem_addr=0, arch=ArchAMD64())
    print irsb.tyenv
    print "Orig"
    print irsb.tyenv

    print "Empty"
    irsb2 = pyvex.IRSB.empty_block(arch=ArchAMD64(), addr=0)
    print irsb2.tyenv

    print "Unwrapped"
    irsb2.tyenv = copy.deepcopy(irsb.tyenv)
    print irsb2.tyenv

##################
### Statements ###
##################

def test_irstmt_pp():
    irsb = pyvex.IRSB(data='\x5d\xc3', mem_addr=0, arch=ArchAMD64())
    stmts = irsb.statements
    for i in stmts:
        print "STMT: ",
        print i

def test_irstmt_flat():
    print "TODO"

def test_irstmt_imark():
    m = pyvex.IRStmt.IMark(1,2,3)
    nose.tools.assert_equal(m.tag, "Ist_IMark")
    nose.tools.assert_equal(m.addr, 1)
    nose.tools.assert_equal(m.len, 2)
    nose.tools.assert_equal(m.delta, 3)

    m.addr = 5
    nose.tools.assert_equal(m.addr, 5)
    m.len = 5
    nose.tools.assert_equal(m.len, 5)
    m.delta = 5
    nose.tools.assert_equal(m.delta, 5)

    nose.tools.assert_raises(Exception, pyvex.IRStmt.IMark, ())

def test_irstmt_abihint():
    nose.tools.assert_raises(Exception, pyvex.IRStmt.AbiHint, ())

    a = pyvex.IRExpr.RdTmp(123)
    b = pyvex.IRExpr.RdTmp(456)

    m = pyvex.IRStmt.AbiHint(a, 10, b)
    nose.tools.assert_equal(m.base.tmp, 123)
    nose.tools.assert_equal(m.len, 10)
    nose.tools.assert_equal(m.nia.tmp, 456)

def test_irstmt_put():
    nose.tools.assert_raises(Exception, pyvex.IRStmt.Put, ())

    a = pyvex.IRExpr.RdTmp(123)
    m = pyvex.IRStmt.Put(a, 10)
    print "Put stmt:",
    print m
    print ""
    nose.tools.assert_equal(m.data.tmp, 123)
    nose.tools.assert_equal(m.offset, 10)

def test_irexpr_puti():
    r = pyvex.IRRegArray(10, "Ity_I64", 20)
    i = pyvex.IRExpr.RdTmp(5)
    d = pyvex.IRExpr.RdTmp(30)
    m = pyvex.IRStmt.PutI(r, i, d, 2)
    nose.tools.assert_equal(m.descr.base, 10)
    nose.tools.assert_equal(m.ix.tmp, 5)
    nose.tools.assert_equal(m.bias, 2)
    nose.tools.assert_equal(m.data.tmp, d.tmp)

    nose.tools.assert_raises(Exception, pyvex.IRStmt.PutI, ())

def test_irstmt_wrtmp():
    nose.tools.assert_raises(Exception, pyvex.IRStmt.WrTmp, ())

    a = pyvex.IRExpr.RdTmp(123)
    m = pyvex.IRStmt.WrTmp(10, a)
    nose.tools.assert_equal(m.tag, "Ist_WrTmp")
    nose.tools.assert_equal(m.tmp, 10)
    nose.tools.assert_equal(m.data.tmp, 123)

def test_irstmt_store():
    nose.tools.assert_raises(Exception, pyvex.IRStmt.Store, ())

    a = pyvex.IRExpr.RdTmp(123)
    d = pyvex.IRExpr.RdTmp(456)
    m = pyvex.IRStmt.Store(a, d, "Iend_LE")
    nose.tools.assert_equal(m.tag, "Ist_Store")
    nose.tools.assert_equal(m.endness, "Iend_LE")
    nose.tools.assert_equal(m.addr.tmp, a.tmp)
    nose.tools.assert_equal(m.data.tmp, d.tmp)

def test_irstmt_cas():
    nose.tools.assert_raises(Exception, pyvex.IRStmt.CAS, ())

    a = pyvex.IRExpr.RdTmp(10)
    eh = pyvex.IRExpr.RdTmp(11)
    el = pyvex.IRExpr.RdTmp(12)
    dh = pyvex.IRExpr.RdTmp(21)
    dl = pyvex.IRExpr.RdTmp(22)

    args = { "oldHi": 1, "oldLo": 2, "end": "Iend_LE", "addr": a,
                 "expdHi": eh, "expdLo": el, "dataHi": dh, "dataLo": dl }

    m = pyvex.IRStmt.CAS(**args)
    nose.tools.assert_equal(m.tag, "Ist_CAS")
    nose.tools.assert_equal(m.endness, "Iend_LE")
    nose.tools.assert_equal(m.oldHi, 1)
    nose.tools.assert_equal(m.oldLo, 2)
    nose.tools.assert_equal(m.addr.tmp, a.tmp)
    nose.tools.assert_equal(m.expdHi.tmp, eh.tmp)
    nose.tools.assert_equal(m.expdLo.tmp, el.tmp)
    nose.tools.assert_equal(m.dataHi.tmp, dh.tmp)
    nose.tools.assert_equal(m.dataLo.tmp, dl.tmp)

def test_irstmt_loadg():
    nose.tools.assert_raises(Exception, pyvex.IRStmt.LoadG, ())

    a = pyvex.IRExpr.RdTmp(10)
    alt = pyvex.IRExpr.RdTmp(11)
    guard = pyvex.IRExpr.RdTmp(12)

    args = { "dst": 1, "end": "Iend_LE", "addr": a,
                 "alt": alt, "guard": guard, "cvt": "ILGop_Ident32" }

    m = pyvex.IRStmt.LoadG(**args)
    nose.tools.assert_equal(m.tag, "Ist_LoadG")
    nose.tools.assert_equal(m.end, "Iend_LE")
    nose.tools.assert_equal(m.cvt, "ILGop_Ident32")
    nose.tools.assert_equal(m.dst, 1)
    nose.tools.assert_equal(m.addr.tmp, a.tmp)
    nose.tools.assert_equal(m.alt.tmp, alt.tmp)
    nose.tools.assert_equal(m.guard.tmp, guard.tmp)

    nose.tools.assert_equal(m.cvt_types, ("Ity_I32", "Ity_I32"))

def test_irstmt_storeg():
    nose.tools.assert_raises(Exception, pyvex.IRStmt.LoadG, ())

    a = pyvex.IRExpr.RdTmp(10)
    data = pyvex.IRExpr.RdTmp(11)
    guard = pyvex.IRExpr.RdTmp(12)

    args = { "end": "Iend_LE", "addr": a, "data": data, "guard": guard }

    m = pyvex.IRStmt.StoreG(**args)
    nose.tools.assert_equal(m.tag, "Ist_StoreG")
    nose.tools.assert_equal(m.end, "Iend_LE")
    nose.tools.assert_equal(m.addr.tmp, a.tmp)
    nose.tools.assert_equal(m.data.tmp, data.tmp)
    nose.tools.assert_equal(m.guard.tmp, guard.tmp)

def test_irstmt_llsc():
    nose.tools.assert_raises(Exception, pyvex.IRStmt.LLSC)

    a = pyvex.IRExpr.RdTmp(123)
    d = pyvex.IRExpr.RdTmp(456)
    m = pyvex.IRStmt.LLSC(a, d, 1, "Iend_LE")
    nose.tools.assert_equal(m.tag, "Ist_LLSC")
    nose.tools.assert_equal(m.endness, "Iend_LE")
    nose.tools.assert_equal(m.result, 1)
    nose.tools.assert_equal(m.addr.tmp, a.tmp)
    nose.tools.assert_equal(m.storedata.tmp, d.tmp)

def test_irstmt_mbe():
    m = pyvex.IRStmt.MBE("Imbe_CancelReservation")
    nose.tools.assert_equal(m.event, "Imbe_CancelReservation")
    m.event = "Imbe_Fence"
    nose.tools.assert_equal(m.event, "Imbe_Fence")

def test_irstmt_dirty():
    args = [ pyvex.IRExpr.RdTmp(i) for i in range(10) ]
    m = pyvex.IRStmt.Dirty("test_dirty", pyvex.IRConst.U8(1), args, 15, "Ifx_None", 0, 1, 0)
    nose.tools.assert_equal(m.cee, "test_dirty")
    nose.tools.assert_equals(type(m.guard), pyvex.IRConst.U8)
    nose.tools.assert_equals(m.tmp, 15)
    nose.tools.assert_equals(m.mFx, "Ifx_None")
    nose.tools.assert_equals(m.nFxState, 0)

    for n,a in enumerate(m.args):
        nose.tools.assert_equals(a.tmp, args[n].tmp)

def test_irstmt_exit():
    nose.tools.assert_raises(Exception, pyvex.IRStmt.Exit)

    g = pyvex.IRExpr.RdTmp(123)
    d = pyvex.IRConst.U32(456)

    m = pyvex.IRStmt.Exit(g, d, "Ijk_Ret", 10)
    nose.tools.assert_equal(m.tag, "Ist_Exit")
    nose.tools.assert_equal(m.jumpkind, "Ijk_Ret")
    nose.tools.assert_equal(m.offsIP, 10)
    nose.tools.assert_equal(m.guard.tmp, g.tmp)
    nose.tools.assert_equal(m.dst.value, d.value)

##################
### IRRegArray ###
##################

def test_irregarray():
    m = pyvex.IRRegArray(10, "Ity_I64", 20)

    nose.tools.assert_equals(m.nElems, 20)
    nose.tools.assert_equals(m.elemTy, "Ity_I64")
    nose.tools.assert_equals(m.base, 10)

################
### IRConst.s ###
################

def helper_const_subtype(subtype, tag, value):
    print "Testing %s" % tag
    nose.tools.assert_raises(Exception, subtype)

    c = subtype(value)
    nose.tools.assert_equals(c.tag, tag)
    nose.tools.assert_equals(c.value, value)

    d = subtype(value - 1)
    e = subtype(value)
    nose.tools.assert_equals(c.value, e.value)
    nose.tools.assert_equals(e.value, c.value)
    nose.tools.assert_not_equals(c.value, d.value)
    nose.tools.assert_not_equals(d.value, c.value)
    nose.tools.assert_not_equals(c.value, "test")

    # TODO: actually check value
    nose.tools.assert_equals(c.type, d.type)

def test_irconst():
    helper_const_subtype(pyvex.IRConst.U1, "Ico_U1", 1)
    helper_const_subtype(pyvex.IRConst.U8, "Ico_U8", 233)
    helper_const_subtype(pyvex.IRConst.U16, "Ico_U16", 39852)
    helper_const_subtype(pyvex.IRConst.U32, "Ico_U32", 3442312356)
    helper_const_subtype(pyvex.IRConst.U64, "Ico_U64", 823452334523623455)
    helper_const_subtype(pyvex.IRConst.F32, "Ico_F32", 13453.234375)
    helper_const_subtype(pyvex.IRConst.F32i, "Ico_F32i", 3442312356)
    helper_const_subtype(pyvex.IRConst.F64, "Ico_F64", 13453.234525)
    helper_const_subtype(pyvex.IRConst.F64i, "Ico_F64i", 823457234523623455)
    helper_const_subtype(pyvex.IRConst.V128, "Ico_V128", 39852)
    helper_const_subtype(pyvex.IRConst.V256, "Ico_V256", 3442312356)

###################
### Expressions ###
###################

def test_irexpr_binder():
    # binder doesn't work statically, but hopefully we should
    # never see it, anyways
    return
    m = pyvex.IRExpr.Binder(1534252)
    nose.tools.assert_equal(m.binder, 1534252)

def test_irexpr_geti():
    r = pyvex.IRRegArray(10, "Ity_I64", 20)
    i = pyvex.IRExpr.RdTmp(5)
    m = pyvex.IRExpr.GetI(r, i, 2)
    nose.tools.assert_equal(m.description.base, 10)
    nose.tools.assert_equal(m.index.tmp, 5)
    nose.tools.assert_equal(m.bias, 2)

    nose.tools.assert_raises(Exception, pyvex.IRExpr.GetI)

def test_irexpr_rdtmp():
    m = pyvex.IRExpr.RdTmp(123)
    nose.tools.assert_equal(m.tag, "Iex_RdTmp")
    nose.tools.assert_equal(m.tmp, 123)

    m.tmp = 1337
    nose.tools.assert_equal(m.tmp, 1337)
    nose.tools.assert_raises(Exception, pyvex.IRExpr.RdTmp)

    irsb = pyvex.IRSB('\x90\x5d\xc3', mem_addr=0x0, arch=ArchAMD64())
    print "TMP:",irsb.next.tmp


def test_irexpr_get():
    m = pyvex.IRExpr.Get(0, "Ity_I64")
    nose.tools.assert_equal(m.type, "Ity_I64")

    nose.tools.assert_raises(Exception, pyvex.IRExpr.Get)

def test_irexpr_qop():
    a = pyvex.IRExpr.Get(0, "Ity_I64")
    b = pyvex.IRExpr.Get(184, "Ity_I64")
    c = pyvex.IRExpr.RdTmp(1)
    d = pyvex.IRExpr.RdTmp(2)
    op = "Iop_QAdd32S"

    m = pyvex.IRExpr.Qop(op, [a, b, c, d])

    nose.tools.assert_equal(m.op, op)
    nose.tools.assert_equal(m.args[1].type, b.type)

    nose.tools.assert_equal(len(m.args), 4)
    nose.tools.assert_equal(m.args[2].tmp, c.tmp)

def test_irexpr_triop():
    a = pyvex.IRExpr.Get(0, "Ity_I64")
    b = pyvex.IRExpr.Get(184, "Ity_I64")
    c = pyvex.IRExpr.RdTmp(1)
    op = "Iop_MAddF64"

    m = pyvex.IRExpr.Triop(op, [a, b, c])

    nose.tools.assert_equal(m.op, op)
    nose.tools.assert_equal(m.args[1].type, b.type)

    nose.tools.assert_equal(len(m.args), 3)
    nose.tools.assert_equal(m.args[2].tmp, c.tmp)

def test_irexpr_binop():
    a = pyvex.IRExpr.Get(0, "Ity_I64")
    c = pyvex.IRExpr.RdTmp(1)
    op = "Iop_Add64"

    m = pyvex.IRExpr.Binop(op, [a, c])

    nose.tools.assert_equal(m.op, op)
    nose.tools.assert_equal(m.args[1].tmp, c.tmp)

    nose.tools.assert_equal(len(m.args), 2)
    nose.tools.assert_equal(m.args[1].tmp, c.tmp)

def test_irexpr_unop():
    a = pyvex.IRExpr.Get(0, "Ity_I64")
    op = "Iop_Add64"

    m = pyvex.IRExpr.Unop(op, [a])

    nose.tools.assert_equal(m.op, op)
    nose.tools.assert_equal(len(m.args), 1)
    nose.tools.assert_equal(m.args[0].offset, a.offset)

def test_irexpr_load():
    a = pyvex.IRExpr.Get(0, "Ity_I64")
    e = "Iend_LE"
    t = "Ity_I64"

    m = pyvex.IRExpr.Load(e, t, a)

    nose.tools.assert_equal(m.endness, e)
    nose.tools.assert_equal(m.type, t)

def test_irexpr_const():
    u1 = pyvex.IRConst.U1(1)
    f64 = pyvex.IRConst.F64(1.123)

    ue = pyvex.IRExpr.Const(u1)
    fe = pyvex.IRExpr.Const(f64)

    nose.tools.assert_equal(ue.con.value, u1.value)
    nose.tools.assert_not_equal(ue.con.value, f64.value)

def test_irexpr_ite():
    a = pyvex.IRExpr.Get(0, "Ity_I64")
    iffalse = pyvex.IRExpr.RdTmp(1)
    iftrue = pyvex.IRExpr.Const(pyvex.IRConst.U8(200))

    m = pyvex.IRExpr.ITE(a, iffalse, iftrue)

    nose.tools.assert_equal(m.iftrue.con.value, iftrue.con.value)

def test_irexpr_ccall():
    callee = pyvex.IRCallee(3, "test_name", 1234, 0xFFFFFF)
    args = [ pyvex.IRExpr.RdTmp(i) for i in range(10) ]

    m = pyvex.IRExpr.CCall("Ity_I64", callee, args)

    nose.tools.assert_equal(len(m.args), len(args))
    nose.tools.assert_equal(m.ret_type, "Ity_I64")
    nose.tools.assert_equal(m.callee.addr, 1234)

    for n,a in enumerate(m.args):
        nose.tools.assert_equals(a.tmp, args[n].tmp)

    m = pyvex.IRExpr.CCall(callee, "Ity_I64", ())
    nose.tools.assert_equals(len(m.args), 0)

if __name__ == '__main__':
    test_memory()
