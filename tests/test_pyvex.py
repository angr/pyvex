import copy
import gc
import logging
import os
import random
import sys
import unittest

import pyvex
from pyvex.lifting import LibVEXLifter

if sys.platform == "linux":
    import resource


# pylint: disable=R0201
class TestPyvex(unittest.TestCase):
    @unittest.skipUnless(
        sys.platform == "linux", "Cannot import the resource package on windows, values different on macos."
    )
    def test_memory(self):
        arches = [pyvex.ARCH_X86, pyvex.ARCH_PPC32, pyvex.ARCH_AMD64, pyvex.ARCH_ARM_BE]
        # we're not including ArchMIPS32 cause it segfaults sometimes

        # disable logging, as that may fill up log buffers somewhere
        logging.disable(logging.ERROR)

        for _ in range(10000):
            try:
                s = os.urandom(32)
                a = random.choice(arches)
                p = pyvex.IRSB(data=s, mem_addr=0, arch=a)
            except pyvex.PyVEXError:
                pass

        kb_start = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        for _ in range(20000):
            try:
                s = os.urandom(32)
                a = random.choice(arches)
                p = pyvex.IRSB(data=s, mem_addr=0, arch=a)
            except pyvex.PyVEXError:
                pass
        del p
        gc.collect()

        logging.disable(logging.NOTSET)

        kb_end = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        pyvex.pvc.clear_log()
        pyvex.pvc.LibVEX_ShowAllocStats()
        print(LibVEXLifter.get_vex_log())

        # allow a 5mb leeway
        assert kb_end - kb_start < 5000

    ################
    ### IRCallee ###
    ################

    def test_ircallee(self):
        callee = pyvex.IRCallee(3, "test_name", 0xFFFFFF)
        assert callee.name == "test_name"
        assert callee.regparms == 3
        assert callee.mcx_mask == 0xFFFFFF

    ############
    ### IRSB ###
    ############

    def test_irsb_empty(self):
        self.assertRaises(Exception, pyvex.IRSB)
        self.assertRaises(Exception, pyvex.IRSB, data="", arch=pyvex.ARCH_AMD64, mem_addr=0)

    def test_irsb_arm(self):
        irsb = pyvex.IRSB(data=b"\x33\xff\x2f\xe1", mem_addr=0, arch=pyvex.ARCH_ARM_BE)
        assert len([i for i in irsb.statements if type(i) == pyvex.IRStmt.IMark]) == 1

    def test_irsb_popret(self):
        irsb = pyvex.IRSB(data=b"\x5d\xc3", mem_addr=0, arch=pyvex.ARCH_AMD64)
        stmts = irsb.statements
        irsb.pp()

        assert len(stmts) > 0
        assert irsb.jumpkind == "Ijk_Ret"
        assert irsb.offsIP == 184

        cursize = len(irsb.tyenv.types)
        assert cursize > 0
        print(irsb.statements[10].data)
        print(irsb.statements[10].data.tmp)
        print(irsb.tyenv.types[irsb.statements[10].data.tmp])
        assert irsb.tyenv.lookup(irsb.statements[10].data.tmp) == "Ity_I64"

    def test_two_irsb(self):
        irsb1 = pyvex.IRSB(data=b"\x5d\xc3", mem_addr=0, arch=pyvex.ARCH_AMD64)
        irsb2 = pyvex.IRSB(data=b"\x5d\x5d\x5d\x5d", mem_addr=0, arch=pyvex.ARCH_AMD64)

        stmts1 = irsb1.statements
        stmts2 = irsb2.statements

        assert len(stmts1) != len(stmts2)

    def test_irsb_deepCopy(self):
        irsb = pyvex.IRSB(data=b"\x5d\xc3", mem_addr=0, arch=pyvex.ARCH_AMD64)
        stmts = irsb.statements

        irsb2 = copy.deepcopy(irsb)
        stmts2 = irsb2.statements
        assert len(stmts) == len(stmts2)

    def test_irsb_addStmt(self):
        irsb = pyvex.IRSB(data=b"\x5d\xc3", mem_addr=0, arch=pyvex.ARCH_AMD64)
        stmts = irsb.statements

        irsb2 = copy.deepcopy(irsb)
        irsb2.statements = []
        assert len(irsb2.statements) == 0

        for n, i in enumerate(stmts):
            assert len(irsb2.statements) == n
            irsb2.statements.append(copy.deepcopy(i))

        irsb2.pp()

    def test_irsb_tyenv(self):
        irsb = pyvex.IRSB(data=b"\x5d\xc3", mem_addr=0, arch=pyvex.ARCH_AMD64)
        print(irsb.tyenv)
        print("Orig")
        print(irsb.tyenv)

        print("Empty")
        irsb2 = pyvex.IRSB.empty_block(arch=pyvex.ARCH_AMD64, addr=0)
        print(irsb2.tyenv)

        print("Unwrapped")
        irsb2.tyenv = copy.deepcopy(irsb.tyenv)
        print(irsb2.tyenv)

    ##################
    ### Statements ###
    ##################

    def test_irstmt_pp(self):
        irsb = pyvex.IRSB(data=b"\x5d\xc3", mem_addr=0, arch=pyvex.ARCH_AMD64)
        stmts = irsb.statements
        for i in stmts:
            print("STMT: ", end=" ")
            print(i)

    def test_irstmt_flat(self):
        print("TODO")

    def test_irstmt_imark(self):
        m = pyvex.IRStmt.IMark(1, 2, 3)
        assert m.tag == "Ist_IMark"
        assert m.addr == 1
        assert m.len == 2
        assert m.delta == 3

        m.addr = 5
        assert m.addr == 5
        m.len = 5
        assert m.len == 5
        m.delta = 5
        assert m.delta == 5

        self.assertRaises(Exception, pyvex.IRStmt.IMark, ())

    def test_irstmt_abihint(self):
        self.assertRaises(Exception, pyvex.IRStmt.AbiHint, ())

        a = pyvex.IRExpr.RdTmp.get_instance(123)
        b = pyvex.IRExpr.RdTmp.get_instance(456)

        m = pyvex.IRStmt.AbiHint(a, 10, b)
        assert m.base.tmp == 123
        assert m.len == 10
        assert m.nia.tmp == 456

    def test_irstmt_put(self):
        self.assertRaises(Exception, pyvex.IRStmt.Put, ())

        a = pyvex.IRExpr.RdTmp.get_instance(123)
        m = pyvex.IRStmt.Put(a, 10)
        print("Put stmt:", end=" ")
        print(m)
        print("")
        assert m.data.tmp == 123
        assert m.offset == 10

    def test_irexpr_puti(self):
        r = pyvex.IRRegArray(10, "Ity_I64", 20)
        i = pyvex.IRExpr.RdTmp.get_instance(5)
        d = pyvex.IRExpr.RdTmp.get_instance(30)
        m = pyvex.IRStmt.PutI(r, i, d, 2)
        assert m.descr.base == 10
        assert m.ix.tmp == 5
        assert m.bias == 2
        assert m.data.tmp == d.tmp

        self.assertRaises(Exception, pyvex.IRStmt.PutI, ())

    def test_irstmt_wrtmp(self):
        self.assertRaises(Exception, pyvex.IRStmt.WrTmp, ())

        a = pyvex.IRExpr.RdTmp.get_instance(123)
        m = pyvex.IRStmt.WrTmp(10, a)
        assert m.tag == "Ist_WrTmp"
        assert m.tmp == 10
        assert m.data.tmp == 123

    def test_irstmt_store(self):
        self.assertRaises(Exception, pyvex.IRStmt.Store, ())

        a = pyvex.IRExpr.RdTmp.get_instance(123)
        d = pyvex.IRExpr.RdTmp.get_instance(456)
        m = pyvex.IRStmt.Store(a, d, "Iend_LE")
        assert m.tag == "Ist_Store"
        assert m.endness == "Iend_LE"
        assert m.addr.tmp == a.tmp
        assert m.data.tmp == d.tmp

    def test_irstmt_cas(self):
        self.assertRaises(Exception, pyvex.IRStmt.CAS, ())

        a = pyvex.IRExpr.RdTmp.get_instance(10)
        eh = pyvex.IRExpr.RdTmp.get_instance(11)
        el = pyvex.IRExpr.RdTmp.get_instance(12)
        dh = pyvex.IRExpr.RdTmp.get_instance(21)
        dl = pyvex.IRExpr.RdTmp.get_instance(22)

        args = {
            "oldHi": 1,
            "oldLo": 2,
            "end": "Iend_LE",
            "addr": a,
            "expdHi": eh,
            "expdLo": el,
            "dataHi": dh,
            "dataLo": dl,
        }

        m = pyvex.IRStmt.CAS(**args)
        assert m.tag == "Ist_CAS"
        assert m.endness == "Iend_LE"
        assert m.oldHi == 1
        assert m.oldLo == 2
        assert m.addr.tmp == a.tmp
        assert m.expdHi.tmp == eh.tmp
        assert m.expdLo.tmp == el.tmp
        assert m.dataHi.tmp == dh.tmp
        assert m.dataLo.tmp == dl.tmp

    def test_irstmt_loadg(self):
        self.assertRaises(Exception, pyvex.IRStmt.LoadG, ())

        a = pyvex.IRExpr.RdTmp.get_instance(10)
        alt = pyvex.IRExpr.RdTmp.get_instance(11)
        guard = pyvex.IRExpr.RdTmp.get_instance(12)

        args = {
            "dst": 1,
            "end": "Iend_LE",
            "addr": a,
            "alt": alt,
            "guard": guard,
            "cvt": "ILGop_Ident32",
        }

        m = pyvex.IRStmt.LoadG(**args)
        assert m.tag == "Ist_LoadG"
        assert m.end == "Iend_LE"
        assert m.cvt == "ILGop_Ident32"
        assert m.dst == 1
        assert m.addr.tmp == a.tmp
        assert m.alt.tmp == alt.tmp
        assert m.guard.tmp == guard.tmp

        assert m.cvt_types == ("Ity_I32", "Ity_I32")

    def test_irstmt_storeg(self):
        self.assertRaises(Exception, pyvex.IRStmt.LoadG, ())

        a = pyvex.IRExpr.RdTmp.get_instance(10)
        data = pyvex.IRExpr.RdTmp.get_instance(11)
        guard = pyvex.IRExpr.RdTmp.get_instance(12)

        args = {"end": "Iend_LE", "addr": a, "data": data, "guard": guard}

        m = pyvex.IRStmt.StoreG(**args)
        assert m.tag == "Ist_StoreG"
        assert m.end == "Iend_LE"
        assert m.addr.tmp == a.tmp
        assert m.data.tmp == data.tmp
        assert m.guard.tmp == guard.tmp

    def test_irstmt_llsc(self):
        self.assertRaises(Exception, pyvex.IRStmt.LLSC)

        a = pyvex.IRExpr.RdTmp.get_instance(123)
        d = pyvex.IRExpr.RdTmp.get_instance(456)
        m = pyvex.IRStmt.LLSC(a, d, 1, "Iend_LE")
        assert m.tag == "Ist_LLSC"
        assert m.endness == "Iend_LE"
        assert m.result == 1
        assert m.addr.tmp == a.tmp
        assert m.storedata.tmp == d.tmp

    def test_irstmt_mbe(self):
        m = pyvex.IRStmt.MBE("Imbe_CancelReservation")
        assert m.event == "Imbe_CancelReservation"
        m.event = "Imbe_Fence"
        assert m.event == "Imbe_Fence"

    def test_irstmt_dirty(self):
        args = [pyvex.IRExpr.RdTmp.get_instance(i) for i in range(10)]
        m = pyvex.IRStmt.Dirty("test_dirty", pyvex.IRConst.U8(1), args, 15, "Ifx_None", 0, 1, 0)
        assert m.cee == "test_dirty"
        assert type(m.guard) == pyvex.IRConst.U8
        assert m.tmp == 15
        assert m.mFx == "Ifx_None"
        assert m.nFxState == 0

        for n, a in enumerate(m.args):
            assert a.tmp == args[n].tmp

    def test_irstmt_exit(self):
        self.assertRaises(Exception, pyvex.IRStmt.Exit)

        g = pyvex.IRExpr.RdTmp.get_instance(123)
        d = pyvex.IRConst.U32(456)

        m = pyvex.IRStmt.Exit(g, d, "Ijk_Ret", 10)
        assert m.tag == "Ist_Exit"
        assert m.jumpkind == "Ijk_Ret"
        assert m.offsIP == 10
        assert m.guard.tmp == g.tmp
        assert m.dst.value == d.value

    ##################
    ### IRRegArray ###
    ##################

    def test_irregarray(self):
        m = pyvex.IRRegArray(10, "Ity_I64", 20)

        assert m.nElems == 20
        assert m.elemTy == "Ity_I64"
        assert m.base == 10

    ################
    ### IRConst.s ###
    ################

    def helper_const_subtype(self, subtype, tag, value):
        print("Testing %s" % tag)
        self.assertRaises(Exception, subtype)

        c = subtype(value)
        assert c.tag == tag
        assert c.value == value

        d = subtype(value - 1)
        e = subtype(value)
        assert c.value == e.value
        assert e.value == c.value
        self.assertNotEqual(c.value, d.value)
        self.assertNotEqual(d.value, c.value)
        self.assertNotEqual(c.value, "test")

        # TODO: actually check value
        assert c.type == d.type

    def test_irconst(self):
        self.helper_const_subtype(pyvex.IRConst.U1, "Ico_U1", 1)
        self.helper_const_subtype(pyvex.IRConst.U8, "Ico_U8", 233)
        self.helper_const_subtype(pyvex.IRConst.U16, "Ico_U16", 39852)
        self.helper_const_subtype(pyvex.IRConst.U32, "Ico_U32", 3442312356)
        self.helper_const_subtype(pyvex.IRConst.U64, "Ico_U64", 823452334523623455)
        self.helper_const_subtype(pyvex.IRConst.F32, "Ico_F32", 13453.234375)
        self.helper_const_subtype(pyvex.IRConst.F32i, "Ico_F32i", 3442312356)
        self.helper_const_subtype(pyvex.IRConst.F64, "Ico_F64", 13453.234525)
        self.helper_const_subtype(pyvex.IRConst.F64i, "Ico_F64i", 823457234523623455)
        self.helper_const_subtype(pyvex.IRConst.V128, "Ico_V128", 39852)
        self.helper_const_subtype(pyvex.IRConst.V256, "Ico_V256", 3442312356)

    ###################
    ### Expressions ###
    ###################

    def test_irexpr_binder(self):
        # binder doesn't work statically, but hopefully we should
        # never see it, anyways
        return
        # m = pyvex.IRExpr.Binder(1534252)
        # assert m.binder == 1534252

    def test_irexpr_geti(self):
        r = pyvex.IRRegArray(10, "Ity_I64", 20)
        i = pyvex.IRExpr.RdTmp.get_instance(5)
        m = pyvex.IRExpr.GetI(r, i, 2)
        assert m.description.base == 10
        assert m.index.tmp == 5
        assert m.bias == 2

        self.assertRaises(Exception, pyvex.IRExpr.GetI)

    def test_irexpr_rdtmp(self):
        m = pyvex.IRExpr.RdTmp.get_instance(123)
        assert m.tag == "Iex_RdTmp"
        assert m.tmp == 123

        irsb = pyvex.IRSB(b"\x90\x5d\xc3", mem_addr=0x0, arch=pyvex.ARCH_AMD64)
        print("TMP:", irsb.next.tmp)

    def test_irexpr_get(self):
        m = pyvex.IRExpr.Get(0, "Ity_I64")
        assert m.type == "Ity_I64"

        self.assertRaises(Exception, pyvex.IRExpr.Get)

    def test_irexpr_qop(self):
        a = pyvex.IRExpr.Get(0, "Ity_I64")
        b = pyvex.IRExpr.Get(184, "Ity_I64")
        c = pyvex.IRExpr.RdTmp.get_instance(1)
        d = pyvex.IRExpr.RdTmp.get_instance(2)
        op = "Iop_QAdd32S"

        m = pyvex.IRExpr.Qop(op, [a, b, c, d])

        assert m.op == op
        assert m.args[1].type == b.type

        assert len(m.args) == 4
        assert m.args[2].tmp == c.tmp

    def test_irexpr_triop(self):
        a = pyvex.IRExpr.Get(0, "Ity_I64")
        b = pyvex.IRExpr.Get(184, "Ity_I64")
        c = pyvex.IRExpr.RdTmp.get_instance(1)
        op = "Iop_MAddF64"

        m = pyvex.IRExpr.Triop(op, [a, b, c])

        assert m.op == op
        assert m.args[1].type == b.type

        assert len(m.args) == 3
        assert m.args[2].tmp == c.tmp

    def test_irexpr_binop(self):
        a = pyvex.IRExpr.Get(0, "Ity_I64")
        c = pyvex.IRExpr.RdTmp.get_instance(1)
        op = "Iop_Add64"

        m = pyvex.IRExpr.Binop(op, [a, c])

        assert m.op == op
        assert m.args[1].tmp == c.tmp

        assert len(m.args) == 2
        assert m.args[1].tmp == c.tmp

    def test_irexpr_unop(self):
        a = pyvex.IRExpr.Get(0, "Ity_I64")
        op = "Iop_Add64"

        m = pyvex.IRExpr.Unop(op, [a])

        assert m.op == op
        assert len(m.args) == 1
        assert m.args[0].offset == a.offset

    def test_irexpr_load(self):
        a = pyvex.IRExpr.Get(0, "Ity_I64")
        e = "Iend_LE"
        t = "Ity_I64"

        m = pyvex.IRExpr.Load(e, t, a)

        assert m.endness == e
        assert m.type == t

    def test_irexpr_const(self):
        u1 = pyvex.IRConst.U1(1)
        f64 = pyvex.IRConst.F64(1.123)

        ue = pyvex.IRExpr.Const(u1)
        _ = pyvex.IRExpr.Const(f64)

        assert ue.con.value == u1.value
        assert ue.con.value != f64.value

    def test_irexpr_ite(self):
        a = pyvex.IRExpr.Get(0, "Ity_I64")
        iffalse = pyvex.IRExpr.RdTmp.get_instance(1)
        iftrue = pyvex.IRExpr.Const(pyvex.IRConst.U8(200))

        m = pyvex.IRExpr.ITE(a, iffalse, iftrue)

        assert m.iftrue.con.value == iftrue.con.value

    def test_irexpr_ccall(self):
        callee = pyvex.IRCallee(3, "test_name", 0xFFFFFF)
        args = [pyvex.IRExpr.RdTmp.get_instance(i) for i in range(10)]

        m = pyvex.IRExpr.CCall("Ity_I64", callee, args)

        assert len(m.args) == len(args)
        assert m.ret_type == "Ity_I64"

        for n, a in enumerate(m.args):
            assert a.tmp == args[n].tmp

        m = pyvex.IRExpr.CCall(callee, "Ity_I64", ())
        assert len(m.args) == 0


if __name__ == "__main__":
    unittest.main()
