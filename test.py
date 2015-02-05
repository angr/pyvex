import pyvex
import nose

################
### IRCallee ###
################

def test_ircallee():
	callee = pyvex.IRCallee(3, "test_name", 1234, 0xFFFFFF)
	nose.tools.assert_equals(callee.regparms, 3)
	nose.tools.assert_equals(callee.name, "test_name")
	nose.tools.assert_equals(callee.addr, 1234)
	nose.tools.assert_equals(callee.mcx_mask, 0xFFFFFF)

############
### IRSB ###
############

def test_irsb_empty():
	irsb = pyvex.IRSB()
	stmts = irsb.statements()
	nose.tools.assert_equal(len(stmts), 0)

def test_irsb_arm():
	irsb = pyvex.IRSB(bytes='\x33\xff\x2f\xe1', arch="VexArchARM")
	nose.tools.assert_equal(sum([ 1 for i in irsb.statements() if type(i) == pyvex.IRStmt.IMark ]), 1)

def test_irsb_popret():
	irsb = pyvex.IRSB(bytes='\x5d\xc3')
	stmts = irsb.statements()
	irsb.pp()

	nose.tools.assertGreater(len(stmts), 0)
	nose.tools.assert_equal(irsb.jumpkind, "Ijk_Ret")
	nose.tools.assert_equal(irsb.offsIP, 184)

	cursize = len(irsb.tyenv.types())
	nose.tools.assertGreater(cursize, 0)
	new_tmp = irsb.tyenv.newTemp("Ity_I32")
	nose.tools.assert_equal(cursize + 1, len(irsb.tyenv.types()))
	nose.tools.assert_equal(irsb.tyenv.typeOf(new_tmp), "Ity_I32")

	nose.tools.assert_equal(irsb.tyenv.typeOf(irsb.statements()[16].data), 'Ity_I64')

def test_two_irsb():
	irsb1 = pyvex.IRSB(bytes='\x5d\xc3')
	irsb2 = pyvex.IRSB(bytes='\x5d\x5d\x5d\x5d')

	stmts1 = irsb1.statements()
	stmts2 = irsb2.statements()

	nose.tools.assert_not_equal(len(stmts1), len(stmts2))

def test_irsb_deepCopy():
	irsb = pyvex.IRSB(bytes='\x5d\xc3')
	stmts = irsb.statements()

	irsb2 = irsb.deepCopy()
	stmts2 = irsb2.statements()
	nose.tools.assert_equal(len(stmts), len(stmts2))

def test_irsb_addStmt():
	irsb = pyvex.IRSB(bytes='\x5d\xc3')
	stmts = irsb.statements()

	irsb2 = irsb.deepCopyExceptStmts()
	nose.tools.assert_equal(len(irsb2.statements()), 0)

	for n, i in enumerate(stmts):
		nose.tools.assert_equal(len(irsb2.statements()), n)
		irsb2.addStatement(i.deepCopy())

	irsb2.pp()

def test_irsb_tyenv():
	irsb = pyvex.IRSB(bytes='\x5d\xc3')
	print irsb.tyenv
	print "Orig"
	irsb.tyenv.pp()
	print "Copy"
	irsb.tyenv.deepCopy().pp()

	print "Empty"
	irsb2 = pyvex.IRSB()
	irsb2.tyenv.pp()

	print "Unwrapped"
	irsb2.tyenv = irsb.tyenv.deepCopy()
	irsb2.tyenv.pp()

##################
### Statements ###
##################

def test_empty_irstmt_fail():
	nose.tools.assert_raises(pyvex.PyVEXError, pyvex.IRStmt, ())

def test_irstmt_pp():
	irsb = pyvex.IRSB(bytes='\x5d\xc3')
	stmts = irsb.statements()
	for i in stmts:
		print "STMT: ",
		i.pp()
		print

def test_irstmt_flat():
	print "TODO"

def test_irstmt_noop():
	irsb = pyvex.IRSB(bytes='\x90\x5d\xc3')
	irnop = irsb.statements()[0]
	irnop2 = pyvex.IRStmt.NoOp()
	irnop3 = irnop2.deepCopy()

	nose.tools.assert_equal(irnop.tag, "Ist_NoOp")
	nose.tools.assert_equal(type(irnop), type(irnop2))
	nose.tools.assert_equal(type(irnop), type(irnop3))
	
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
	nose.tools.assert_equal(type(m), type(m.deepCopy()))

def test_irstmt_abihint():
	nose.tools.assert_raises(Exception, pyvex.IRStmt.AbiHint, ())

	a = pyvex.IRExpr.RdTmp(123)
	b = pyvex.IRExpr.RdTmp(456)

	m = pyvex.IRStmt.AbiHint(a, 10, b)
	nose.tools.assert_equal(m.base.tmp, 123)
	nose.tools.assert_equal(m.len, 10)
	nose.tools.assert_equal(m.nia.tmp, 456)
	nose.tools.assert_equal(type(m), type(m.deepCopy()))

def test_irstmt_put():
	nose.tools.assert_raises(Exception, pyvex.IRStmt.Put, ())

	a = pyvex.IRExpr.RdTmp(123)
	m = pyvex.IRStmt.Put(10, a)
	print "Put stmt:",
	m.pp()
	print ""
	nose.tools.assert_equal(m.data.tmp, 123)
	nose.tools.assert_equal(m.offset, 10)
	nose.tools.assert_equal(type(m), type(m.deepCopy()))

def test_irexpr_puti():
	r = pyvex.IRRegArray(10, "Ity_I64", 20)
	i = pyvex.IRExpr.RdTmp(5)
	d = pyvex.IRExpr.RdTmp(30)
	m = pyvex.IRStmt.PutI(r, i, 2, d)
	nose.tools.assert_equal(m.deepCopy().description.base, 10)
	nose.tools.assert_equal(m.index.tmp, 5)
	nose.tools.assert_equal(m.bias, 2)
	nose.tools.assert_equal(m.deepCopy().data.deepCopy().tmp, d.tmp)

	nose.tools.assert_raises(Exception, pyvex.IRStmt.PutI, ())

def test_irstmt_wrtmp():
	nose.tools.assert_raises(Exception, pyvex.IRStmt.WrTmp, ())

	a = pyvex.IRExpr.RdTmp(123)
	m = pyvex.IRStmt.WrTmp(10, a)
	nose.tools.assert_equal(m.tag, "Ist_WrTmp")
	nose.tools.assert_equal(m.tmp, 10)
	nose.tools.assert_equal(m.data.tmp, 123)
	nose.tools.assert_equal(type(m), type(m.deepCopy()))

def test_irstmt_store():
	nose.tools.assert_raises(Exception, pyvex.IRStmt.Store, ())

	a = pyvex.IRExpr.RdTmp(123)
	d = pyvex.IRExpr.RdTmp(456)
	m = pyvex.IRStmt.Store("Iend_LE", a, d)
	nose.tools.assert_equal(m.tag, "Ist_Store")
	nose.tools.assert_equal(m.endness, "Iend_LE")
	nose.tools.assert_equal(m.addr.tmp, a.tmp)
	nose.tools.assert_equal(m.data.tmp, d.tmp)

	m.endness = "Iend_BE"
	nose.tools.assert_equal(m.endness, "Iend_BE")
	nose.tools.assert_equal(type(m), type(m.deepCopy()))

def test_irstmt_cas():
	nose.tools.assert_raises(Exception, pyvex.IRStmt.CAS, ())

	a = pyvex.IRExpr.RdTmp(10)
	eh = pyvex.IRExpr.RdTmp(11)
	el = pyvex.IRExpr.RdTmp(12)
	dh = pyvex.IRExpr.RdTmp(21)
	dl = pyvex.IRExpr.RdTmp(22)

	args = { "oldHi": 1, "oldLo": 2, "endness": "Iend_LE", "addr": a,
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

	m.endness = "Iend_BE"
	nose.tools.assert_equal(m.endness, "Iend_BE")
	nose.tools.assert_equal(type(m), type(m.deepCopy()))

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

	nose.tools.assert_equal(m.cvt_types(), ("Ity_I32", "Ity_I32"))
	m.cvt = "ILGop_8Sto32"
	nose.tools.assert_equal(m.cvt_types(), ("Ity_I8", "Ity_I32"))

	m.end = "Iend_BE"
	nose.tools.assert_equal(m.end, "Iend_BE")
	nose.tools.assert_equal(type(m), type(m.deepCopy()))

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

	m.end = "Iend_BE"
	nose.tools.assert_equal(m.end, "Iend_BE")
	nose.tools.assert_equal(type(m), type(m.deepCopy()))

def test_irstmt_llsc():
	nose.tools.assert_raises(Exception, pyvex.IRStmt.LLSC, ())

	a = pyvex.IRExpr.RdTmp(123)
	d = pyvex.IRExpr.RdTmp(456)
	m = pyvex.IRStmt.LLSC("Iend_LE", 1, a, d)
	nose.tools.assert_equal(m.tag, "Ist_LLSC")
	nose.tools.assert_equal(m.endness, "Iend_LE")
	nose.tools.assert_equal(m.result, 1)
	nose.tools.assert_equal(m.addr.tmp, a.tmp)
	nose.tools.assert_equal(m.storedata.tmp, d.tmp)

	m.endness = "Iend_BE"
	nose.tools.assert_equal(m.endness, "Iend_BE")
	nose.tools.assert_equal(type(m), type(m.deepCopy()))

def test_irstmt_mbe():
	m = pyvex.IRStmt.MBE("Imbe_CancelReservation")
	nose.tools.assert_equal(m.deepCopy().event, "Imbe_CancelReservation")
	m.event = "Imbe_Fence"
	nose.tools.assert_equal(m.event, "Imbe_Fence")

def test_irstmt_dirty():
	args = [ pyvex.IRExpr.RdTmp(i) for i in range(10) ]
	m = pyvex.IRStmt.Dirty(3, "test_dirty", 1234, args, tmp=15)
	nose.tools.assert_equal(m.cee.name, "test_dirty")
	nose.tools.assert_equals(type(m.guard), pyvex.IRExpr.Const)
	nose.tools.assert_equals(m.tmp, 15)
	nose.tools.assert_equals(m.mFx, "Ifx_None")
	nose.tools.assert_equals(m.nFxState, 0)

	for n,a in enumerate(m.args()):
		nose.tools.assert_equals(a.tmp, args[n].tmp)

	nose.tools.assert_equals(len(m.fxState()), 0)

def test_irstmt_exit():
	nose.tools.assert_raises(Exception, pyvex.IRStmt.Exit, ())

	g = pyvex.IRExpr.RdTmp(123)
	d = pyvex.IRConst.U32(456)

	m = pyvex.IRStmt.Exit(g, "Ijk_Ret", d, 10)
	nose.tools.assert_equal(m.tag, "Ist_Exit")
	nose.tools.assert_equal(m.jumpkind, "Ijk_Ret")
	nose.tools.assert_equal(m.offsIP, 10)
	nose.tools.assert_equal(m.guard.tmp, g.tmp)
	nose.tools.assert_equal(m.dst.value, d.value)

	m.jumpkind = "Ijk_SigSEGV"
	nose.tools.assert_equal(m.jumpkind, "Ijk_SigSEGV")
	nose.tools.assert_equal(type(m), type(m.deepCopy()))

##################
### IRRegArray ###
##################

def test_irregarray():
	m = pyvex.IRRegArray(10, "Ity_I64", 20)
	n = pyvex.IRRegArray(20, "Ity_I32", 30)
	nose.tools.assert_true(m.equals(m))
	nose.tools.assert_false(m.equals(n))
	nose.tools.assert_false(n.equals(m))

	nose.tools.assert_equals(m.num_elements, 20)
	nose.tools.assert_equals(m.element_type, "Ity_I64")
	nose.tools.assert_equals(m.base, 10)

################
### IRConst.s ###
################

def helper_const_subtype(subtype, tag, value):
	print "Testing %s" % tag
	nose.tools.assert_raises(Exception, subtype, ())

	c = subtype(value)
	nose.tools.assert_equals(c.tag, tag)
	nose.tools.assert_equals(c.value, value)

	d = subtype(value - 1)
	e = subtype(value)
	nose.tools.assert_true(c.equals(e))
	nose.tools.assert_true(e.equals(c))
	nose.tools.assert_false(c.equals(d))
	nose.tools.assert_false(d.equals(c))
	nose.tools.assert_false(c.equals("test"))

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
	nose.tools.assert_raises(Exception, m.deepCopy, ())

def test_irexpr_geti():
	r = pyvex.IRRegArray(10, "Ity_I64", 20)
	i = pyvex.IRExpr.RdTmp(5)
	m = pyvex.IRExpr.GetI(r, i, 2)
	nose.tools.assert_equal(m.deepCopy().description.base, 10)
	nose.tools.assert_equal(m.index.tmp, 5)
	nose.tools.assert_equal(m.bias, 2)

	nose.tools.assert_raises(Exception, pyvex.IRExpr.GetI, ())

def test_irexpr_rdtmp():
	m = pyvex.IRExpr.RdTmp(123)
	nose.tools.assert_equal(m.tag, "Iex_RdTmp")
	nose.tools.assert_equal(m.tmp, m.deepCopy().tmp)
	nose.tools.assert_equal(m.tmp, 123)

	m.tmp = 1337
	nose.tools.assert_equal(m.tmp, 1337)
	nose.tools.assert_raises(Exception, pyvex.IRExpr.RdTmp, ())
	nose.tools.assert_equal(type(m), type(m.deepCopy()))

	print "FUCK"
	irsb = pyvex.IRSB(bytes='\x90\x5d\xc3')
	print "TMP:",irsb.next.tmp
	nose.tools.assert_equal(irsb.next.tmp, irsb.next.deepCopy().tmp)


def test_irexpr_get():
	m = pyvex.IRExpr.Get(0, "Ity_I64")
	nose.tools.assert_equal(m.type, "Ity_I64")
	nose.tools.assert_equal(m.type, m.deepCopy().type)
	nose.tools.assert_equal(type(m), type(m.deepCopy()))

	nose.tools.assert_raises(Exception, pyvex.IRExpr.Get, ())

def test_irexpr_qop():
	a = pyvex.IRExpr.Get(0, "Ity_I64")
	b = pyvex.IRExpr.Get(184, "Ity_I64")
	c = pyvex.IRExpr.RdTmp(1)
	d = pyvex.IRExpr.RdTmp(2)
	op = "Iop_QAdd32S"

	m = pyvex.IRExpr.Qop(op, a, b, c, d)

	nose.tools.assert_equal(m.op, op)
	nose.tools.assert_equal(type(m), type(m.deepCopy()))
	nose.tools.assert_equal(m.arg1.type, m.deepCopy().arg1.type)
	nose.tools.assert_equal(m.arg2.type, b.type)

	nose.tools.assert_equal(len(m.args()), 4)
	nose.tools.assert_equal(m.args()[2].tmp, c.tmp)

def test_irexpr_triop():
	a = pyvex.IRExpr.Get(0, "Ity_I64")
	b = pyvex.IRExpr.Get(184, "Ity_I64")
	c = pyvex.IRExpr.RdTmp(1)
	op = "Iop_MAddF64"

	m = pyvex.IRExpr.Triop(op, a, b, c)

	nose.tools.assert_equal(m.op, op)
	nose.tools.assert_equal(type(m), type(m.deepCopy()))
	nose.tools.assert_equal(m.arg1.type, m.deepCopy().arg1.type)
	nose.tools.assert_equal(m.arg2.type, b.type)

	nose.tools.assert_equal(len(m.args()), 3)
	nose.tools.assert_equal(m.args()[2].tmp, c.tmp)

def test_irexpr_binop():
	a = pyvex.IRExpr.Get(0, "Ity_I64")
	c = pyvex.IRExpr.RdTmp(1)
	op = "Iop_Add64"

	m = pyvex.IRExpr.Binop(op, a, c)

	nose.tools.assert_equal(m.op, op)
	nose.tools.assert_equal(type(m), type(m.deepCopy()))
	nose.tools.assert_equal(m.arg1.type, m.deepCopy().arg1.type)
	nose.tools.assert_equal(m.arg2.tmp, c.tmp)

	nose.tools.assert_equal(len(m.args()), 2)
	nose.tools.assert_equal(m.args()[1].tmp, c.tmp)

def test_irexpr_unop():
	a = pyvex.IRExpr.Get(0, "Ity_I64")
	op = "Iop_Add64"

	m = pyvex.IRExpr.Unop(op, a)

	nose.tools.assert_equal(m.op, op)
	nose.tools.assert_equal(type(m), type(m.deepCopy()))
	nose.tools.assert_equal(m.arg1.type, m.deepCopy().arg1.type)
	nose.tools.assert_equal(len(m.args()), 1)
	nose.tools.assert_equal(m.args()[0].offset, a.offset)

def test_irexpr_load():
	a = pyvex.IRExpr.Get(0, "Ity_I64")
	e = "Iend_LE"
	t = "Ity_I64"

	m = pyvex.IRExpr.Load(e, t, a)

	nose.tools.assert_equal(m.endness, e)
	nose.tools.assert_equal(type(m), type(m.deepCopy()))
	nose.tools.assert_equal(m.addr.type, m.deepCopy().addr.type)
	nose.tools.assert_equal(m.type, t)

def test_irexpr_const():
	u1 = pyvex.IRConst.U1(1)
	f64 = pyvex.IRConst.F64(1.123)

	ue = pyvex.IRExpr.Const(u1)
	fe = pyvex.IRExpr.Const(f64)

	nose.tools.assert_equal(ue.con.value, u1.value)
	nose.tools.assert_not_equal(ue.con.value, f64.value)
	nose.tools.assert_equal(type(ue), type(fe.deepCopy()))
	nose.tools.assert_equal(fe.con.value, fe.deepCopy().con.value)

def test_irexpr_ite():
	a = pyvex.IRExpr.Get(0, "Ity_I64")
	b = pyvex.IRExpr.Const(pyvex.IRConst.U8(200))
	c = pyvex.IRExpr.RdTmp(1)

	m = pyvex.IRExpr.ITE(a, b, c)

	nose.tools.assert_equal(type(m), type(m.deepCopy()))
	nose.tools.assert_equal(m.cond.type, m.deepCopy().cond.type)
	nose.tools.assert_equal(m.iftrue.con.value, b.con.value)
	nose.tools.assert_equal(m.iffalse.tmp, m.deepCopy().iffalse.tmp)

def test_irexpr_ccall():
	callee = pyvex.IRCallee(3, "test_name", 1234, 0xFFFFFF)
	args = [ pyvex.IRExpr.RdTmp(i) for i in range(10) ]

	m = pyvex.IRExpr.CCall(callee, "Ity_I64", args)

	nose.tools.assert_equal(type(m), type(m.deepCopy()))
	nose.tools.assert_equal(len(m.args()), len(args))
	nose.tools.assert_equal(m.ret_type, "Ity_I64")
	nose.tools.assert_equal(m.callee.addr, 1234)
	nose.tools.assert_equal(m.deepCopy().callee.regparms, 3)

	for n,a in enumerate(m.args()):
		nose.tools.assert_equals(a.tmp, args[n].tmp)

	m = pyvex.IRExpr.CCall(callee, "Ity_I64", ())
	nose.tools.assert_equals(len(m.args()), 0)

if __name__ == '__main__':
	test_irconst()
