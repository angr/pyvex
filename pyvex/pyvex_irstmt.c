// This code is GPLed by Yan Shoshitaishvili

#include <Python.h>
#include <structmember.h>
#include <libvex.h>

#include "pyvex_enums.h"
#include "pyvex_types.h"
#include "pyvex_macros.h"
#include "pyvex_logging.h"

#ifdef PYVEX_STATIC
	#include "pyvex_static.h"
	#include "pyvex_deepcopy.h"
#endif


///////////////////////
// IRStmt base class //
///////////////////////

PYMARE_NEW(IRStmt)
PYMARE_DEALLOC(IRStmt)
PYVEX_METH_STANDARD(IRStmt)

static int
pyIRStmt_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYMARE_WRAP_CONSTRUCTOR(IRStmt);
	PyErr_SetString(PyVEXError, "Base IRStmt creation not supported.");
	return -1;
}

PYMARE_ACCESSOR_WRAPPED(IRStmt, IRStmt, self->wrapped, wrapped, IRStmt)
PYMARE_ACCESSOR_ENUM(IRStmt, IRStmt, self->wrapped->tag, tag, IRStmtTag)

static PyGetSetDef pyIRStmt_getseters[] =
{
	PYMARE_ACCESSOR_DEF(IRStmt, wrapped),
	PYMARE_ACCESSOR_DEF(IRStmt, tag),
	{NULL}
};

static PyObject *pyIRStmt_flat(pyIRStmt* self)
{
	if (isFlatIRStmt(self->wrapped)) { Py_RETURN_TRUE; }
	Py_RETURN_FALSE;
}

static PyMethodDef pyIRStmt_methods[] =
{
	PYVEX_METHDEF_STANDARD(IRStmt),
	{"flat", (PyCFunction)pyIRStmt_flat, METH_NOARGS, "Returns true if IRStmt is flat, false otherwise."},
	{NULL}
};

static PyMemberDef pyIRStmt_members[] = { {NULL} };
PYMARE_TYPEOBJECT("pyvex", IRStmt);

// wrap functionality
PyObject *wrap_IRStmt(IRStmt *i)
{
	PyTypeObject *t = NULL;

	switch (i->tag)
	{
		PYVEX_WRAPCASE(IRStmt, Ist_, NoOp)
		PYVEX_WRAPCASE(IRStmt, Ist_, IMark)
		PYVEX_WRAPCASE(IRStmt, Ist_, AbiHint)
		PYVEX_WRAPCASE(IRStmt, Ist_, Put)
		PYVEX_WRAPCASE(IRStmt, Ist_, PutI)
		PYVEX_WRAPCASE(IRStmt, Ist_, WrTmp)
		PYVEX_WRAPCASE(IRStmt, Ist_, Store)
		PYVEX_WRAPCASE(IRStmt, Ist_, CAS)
		PYVEX_WRAPCASE(IRStmt, Ist_, LLSC)
		PYVEX_WRAPCASE(IRStmt, Ist_, Dirty)
		PYVEX_WRAPCASE(IRStmt, Ist_, MBE)
		PYVEX_WRAPCASE(IRStmt, Ist_, Exit)
		PYVEX_WRAPCASE(IRStmt, Ist_, LoadG)
		PYVEX_WRAPCASE(IRStmt, Ist_, StoreG)
		default:
			error("PyVEX: Unknown/unsupported IRStmtTag %s\n", IRStmtTag_to_str(i->tag));
			t = &pyIRStmtType;
	}

	PyObject *args = Py_BuildValue("");
	PyObject *kwargs = Py_BuildValue("{s:O}", "wrap", PyCapsule_New(i, "IRStmt", NULL));
	PyObject *o = PyObject_Call((PyObject *)t, args, kwargs);
	Py_DECREF(args); Py_DECREF(kwargs);
	return (PyObject *)o;
}

/////////////////
// NoOp IRStmt //
/////////////////

static int
pyIRStmtNoOp_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	if (!kwargs) { self->wrapped = PYVEX_COPYOUT(IRStmt, IRStmt_NoOp()); return 0; }
	PYMARE_WRAP_CONSTRUCTOR(IRStmt);

	PyErr_SetString(PyVEXError, "Unexpected arguments provided to constructor.");
	return -1;
}

static PyMethodDef pyIRStmtNoOp_methods[] = { {NULL} };
static PyGetSetDef pyIRStmtNoOp_getseters[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(NoOp, IRStmt);

//////////////////
// IMark IRStmt //
//////////////////

static int
pyIRStmtIMark_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYMARE_WRAP_CONSTRUCTOR(IRStmt);

	Addr64 addr;
	Int len;
	UChar delta;

	static char *kwlist[] = {"addr", "len", "delta", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "Kib", kwlist, &addr, &len, &delta)) return -1;

	self->wrapped = PYVEX_COPYOUT(IRStmt, IRStmt_IMark(addr, len, delta));
	return 0;
}

PYMARE_ACCESSOR_BUILDVAL(IRStmtIMark, IRStmt, self->wrapped->Ist.IMark.addr, addr, "K")
PYMARE_ACCESSOR_BUILDVAL(IRStmtIMark, IRStmt, self->wrapped->Ist.IMark.len, len, "i")
PYMARE_ACCESSOR_BUILDVAL(IRStmtIMark, IRStmt, self->wrapped->Ist.IMark.delta, delta, "b")

static PyGetSetDef pyIRStmtIMark_getseters[] =
{
	PYMARE_ACCESSOR_DEF(IRStmtIMark, addr),
	PYMARE_ACCESSOR_DEF(IRStmtIMark, len),
	PYMARE_ACCESSOR_DEF(IRStmtIMark, delta),
	{NULL}
};

static PyMethodDef pyIRStmtIMark_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(IMark, IRStmt);

////////////////////
// AbiHint IRStmt //
////////////////////

static int
pyIRStmtAbiHint_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYMARE_WRAP_CONSTRUCTOR(IRStmt);

	pyIRExpr *base;
	Int len;
	pyIRExpr *nia;

	static char *kwlist[] = {"base", "len", "nia", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OiO", kwlist, &base, &len, &nia)) return -1;
	PYMARE_CHECKTYPE(base, pyIRExprType, return -1)
	PYMARE_CHECKTYPE(nia, pyIRExprType, return -1)

	self->wrapped = PYVEX_COPYOUT(IRStmt, IRStmt_AbiHint(base->wrapped, len, nia->wrapped));
	return 0;
}

PYMARE_ACCESSOR_WRAPPED(IRStmtAbiHint, IRStmt, self->wrapped->Ist.AbiHint.base, base, IRExpr)
PYMARE_ACCESSOR_BUILDVAL(IRStmtAbiHint, IRStmt, self->wrapped->Ist.AbiHint.len, len, "i")
PYMARE_ACCESSOR_WRAPPED(IRStmtAbiHint, IRStmt, self->wrapped->Ist.AbiHint.nia, nia, IRExpr)

static PyGetSetDef pyIRStmtAbiHint_getseters[] =
{
	PYMARE_ACCESSOR_DEF(IRStmtAbiHint, base),
	PYMARE_ACCESSOR_DEF(IRStmtAbiHint, len),
	PYMARE_ACCESSOR_DEF(IRStmtAbiHint, nia),
	{NULL}
};

static PyMethodDef pyIRStmtAbiHint_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(AbiHint, IRStmt);

////////////////
// Put IRStmt //
////////////////

static int
pyIRStmtPut_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYMARE_WRAP_CONSTRUCTOR(IRStmt);

	Int offset;
	pyIRExpr *data;

	static char *kwlist[] = {"offset", "data", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "iO", kwlist, &offset, &data)) return -1;
	PYMARE_CHECKTYPE(data, pyIRExprType, return -1)

	self->wrapped = PYVEX_COPYOUT(IRStmt, IRStmt_Put(offset, data->wrapped));
	return 0;
}

PYMARE_ACCESSOR_BUILDVAL(IRStmtPut, IRStmt, self->wrapped->Ist.Put.offset, offset, "i")
PYMARE_ACCESSOR_WRAPPED(IRStmtPut, IRStmt, self->wrapped->Ist.Put.data, data, IRExpr)

static PyGetSetDef pyIRStmtPut_getseters[] =
{
	PYMARE_ACCESSOR_DEF(IRStmtPut, offset),
	PYMARE_ACCESSOR_DEF(IRStmtPut, data),
	{NULL}
};

static PyMethodDef pyIRStmtPut_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(Put, IRStmt);

/////////////////
// PutI IRStmt //
/////////////////

static int
pyIRStmtPutI_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYMARE_WRAP_CONSTRUCTOR(IRStmt);

	pyIRRegArray *descr;
	pyIRExpr *ix;
	Int bias;
	pyIRExpr *data;

	static char *kwlist[] = {"description", "index", "bias", "data", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OOiO", kwlist, &descr, &ix, &bias, &data)) return -1;
	PYMARE_CHECKTYPE(descr, pyIRRegArrayType, return -1)
	PYMARE_CHECKTYPE(ix, pyIRExprType, return -1)
	PYMARE_CHECKTYPE(data, pyIRExprType, return -1)

	self->wrapped = PYVEX_COPYOUT(IRStmt, IRStmt_PutI(mkIRPutI(descr->wrapped, ix->wrapped, bias, data->wrapped)));
	return 0;
}

PYMARE_ACCESSOR_WRAPPED(IRStmtPutI, IRStmt, self->wrapped->Ist.PutI.details->descr, description, IRRegArray)
PYMARE_ACCESSOR_WRAPPED(IRStmtPutI, IRStmt, self->wrapped->Ist.PutI.details->ix, index, IRExpr)
PYMARE_ACCESSOR_BUILDVAL(IRStmtPutI, IRStmt, self->wrapped->Ist.PutI.details->bias, bias, "i")
PYMARE_ACCESSOR_WRAPPED(IRStmtPutI, IRStmt, self->wrapped->Ist.PutI.details->data, data, IRExpr)

static PyGetSetDef pyIRStmtPutI_getseters[] =
{
	PYMARE_ACCESSOR_DEF(IRStmtPutI, description),
	PYMARE_ACCESSOR_DEF(IRStmtPutI, index),
	PYMARE_ACCESSOR_DEF(IRStmtPutI, bias),
	PYMARE_ACCESSOR_DEF(IRStmtPutI, data),
	{NULL}
};

static PyMethodDef pyIRStmtPutI_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(PutI, IRStmt);

//////////////////
// WrTmp IRStmt //
//////////////////

static int
pyIRStmtWrTmp_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYMARE_WRAP_CONSTRUCTOR(IRStmt);

	IRTemp tmp;
	pyIRExpr *data;

	static char *kwlist[] = {"tmp", "data", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "IO", kwlist, &tmp, &data)) return -1;
	PYMARE_CHECKTYPE(data, pyIRExprType, return -1)

	self->wrapped = PYVEX_COPYOUT(IRStmt, IRStmt_WrTmp(tmp, data->wrapped));
	return 0;
}

PYMARE_ACCESSOR_BUILDVAL(IRStmtWrTmp, IRStmt, self->wrapped->Ist.WrTmp.tmp, tmp, "i")
PYMARE_ACCESSOR_WRAPPED(IRStmtWrTmp, IRStmt, self->wrapped->Ist.WrTmp.data, data, IRExpr)

static PyGetSetDef pyIRStmtWrTmp_getseters[] =
{
	PYMARE_ACCESSOR_DEF(IRStmtWrTmp, tmp),
	PYMARE_ACCESSOR_DEF(IRStmtWrTmp, data),
	{NULL}
};

static PyMethodDef pyIRStmtWrTmp_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(WrTmp, IRStmt);

//////////////////
// Store IRStmt //
//////////////////

static int
pyIRStmtStore_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYMARE_WRAP_CONSTRUCTOR(IRStmt);

	IREndness endness;
	char *endness_str;
	pyIRExpr *addr;
	pyIRExpr *data;

	static char *kwlist[] = {"endness", "addr", "data", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "sOO", kwlist, &endness_str, &addr, &data)) return -1;
	PYMARE_CHECKTYPE(addr, pyIRExprType, return -1)
	PYMARE_CHECKTYPE(data, pyIRExprType, return -1)
	PYMARE_ENUM_FROMSTR(IREndness, endness, endness_str, return -1);

	self->wrapped = PYVEX_COPYOUT(IRStmt, IRStmt_Store(endness, addr->wrapped, data->wrapped));
	return 0;
}

PYMARE_ACCESSOR_ENUM(IRStmtStore, IRStmt, self->wrapped->Ist.Store.end, endness, IREndness)
PYMARE_ACCESSOR_WRAPPED(IRStmtStore, IRStmt, self->wrapped->Ist.Store.addr, addr, IRExpr)
PYMARE_ACCESSOR_WRAPPED(IRStmtStore, IRStmt, self->wrapped->Ist.Store.data, data, IRExpr)

static PyGetSetDef pyIRStmtStore_getseters[] =
{
	PYMARE_ACCESSOR_DEF(IRStmtStore, endness),
	PYMARE_ACCESSOR_DEF(IRStmtStore, addr),
	PYMARE_ACCESSOR_DEF(IRStmtStore, data),
	{NULL}
};

static PyMethodDef pyIRStmtStore_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(Store, IRStmt);

////////////////
// CAS IRStmt //
////////////////

static int
pyIRStmtCAS_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYMARE_WRAP_CONSTRUCTOR(IRStmt);

	IRTemp oldHi;
	IRTemp oldLo;
	IREndness endness;
	char *endness_str;
	pyIRExpr *addr;
	pyIRExpr *expdHi;
	pyIRExpr *expdLo;
	pyIRExpr *dataHi;
	pyIRExpr *dataLo;

	static char *kwlist[] = {"oldHi", "oldLo", "endness", "addr", "expdHi", "expdLo", "dataHi", "dataLo", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "IIsOOOOO", kwlist, &oldHi, &oldLo, &endness_str, &addr, &expdHi, &expdLo,
				&dataHi, &dataLo)) return -1;
	PYMARE_CHECKTYPE(expdHi, pyIRExprType, return -1)
	PYMARE_CHECKTYPE(expdLo, pyIRExprType, return -1)
	PYMARE_CHECKTYPE(dataHi, pyIRExprType, return -1)
	PYMARE_CHECKTYPE(dataLo, pyIRExprType, return -1)
	PYMARE_ENUM_FROMSTR(IREndness, endness, endness_str, return -1);

	self->wrapped = PYVEX_COPYOUT(IRStmt, IRStmt_CAS(mkIRCAS(oldHi, oldLo, endness, addr->wrapped, expdHi->wrapped, expdLo->wrapped, dataHi->wrapped, dataLo->wrapped)));
	return 0;
}

PYMARE_ACCESSOR_BUILDVAL(IRStmtCAS, IRStmt, self->wrapped->Ist.CAS.details->oldHi, oldHi, "i")
PYMARE_ACCESSOR_BUILDVAL(IRStmtCAS, IRStmt, self->wrapped->Ist.CAS.details->oldLo, oldLo, "i")
PYMARE_ACCESSOR_ENUM(IRStmtCAS, IRStmt, self->wrapped->Ist.CAS.details->end, endness, IREndness)
PYMARE_ACCESSOR_ENUM(IRStmtCAS, IRStmt, self->wrapped->Ist.CAS.details->end, end, IREndness)
PYMARE_ACCESSOR_WRAPPED(IRStmtCAS, IRStmt, self->wrapped->Ist.CAS.details->addr, addr, IRExpr)
PYMARE_ACCESSOR_WRAPPED(IRStmtCAS, IRStmt, self->wrapped->Ist.CAS.details->expdHi, expdHi, IRExpr)
PYMARE_ACCESSOR_WRAPPED(IRStmtCAS, IRStmt, self->wrapped->Ist.CAS.details->expdLo, expdLo, IRExpr)
PYMARE_ACCESSOR_WRAPPED(IRStmtCAS, IRStmt, self->wrapped->Ist.CAS.details->dataHi, dataHi, IRExpr)
PYMARE_ACCESSOR_WRAPPED(IRStmtCAS, IRStmt, self->wrapped->Ist.CAS.details->dataLo, dataLo, IRExpr)

static PyGetSetDef pyIRStmtCAS_getseters[] =
{
	PYMARE_ACCESSOR_DEF(IRStmtCAS, oldHi),
	PYMARE_ACCESSOR_DEF(IRStmtCAS, oldLo),
	PYMARE_ACCESSOR_DEF(IRStmtCAS, endness),
	PYMARE_ACCESSOR_DEF(IRStmtCAS, end),
	PYMARE_ACCESSOR_DEF(IRStmtCAS, addr),
	PYMARE_ACCESSOR_DEF(IRStmtCAS, expdHi),
	PYMARE_ACCESSOR_DEF(IRStmtCAS, expdLo),
	PYMARE_ACCESSOR_DEF(IRStmtCAS, dataHi),
	PYMARE_ACCESSOR_DEF(IRStmtCAS, dataLo),
	{NULL}
};

static PyMethodDef pyIRStmtCAS_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(CAS, IRStmt);

/////////////////
// LLSC IRStmt //
/////////////////

static int
pyIRStmtLLSC_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYMARE_WRAP_CONSTRUCTOR(IRStmt);

	IREndness endness;
	char *endness_str;
	IRTemp result;
	pyIRExpr *addr;
	pyIRExpr *storedata;

	static char *kwlist[] = {"endness", "result", "addr", "storedata", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "sIOO", kwlist, &endness_str, &result, &addr, &storedata)) return -1;
	PYMARE_CHECKTYPE(addr, pyIRExprType, return -1)
	PYMARE_CHECKTYPE(storedata, pyIRExprType, return -1)
	PYMARE_ENUM_FROMSTR(IREndness, endness, endness_str, return -1);

	self->wrapped = PYVEX_COPYOUT(IRStmt, IRStmt_LLSC(endness, result, addr->wrapped, storedata->wrapped));
	return 0;
}

PYMARE_ACCESSOR_BUILDVAL(IRStmtLLSC, IRStmt, self->wrapped->Ist.LLSC.result, result, "i")
PYMARE_ACCESSOR_ENUM(IRStmtLLSC, IRStmt, self->wrapped->Ist.LLSC.end, endness, IREndness)
PYMARE_ACCESSOR_WRAPPED(IRStmtLLSC, IRStmt, self->wrapped->Ist.LLSC.addr, addr, IRExpr)
PYMARE_ACCESSOR_WRAPPED(IRStmtLLSC, IRStmt, self->wrapped->Ist.LLSC.storedata, storedata, IRExpr)

static PyGetSetDef pyIRStmtLLSC_getseters[] =
{
	PYMARE_ACCESSOR_DEF(IRStmtLLSC, endness),
	PYMARE_ACCESSOR_DEF(IRStmtLLSC, result),
	PYMARE_ACCESSOR_DEF(IRStmtLLSC, addr),
	PYMARE_ACCESSOR_DEF(IRStmtLLSC, storedata),
	{NULL}
};

static PyMethodDef pyIRStmtLLSC_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(LLSC, IRStmt);

/////////////////
// MBE IRStmt //
/////////////////

static int
pyIRStmtMBE_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYMARE_WRAP_CONSTRUCTOR(IRStmt);

	IRMBusEvent mb; char *mb_str;

	static char *kwlist[] = {"jumpkind", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", kwlist, &mb_str)) return -1;
	PYMARE_ENUM_FROMSTR(IRMBusEvent, mb, mb_str, return -1);

	self->wrapped = PYVEX_COPYOUT(IRStmt, IRStmt_MBE(mb));
	return 0;
}

PYMARE_ACCESSOR_ENUM(IRStmtMBE, IRStmt, self->wrapped->Ist.MBE.event, event, IRMBusEvent)

static PyGetSetDef pyIRStmtMBE_getseters[] =
{
	PYMARE_ACCESSOR_DEF(IRStmtMBE, event),
	{NULL}
};

static PyMethodDef pyIRStmtMBE_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(MBE, IRStmt);

/////////////////
// Exit IRStmt //
/////////////////

static int
pyIRStmtExit_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYMARE_WRAP_CONSTRUCTOR(IRStmt);

	pyIRExpr *guard;
	pyIRConst *dst;
	IRJumpKind jk; char *jk_str;
	int offsIP;

	static char *kwlist[] = {"guard", "jumpkind", "dst", "offsIP", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OsOi", kwlist, &guard, &jk_str, &dst, &offsIP)) return -1;
	PYMARE_CHECKTYPE(guard, pyIRExprType, return -1)
	PYMARE_CHECKTYPE(dst, pyIRConstType, return -1)
	PYMARE_ENUM_FROMSTR(IRJumpKind, jk, jk_str, return -1);

	self->wrapped = PYVEX_COPYOUT(IRStmt, IRStmt_Exit(guard->wrapped, jk, dst->wrapped, offsIP));
	return 0;
}

PYMARE_ACCESSOR_WRAPPED(IRStmtExit, IRStmt, self->wrapped->Ist.Exit.guard, guard, IRExpr)
PYMARE_ACCESSOR_WRAPPED(IRStmtExit, IRStmt, self->wrapped->Ist.Exit.dst, dst, IRConst)
PYMARE_ACCESSOR_ENUM(IRStmtExit, IRStmt, self->wrapped->Ist.Exit.jk, jumpkind, IRJumpKind)
PYMARE_ACCESSOR_BUILDVAL(IRStmtExit, IRStmt, self->wrapped->Ist.Exit.offsIP, offsIP, "i")

static PyGetSetDef pyIRStmtExit_getseters[] =
{
	PYMARE_ACCESSOR_DEF(IRStmtExit, guard),
	PYMARE_ACCESSOR_DEF(IRStmtExit, dst),
	PYMARE_ACCESSOR_DEF(IRStmtExit, jumpkind),
	PYMARE_ACCESSOR_DEF(IRStmtExit, offsIP),
	{NULL}
};

static PyMethodDef pyIRStmtExit_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(Exit, IRStmt);

//////////////////
// Dirty IRStmt //
//////////////////

static int
pyIRStmtDirty_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYMARE_WRAP_CONSTRUCTOR(IRStmt);

	IRTemp dest;
	Int regparms;
	const char *name;
	unsigned long long addr;
	PyObject *args_seq;

	static char *kwlist[] = {"regparms", "name", "addr", "args", "tmp", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "isKO|I", kwlist, &regparms, &name, &addr, &args_seq, &dest)) return -1;
	if (!PySequence_Check(args_seq)) { PyErr_SetString(PyVEXError, "need sequence of args for Dirty"); return -1; }

	int seq_size = PySequence_Size(args_seq);
	IRExpr **cargs = (IRExpr **) malloc((seq_size + 1) * sizeof(IRExpr *));
	int i;
	for (i = 0; i < seq_size; i++)
	{
		pyIRExpr *expr = (pyIRExpr *)PySequence_GetItem(args_seq, i);
		PYMARE_CHECKTYPE(expr, pyIRExprType, return -1);
		cargs[i] = expr->wrapped;
	}
        cargs[i] = NULL;

        IRDirty *dirty;
        if (PyDict_GetItemString(kwargs, "tmp")) dirty = PYVEX_COPYOUT(IRDirty, unsafeIRDirty_1_N(dest, regparms, (char*) name, (void *)addr, cargs));
        else dirty = unsafeIRDirty_0_N(regparms, (char*)name, (void *)addr, cargs);

	self->wrapped = PYVEX_COPYOUT(IRStmt, IRStmt_Dirty(dirty));
	return 0;
}

PYMARE_ACCESSOR_WRAPPED(IRStmtDirty, IRStmt, self->wrapped->Ist.Dirty.details->cee, cee, IRCallee)
PYMARE_ACCESSOR_WRAPPED(IRStmtDirty, IRStmt, self->wrapped->Ist.Dirty.details->guard, guard, IRExpr)
PYMARE_ACCESSOR_BUILDVAL(IRStmtDirty, IRStmt, self->wrapped->Ist.Dirty.details->tmp, tmp, "I")
PYMARE_ACCESSOR_ENUM(IRStmtDirty, IRStmt, self->wrapped->Ist.Dirty.details->mFx, mFx, IREffect)
PYMARE_ACCESSOR_WRAPPED(IRStmtDirty, IRStmt, self->wrapped->Ist.Dirty.details->mAddr, mAddr, IRExpr)
PYMARE_ACCESSOR_BUILDVAL(IRStmtDirty, IRStmt, self->wrapped->Ist.Dirty.details->mSize, mSize, "I")
PYMARE_ACCESSOR_BUILDVAL(IRStmtDirty, IRStmt, self->wrapped->Ist.Dirty.details->nFxState, nFxState, "i")

static PyGetSetDef pyIRStmtDirty_getseters[] =
{
	PYMARE_ACCESSOR_DEF(IRStmtDirty, cee),
	PYMARE_ACCESSOR_DEF(IRStmtDirty, guard),
	PYMARE_ACCESSOR_DEF(IRStmtDirty, tmp),
	PYMARE_ACCESSOR_DEF(IRStmtDirty, mFx),
	PYMARE_ACCESSOR_DEF(IRStmtDirty, mAddr),
	PYMARE_ACCESSOR_DEF(IRStmtDirty, mSize),
	PYMARE_ACCESSOR_DEF(IRStmtDirty, nFxState),
	{NULL}
};

PyObject *pyIRStmtDirty_args(pyIRStmt* self)
{
	int size; for (size = 0; self->wrapped->Ist.Dirty.details->args[size] != NULL; size++);

	PyObject *result = PyTuple_New(size);
	for (int i = 0; i < size; i++)
	{
		PyObject *wrapped = wrap_IRExpr(self->wrapped->Ist.Dirty.details->args[i]);
		PyTuple_SetItem(result, i, wrapped);
	}
	return result;
}

PyObject *pyIRStmtDirty_fxState(pyIRStmt* self)
{
	int size = self->wrapped->Ist.Dirty.details->nFxState;
	PyObject *result = PyTuple_New(size);
	for (int i = 0; i < size; i++)
	{
		IREffect e = self->wrapped->Ist.Dirty.details->fxState[i].fx;
		const char *e_str;
		PYMARE_ENUM_TOSTR(IREffect, e, e_str, return NULL);

		PyObject *dict = Py_BuildValue("{s:s,s:H,s:H,s:B,s:B}",
					       "fx", e_str,
					       "offset", self->wrapped->Ist.Dirty.details->fxState[i].offset,
					       "size", self->wrapped->Ist.Dirty.details->fxState[i].size,
					       "nRepeats", self->wrapped->Ist.Dirty.details->fxState[i].nRepeats,
					       "repeatLen", self->wrapped->Ist.Dirty.details->fxState[i].repeatLen);

		PyTuple_SetItem(result, i, dict);
	}
	return result;
}

static PyMethodDef pyIRStmtDirty_methods[] =
{
	{"args", (PyCFunction)pyIRStmtDirty_args, METH_NOARGS, "Returns a tuple of the IRExpr arguments to the callee"},
	{"fxState", (PyCFunction)pyIRStmtDirty_fxState, METH_NOARGS, "Returns a tuple of the fxState descriptions for the call"},
	{NULL}
};
PYVEX_SUBTYPEOBJECT(Dirty, IRStmt);

//////////////////
// LoadG IRStmt //
//////////////////

static int
pyIRStmtLoadG_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYMARE_WRAP_CONSTRUCTOR(IRStmt);

	char *endness_str;
	char *convert_str;
	IRTemp dst;
	pyIRExpr *addr;
	pyIRExpr *alt;
	pyIRExpr *guard;

	IREndness endness;
	IRLoadGOp convert;

	static char *kwlist[] = {"end", "cvt", "dst", "addr", "alt", "guard", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ssIOOO", kwlist, &endness_str, &convert_str, &dst, &addr, &alt, &guard)) return -1;
	PYMARE_CHECKTYPE(addr, pyIRExprType, return -1)
	PYMARE_CHECKTYPE(alt, pyIRExprType, return -1)
	PYMARE_CHECKTYPE(guard, pyIRExprType, return -1)
	PYMARE_ENUM_FROMSTR(IREndness, endness, endness_str, return -1);
	PYMARE_ENUM_FROMSTR(IRLoadGOp, convert, convert_str, return -1);

	self->wrapped = PYVEX_COPYOUT(IRStmt, IRStmt_LoadG(endness, convert, dst, addr->wrapped, alt->wrapped, guard->wrapped));
	return 0;
}

PYMARE_ACCESSOR_ENUM(IRStmtLoadG, IRStmt, self->wrapped->Ist.LoadG.details->end, end, IREndness)
PYMARE_ACCESSOR_ENUM(IRStmtLoadG, IRStmt, self->wrapped->Ist.LoadG.details->cvt, cvt, IRLoadGOp)
PYMARE_ACCESSOR_BUILDVAL(IRStmtLoadG, IRStmt, self->wrapped->Ist.LoadG.details->dst, dst, "i")
PYMARE_ACCESSOR_WRAPPED(IRStmtLoadG, IRStmt, self->wrapped->Ist.LoadG.details->addr, addr, IRExpr)
PYMARE_ACCESSOR_WRAPPED(IRStmtLoadG, IRStmt, self->wrapped->Ist.LoadG.details->alt, alt, IRExpr)
PYMARE_ACCESSOR_WRAPPED(IRStmtLoadG, IRStmt, self->wrapped->Ist.LoadG.details->guard, guard, IRExpr)

PyObject *pyIRStmtLoadG_cvt_types(pyIRStmt* self)
{
	IRType out;
	IRType in;

	typeOfIRLoadGOp(self->wrapped->Ist.LoadG.details->cvt, &out, &in);
	return Py_BuildValue("(ss)", IRType_to_str(in), IRType_to_str(out));
}

static PyGetSetDef pyIRStmtLoadG_getseters[] =
{
	PYMARE_ACCESSOR_DEF(IRStmtLoadG, end),
	PYMARE_ACCESSOR_DEF(IRStmtLoadG, cvt),
	PYMARE_ACCESSOR_DEF(IRStmtLoadG, dst),
	PYMARE_ACCESSOR_DEF(IRStmtLoadG, addr),
	PYMARE_ACCESSOR_DEF(IRStmtLoadG, alt),
	PYMARE_ACCESSOR_DEF(IRStmtLoadG, guard),
	{NULL}
};

static PyMethodDef pyIRStmtLoadG_methods[] =
{
	{"cvt_types", (PyCFunction)pyIRStmtLoadG_cvt_types, METH_NOARGS, "Returns a tuple (in, out) of the IRTypes associated with the IRLoadGOp"},
	{NULL}
};
PYVEX_SUBTYPEOBJECT(LoadG, IRStmt);

///////////////////
// StoreG IRStmt //
///////////////////

static int
pyIRStmtStoreG_init(pyIRStmt *self, PyObject *args, PyObject *kwargs)
{
	PYMARE_WRAP_CONSTRUCTOR(IRStmt);

	char *endness_str;
	pyIRExpr *addr;
	pyIRExpr *data;
	pyIRExpr *guard;

	IREndness endness;

	static char *kwlist[] = {"end", "addr", "data", "guard", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "sOOO", kwlist, &endness_str, &addr, &data, &guard)) return -1;
	PYMARE_CHECKTYPE(addr, pyIRExprType, return -1)
	PYMARE_CHECKTYPE(data, pyIRExprType, return -1)
	PYMARE_CHECKTYPE(guard, pyIRExprType, return -1)
	PYMARE_ENUM_FROMSTR(IREndness, endness, endness_str, return -1);

	self->wrapped = PYVEX_COPYOUT(IRStmt, IRStmt_StoreG(endness, addr->wrapped, data->wrapped, guard->wrapped));
	return 0;
}

PYMARE_ACCESSOR_ENUM(IRStmtStoreG, IRStmt, self->wrapped->Ist.StoreG.details->end, end, IREndness)
PYMARE_ACCESSOR_WRAPPED(IRStmtStoreG, IRStmt, self->wrapped->Ist.StoreG.details->addr, addr, IRExpr)
PYMARE_ACCESSOR_WRAPPED(IRStmtStoreG, IRStmt, self->wrapped->Ist.StoreG.details->data, data, IRExpr)
PYMARE_ACCESSOR_WRAPPED(IRStmtStoreG, IRStmt, self->wrapped->Ist.StoreG.details->guard, guard, IRExpr)

static PyGetSetDef pyIRStmtStoreG_getseters[] =
{
	PYMARE_ACCESSOR_DEF(IRStmtStoreG, end),
	PYMARE_ACCESSOR_DEF(IRStmtStoreG, addr),
	PYMARE_ACCESSOR_DEF(IRStmtStoreG, data),
	PYMARE_ACCESSOR_DEF(IRStmtStoreG, guard),
	{NULL}
};

static PyMethodDef pyIRStmtStoreG_methods[] = { {NULL} };
PYVEX_SUBTYPEOBJECT(StoreG, IRStmt);
