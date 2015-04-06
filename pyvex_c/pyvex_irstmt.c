// This code is GPLed by Yan Shoshitaishvili

#include <Python.h>
#include <libvex.h>

#include "pyvex_types.h"
#include "pyvex_enums.h"
#include "pyvex_export.h"
#include "pyvex_logging.h"



PyObject *export_IRStmtNoOp(IRStmt *stmt, IRTypeEnv *tyenv)
{
	return PyObject_CallObject(pyvexIRStmtNoOp, NULL);
}

PyObject *export_IRStmtIMark(IRStmt *stmt, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRStmtIMark, NULL);

	PYVEX_SETATTRSTRING(r, "addr", PyInt_FromLong(stmt->Ist.IMark.addr));
	PYVEX_SETATTRSTRING(r, "len", PyInt_FromLong(stmt->Ist.IMark.len));
	PYVEX_SETATTRSTRING(r, "delta", PyInt_FromLong(stmt->Ist.IMark.delta));

	return r;
}

PyObject *export_IRStmtAbiHint(IRStmt *stmt, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRStmtAbiHint, NULL);

	PYVEX_SETATTRSTRING(r, "base", export_IRExpr(stmt->Ist.AbiHint.base, tyenv));
	PYVEX_SETATTRSTRING(r, "len", PyInt_FromLong(stmt->Ist.AbiHint.len));
	PYVEX_SETATTRSTRING(r, "nia", export_IRExpr(stmt->Ist.AbiHint.nia, tyenv));

	return r;
}

PyObject *export_IRStmtPut(IRStmt *stmt, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRStmtPut, NULL);

	PYVEX_SETATTRSTRING(r, "data", export_IRExpr(stmt->Ist.Put.data, tyenv));
	PYVEX_SETATTRSTRING(r, "offset", PyInt_FromLong(stmt->Ist.Put.offset));

	return r;
}

PyObject *export_IRStmtPutI(IRStmt *stmt, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRStmtPutI, NULL);

	PYVEX_SETATTRSTRING(r, "descr", export_IRRegArray(stmt->Ist.PutI.details->descr));
	PYVEX_SETATTRSTRING(r, "description", export_IRRegArray(stmt->Ist.PutI.details->descr));

	PYVEX_SETATTRSTRING(r, "ix", export_IRExpr(stmt->Ist.PutI.details->ix, tyenv));
	PYVEX_SETATTRSTRING(r, "index", export_IRExpr(stmt->Ist.PutI.details->ix, tyenv));
	PYVEX_SETATTRSTRING(r, "data", export_IRExpr(stmt->Ist.PutI.details->data, tyenv));
	PYVEX_SETATTRSTRING(r, "bias", PyInt_FromLong(stmt->Ist.PutI.details->bias));

	return r;
}

PyObject *export_IRStmtWrTmp(IRStmt *stmt, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRStmtWrTmp, NULL);

	PYVEX_SETATTRSTRING(r, "data", export_IRExpr(stmt->Ist.WrTmp.data, tyenv));
	PYVEX_SETATTRSTRING(r, "tmp", PyInt_FromLong(stmt->Ist.WrTmp.tmp));

	return r;
}

PyObject *export_IRStmtStore(IRStmt *stmt, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRStmtStore, NULL);

	PYVEX_SETATTRSTRING(r, "data", export_IRExpr(stmt->Ist.Store.data, tyenv));
	PYVEX_SETATTRSTRING(r, "addr", export_IRExpr(stmt->Ist.Store.addr, tyenv));

	PYVEX_SETATTRSTRING(r, "end", export_IREndness(stmt->Ist.Store.end));
	PYVEX_SETATTRSTRING(r, "endness", export_IREndness(stmt->Ist.Store.end));

	return r;
}

PyObject *export_IRStmtCAS(IRStmt *stmt, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRStmtCAS, NULL);

	PYVEX_SETATTRSTRING(r, "dataLo", export_IRExpr(stmt->Ist.CAS.details->dataLo, tyenv));
	PYVEX_SETATTRSTRING(r, "dataHi", export_IRExpr(stmt->Ist.CAS.details->dataHi, tyenv));
	PYVEX_SETATTRSTRING(r, "expdLo", export_IRExpr(stmt->Ist.CAS.details->expdLo, tyenv));
	PYVEX_SETATTRSTRING(r, "expdHi", export_IRExpr(stmt->Ist.CAS.details->expdHi, tyenv));
	PYVEX_SETATTRSTRING(r, "oldLo", PyInt_FromLong(stmt->Ist.CAS.details->oldLo));
	PYVEX_SETATTRSTRING(r, "oldHi", PyInt_FromLong(stmt->Ist.CAS.details->oldHi));
	PYVEX_SETATTRSTRING(r, "addr", export_IRExpr(stmt->Ist.CAS.details->addr, tyenv));

	PYVEX_SETATTRSTRING(r, "end", export_IREndness(stmt->Ist.CAS.details->end));
	PYVEX_SETATTRSTRING(r, "endness", export_IREndness(stmt->Ist.CAS.details->end));

	return r;
}

PyObject *export_IRStmtLLSC(IRStmt *stmt, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRStmtLLSC, NULL);

	PYVEX_SETATTRSTRING(r, "storedata", export_IRExpr(stmt->Ist.LLSC.storedata, tyenv));
	PYVEX_SETATTRSTRING(r, "addr", export_IRExpr(stmt->Ist.LLSC.addr, tyenv));
	PYVEX_SETATTRSTRING(r, "result", PyInt_FromLong(stmt->Ist.LLSC.result));

	PYVEX_SETATTRSTRING(r, "end", export_IREndness(stmt->Ist.LLSC.end));
	PYVEX_SETATTRSTRING(r, "endness", export_IREndness(stmt->Ist.LLSC.end));

	return r;
}

PyObject *export_IRStmtMBE(IRStmt *stmt, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRStmtMBE, NULL);

	PYVEX_SETATTRSTRING(r, "event", export_IRMBusEvent(stmt->Ist.MBE.event));

	return r;
}

PyObject *export_IRStmtExit(IRStmt *stmt, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRStmtExit, NULL);

	PYVEX_SETATTRSTRING(r, "guard", export_IRExpr(stmt->Ist.Exit.guard, tyenv));
	PYVEX_SETATTRSTRING(r, "dst", export_IRConst(stmt->Ist.Exit.dst));
	PYVEX_SETATTRSTRING(r, "offsIP", PyInt_FromLong(stmt->Ist.Exit.offsIP));

	PYVEX_SETATTRSTRING(r, "jk", export_IRJumpKind(stmt->Ist.Exit.jk));
	PYVEX_SETATTRSTRING(r, "jumpkind", export_IRJumpKind(stmt->Ist.Exit.jk));

	return r;
}

PyObject *export_IRStmtDirty(IRStmt *stmt, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRStmtDirty, NULL);

	PYVEX_SETATTRSTRING(r, "cee", export_IRCallee(stmt->Ist.Dirty.details->cee));
	PYVEX_SETATTRSTRING(r, "guard", export_IRExpr(stmt->Ist.Dirty.details->guard, tyenv));
	PYVEX_SETATTRSTRING(r, "tmp", PyInt_FromLong(stmt->Ist.Dirty.details->tmp));
	PYVEX_SETATTRSTRING(r, "mFx", export_IREffect(stmt->Ist.Dirty.details->mFx));
	PYVEX_SETATTRSTRING(r, "mAddr", export_IRExpr(stmt->Ist.Dirty.details->mAddr, tyenv));
	PYVEX_SETATTRSTRING(r, "mSize", PyInt_FromLong(stmt->Ist.Dirty.details->mSize));
	PYVEX_SETATTRSTRING(r, "nFxState", PyInt_FromLong(stmt->Ist.Dirty.details->nFxState));

	// args
	int num_args; for (num_args = 0; stmt->Ist.Dirty.details->args[num_args] != NULL; num_args++);
	PyObject *args = PyTuple_New(num_args);
	for (int i = 0; i < num_args; i++)
	{
		PyTuple_SetItem(args, i, export_IRExpr(stmt->Ist.Dirty.details->args[i], tyenv));
	}
	PYVEX_SETATTRSTRING(r, "args", args);

	int fx_size = stmt->Ist.Dirty.details->nFxState;
	PyObject *fxState = PyTuple_New(fx_size);
	for (int i = 0; i < fx_size; i++)
	{
		PyObject *dict = Py_BuildValue("{s:s,s:H,s:H,s:B,s:B}",
			"fx", export_IREffect(stmt->Ist.Dirty.details->fxState[i].fx),
			"offset", stmt->Ist.Dirty.details->fxState[i].offset,
			"size", stmt->Ist.Dirty.details->fxState[i].size,
			"nRepeats", stmt->Ist.Dirty.details->fxState[i].nRepeats,
			"repeatLen", stmt->Ist.Dirty.details->fxState[i].repeatLen); 

		PyTuple_SetItem(fxState, i, dict);
	}
	PYVEX_SETATTRSTRING(r, "fxState", fxState);

	return r;
}

PyObject *export_IRStmtLoadG(IRStmt *stmt, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRStmtLoadG, NULL);

	PYVEX_SETATTRSTRING(r, "dst", PyInt_FromLong(stmt->Ist.LoadG.details->dst));
	PYVEX_SETATTRSTRING(r, "addr", export_IRExpr(stmt->Ist.LoadG.details->addr, tyenv));
	PYVEX_SETATTRSTRING(r, "alt", export_IRExpr(stmt->Ist.LoadG.details->alt, tyenv));
	PYVEX_SETATTRSTRING(r, "guard", export_IRExpr(stmt->Ist.LoadG.details->guard, tyenv));
	PYVEX_SETATTRSTRING(r, "cvt", export_IRLoadGOp(stmt->Ist.LoadG.details->cvt));

	PYVEX_SETATTRSTRING(r, "end", export_IREndness(stmt->Ist.LoadG.details->end));
	PYVEX_SETATTRSTRING(r, "endness", export_IREndness(stmt->Ist.LoadG.details->end));

	IRType out;
	IRType in;
	typeOfIRLoadGOp(stmt->Ist.LoadG.details->cvt, &out, &in);
	PyObject *in_obj = export_IRType(in);
	PyObject *out_obj = export_IRType(out);
	PYVEX_SETATTRSTRING(r, "cvt_types", Py_BuildValue("(OO)", in_obj, out_obj));
	Py_DECREF(in_obj);
	Py_DECREF(out_obj);

	return r;
}

PyObject *export_IRStmtStoreG(IRStmt *stmt, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRStmtStoreG, NULL);

	PYVEX_SETATTRSTRING(r, "addr", export_IRExpr(stmt->Ist.StoreG.details->addr, tyenv));
	PYVEX_SETATTRSTRING(r, "data", export_IRExpr(stmt->Ist.StoreG.details->data, tyenv));
	PYVEX_SETATTRSTRING(r, "guard", export_IRExpr(stmt->Ist.StoreG.details->guard, tyenv));

	PYVEX_SETATTRSTRING(r, "end", export_IREndness(stmt->Ist.StoreG.details->end));
	PYVEX_SETATTRSTRING(r, "endness", export_IREndness(stmt->Ist.StoreG.details->end));

	return r;
}


PyObject *export_IRStmt(IRStmt *stmt, IRTypeEnv *tyenv)
{
	if (!stmt) Py_RETURN_NONE;

	PyObject *r;
	switch (stmt->tag)
	{
		case Ist_NoOp: r = export_IRStmtNoOp(stmt, tyenv); break;
		case Ist_IMark: r = export_IRStmtIMark(stmt, tyenv); break;
		case Ist_AbiHint: r = export_IRStmtAbiHint(stmt, tyenv); break;
		case Ist_Put: r = export_IRStmtPut(stmt, tyenv); break;
		case Ist_PutI: r = export_IRStmtPutI(stmt, tyenv); break;
		case Ist_WrTmp: r = export_IRStmtWrTmp(stmt, tyenv); break;
		case Ist_Store: r = export_IRStmtStore(stmt, tyenv); break;
		case Ist_CAS: r = export_IRStmtCAS(stmt, tyenv); break;
		case Ist_LLSC: r = export_IRStmtLLSC(stmt, tyenv); break;
		case Ist_Dirty: r = export_IRStmtDirty(stmt, tyenv); break;
		case Ist_MBE: r = export_IRStmtMBE(stmt, tyenv); break;
		case Ist_Exit: r = export_IRStmtExit(stmt, tyenv); break;
		case Ist_LoadG: r = export_IRStmtLoadG(stmt, tyenv); break;
		case Ist_StoreG: r = export_IRStmtStoreG(stmt, tyenv); break;
		default:
			pyvex_error("PyVEX: Unknown/unsupported IRStmtTag %s\n", IRStmtTag_to_str(stmt->tag));
			Py_RETURN_NONE;
	}

	// the stmt tag
	PYVEX_SETATTRSTRING(r, "tag", export_IRStmtTag(stmt->tag));

	// whether the stmt is flat
	if (isFlatIRStmt(stmt))
	{
		Py_INCREF(Py_True);
		PYVEX_SETATTRSTRING(r, "is_flat", Py_True);
	}
	else
	{
		Py_INCREF(Py_False);
		PYVEX_SETATTRSTRING(r, "is_flat", Py_False);
	}

	return r;
}
