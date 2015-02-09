// This code is GPLed by Yan Shoshitaishvili

#include <Python.h>
#include <libvex.h>

#include "pyvex_enums.h"
#include "pyvex_types.h"
#include "pyvex_export.h"
#include "pyvex_logging.h"

PyObject *export_IRExprBinder(IRExpr *expr, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRExprBinder, NULL);

	PYVEX_SETATTRSTRING(r, "binder", PyInt_FromLong(expr->Iex.Binder.binder));

	return r;
}

PyObject *export_IRExprVECRET(IRExpr *expr, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRExprVECRET, NULL);
	return r;
}

PyObject *export_IRExprBBPTR(IRExpr *expr, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRExprBBPTR, NULL);
	return r;
}

PyObject *export_IRExprGetI(IRExpr *expr, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRExprGetI, NULL);

	PYVEX_SETATTRSTRING(r, "description", export_IRRegArray(expr->Iex.GetI.descr));
	PYVEX_SETATTRSTRING(r, "descr", export_IRRegArray(expr->Iex.GetI.descr));

	PYVEX_SETATTRSTRING(r, "index", export_IRExpr(expr->Iex.GetI.ix, tyenv));
	PYVEX_SETATTRSTRING(r, "ix", export_IRExpr(expr->Iex.GetI.ix, tyenv));

	PYVEX_SETATTRSTRING(r, "bias", PyInt_FromLong(expr->Iex.GetI.bias));
	return r;
}

PyObject *export_IRExprGet(IRExpr *expr, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRExprGet, NULL);

	PYVEX_SETATTRSTRING(r, "offset", PyInt_FromLong(expr->Iex.Get.offset));
	PYVEX_SETATTRSTRING(r, "type", export_IRType(expr->Iex.Get.ty));
	PYVEX_SETATTRSTRING(r, "ty", export_IRType(expr->Iex.Get.ty));

	return r;
}

PyObject *export_IRExprRdTmp(IRExpr *expr, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRExprRdTmp, NULL);

	PYVEX_SETATTRSTRING(r, "tmp", PyInt_FromLong(expr->Iex.RdTmp.tmp));

	return r;
}

PyObject *export_IRExprQop(IRExpr *expr, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRExprQop, NULL);

	PYVEX_SETATTRSTRING(r, "op", export_IROp(expr->Iex.Qop.details->op));

	PyObject *a1 = export_IRExpr(expr->Iex.Qop.details->arg1, tyenv);
	PyObject *a2 = export_IRExpr(expr->Iex.Qop.details->arg2, tyenv);
	PyObject *a3 = export_IRExpr(expr->Iex.Qop.details->arg3, tyenv);
	PyObject *a4 = export_IRExpr(expr->Iex.Qop.details->arg4, tyenv);

	//PYVEX_SETATTRSTRING(r, "arg1", a1);
	//PYVEX_SETATTRSTRING(r, "arg2", a2);
	//PYVEX_SETATTRSTRING(r, "arg3", a3);
	//PYVEX_SETATTRSTRING(r, "arg4", a4);

	PYVEX_SETATTRSTRING(r, "args", Py_BuildValue("(OOOO)", a1, a2, a3, a4));

	return r;
}

PyObject *export_IRExprTriop(IRExpr *expr, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRExprTriop, NULL);

	PYVEX_SETATTRSTRING(r, "op", export_IROp(expr->Iex.Triop.details->op));

	PyObject *a1 = export_IRExpr(expr->Iex.Triop.details->arg1, tyenv);
	PyObject *a2 = export_IRExpr(expr->Iex.Triop.details->arg2, tyenv);
	PyObject *a3 = export_IRExpr(expr->Iex.Triop.details->arg3, tyenv);

	//PYVEX_SETATTRSTRING(r, "arg1", a1);
	//PYVEX_SETATTRSTRING(r, "arg2", a2);
	//PYVEX_SETATTRSTRING(r, "arg3", a3);

	PYVEX_SETATTRSTRING(r, "args", Py_BuildValue("(OOO)", a1, a2, a3));

	return r;
}

PyObject *export_IRExprBinop(IRExpr *expr, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRExprBinop, NULL);

	PYVEX_SETATTRSTRING(r, "op", export_IROp(expr->Iex.Binop.op));

	PyObject *a1 = export_IRExpr(expr->Iex.Binop.arg1, tyenv);
	PyObject *a2 = export_IRExpr(expr->Iex.Binop.arg2, tyenv);

	//PYVEX_SETATTRSTRING(r, "arg1", a1);
	//PYVEX_SETATTRSTRING(r, "arg2", a2);

	PYVEX_SETATTRSTRING(r, "args", Py_BuildValue("(OO)", a1, a2));

	return r;
}

PyObject *export_IRExprUnop(IRExpr *expr, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRExprUnop, NULL);

	PYVEX_SETATTRSTRING(r, "op", export_IROp(expr->Iex.Unop.op));

	PyObject *a1 = export_IRExpr(expr->Iex.Unop.arg, tyenv);

	//PYVEX_SETATTRSTRING(r, "arg1", a1);
	//PYVEX_SETATTRSTRING(r, "arg", a1);
	PYVEX_SETATTRSTRING(r, "args", Py_BuildValue("(O)", a1));

	return r;
}

PyObject *export_IRExprLoad(IRExpr *expr, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRExprLoad, NULL);

	PYVEX_SETATTRSTRING(r, "end", export_IREndness(expr->Iex.Load.end));
	PYVEX_SETATTRSTRING(r, "endness", export_IREndness(expr->Iex.Load.end));

	PYVEX_SETATTRSTRING(r, "type", export_IRType(expr->Iex.Load.ty));
	PYVEX_SETATTRSTRING(r, "ty", export_IRType(expr->Iex.Load.ty));

	PYVEX_SETATTRSTRING(r, "addr", export_IRExpr(expr->Iex.Load.addr, tyenv));

	return r;
}

PyObject *export_IRExprConst(IRExpr *expr, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRExprConst, NULL);

	PYVEX_SETATTRSTRING(r, "con", export_IRConst(expr->Iex.Const.con));

	return r;
}

PyObject *export_IRExprITE(IRExpr *expr, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRExprITE, NULL);

	PYVEX_SETATTRSTRING(r, "cond", export_IRExpr(expr->Iex.ITE.cond, tyenv));
	PYVEX_SETATTRSTRING(r, "iffalse", export_IRExpr(expr->Iex.ITE.iffalse, tyenv));
	PYVEX_SETATTRSTRING(r, "iftrue", export_IRExpr(expr->Iex.ITE.iftrue, tyenv));

	return r;
}

PyObject *export_IRExprCCall(IRExpr *expr, IRTypeEnv *tyenv)
{
	PyObject *r = PyObject_CallObject(pyvexIRExprCCall, NULL);

	PYVEX_SETATTRSTRING(r, "retty", export_IRType(expr->Iex.CCall.retty));
	PYVEX_SETATTRSTRING(r, "ret_type", export_IRType(expr->Iex.CCall.retty));

	PYVEX_SETATTRSTRING(r, "callee", export_IRCallee(expr->Iex.CCall.cee));
	PYVEX_SETATTRSTRING(r, "cee", export_IRCallee(expr->Iex.CCall.cee));

	// args
	int num_args; for (num_args = 0; expr->Iex.CCall.args[num_args] != NULL; num_args++);

	PyObject *args = PyTuple_New(num_args);
	for (int i = 0; i < num_args; i++)
	{
		PyTuple_SetItem(args, i, export_IRExpr(expr->Iex.CCall.args[i], tyenv));
	}
	PYVEX_SETATTRSTRING(r, "args", args);

	return r;
}

PyObject *export_IRExpr(IRExpr *expr, IRTypeEnv *tyenv)
{
	if (!expr) Py_RETURN_NONE;

	PyObject *r;
	switch (expr->tag)
	{
		case Iex_Binder: r = export_IRExprBinder(expr, tyenv); break;
		case Iex_Get: r = export_IRExprGet(expr, tyenv); break;
		case Iex_GetI: r = export_IRExprGetI(expr, tyenv); break;
		case Iex_RdTmp: r = export_IRExprRdTmp(expr, tyenv); break;
		case Iex_Qop: r = export_IRExprQop(expr, tyenv); break;
		case Iex_Triop: r = export_IRExprTriop(expr, tyenv); break;
		case Iex_Binop: r = export_IRExprBinop(expr, tyenv); break;
		case Iex_Unop: r = export_IRExprUnop(expr, tyenv); break;
		case Iex_Load: r = export_IRExprLoad(expr, tyenv); break;
		case Iex_Const: r = export_IRExprConst(expr, tyenv); break;
		case Iex_ITE: r = export_IRExprITE(expr, tyenv); break;
		case Iex_CCall: r = export_IRExprCCall(expr, tyenv); break;
		case Iex_BBPTR: r = export_IRExprBBPTR(expr, tyenv); break;
		case Iex_VECRET: r = export_IRExprVECRET(expr, tyenv); break;

		default:
			pyvex_error("PyVEX: Unknown/unsupported IRExprTag %s\n", IRExprTag_to_str(expr->tag));
			Py_RETURN_NONE;
	}

	PYVEX_SETATTRSTRING(r, "result_type", export_IRType(typeOfIRExpr(tyenv, expr)));

	// the expr tag
	PYVEX_SETATTRSTRING(r, "tag", export_IRExprTag(expr->tag));

	if (isIRAtom(expr))
	{
		Py_INCREF(Py_True);
		PYVEX_SETATTRSTRING(r, "is_atomic", Py_True);
	}
	else
	{
		Py_INCREF(Py_False);
		PYVEX_SETATTRSTRING(r, "is_atomic", Py_False);
	}

	return r;
}
