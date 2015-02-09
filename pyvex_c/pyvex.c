// This code is GPLed by Yan Shoshitaishvili

#include <Python.h>
#include "pyvex_static.h"
#include "pyvex_logging.h"
#include "pyvex_types.h"
#include "pyvex_enums.h"

PyObject *module;

// the types
PyObject *PyVEXError;
PyObject *pyvexIRSB;
PyObject *pyvexIRTypeEnv;
PyObject *pyvexIRConst;
PyObject *pyvexIRConstU1;
PyObject *pyvexIRConstU8;
PyObject *pyvexIRConstU16;
PyObject *pyvexIRConstU32;
PyObject *pyvexIRConstU64;
PyObject *pyvexIRConstF32;
PyObject *pyvexIRConstF32i;
PyObject *pyvexIRConstF64;
PyObject *pyvexIRConstF64i;
PyObject *pyvexIRConstV128;
PyObject *pyvexIRConstV256;
PyObject *pyvexIRStmt;
PyObject *pyvexIRStmtNoOp;
PyObject *pyvexIRStmtIMark;
PyObject *pyvexIRStmtAbiHint;
PyObject *pyvexIRStmtPut;
PyObject *pyvexIRStmtPutI;
PyObject *pyvexIRStmtWrTmp;
PyObject *pyvexIRStmtStore;
PyObject *pyvexIRStmtCAS;
PyObject *pyvexIRStmtLLSC;
PyObject *pyvexIRStmtMBE;
PyObject *pyvexIRStmtDirty;
PyObject *pyvexIRStmtExit;
PyObject *pyvexIRStmtLoadG;
PyObject *pyvexIRStmtStoreG;
PyObject *pyvexIRExpr;
PyObject *pyvexIRExprBinder;
PyObject *pyvexIRExprVECRET;
PyObject *pyvexIRExprBBPTR;
PyObject *pyvexIRExprGetI;
PyObject *pyvexIRExprRdTmp;
PyObject *pyvexIRExprGet;
PyObject *pyvexIRExprQop;
PyObject *pyvexIRExprTriop;
PyObject *pyvexIRExprBinop;
PyObject *pyvexIRExprUnop;
PyObject *pyvexIRExprLoad;
PyObject *pyvexIRExprConst;
PyObject *pyvexIRExprITE;
PyObject *pyvexIRExprCCall;
PyObject *pyvexIRCallee;
PyObject *pyvexIRRegArray;



PyObject *actual_init(PyObject *self, PyObject *pyvex_module)
{
	pyvexIRSB = PyObject_GetAttrString(pyvex_module, "IRSB");
	pyvexIRTypeEnv = PyObject_GetAttrString(pyvex_module, "IRTypeEnv");
	pyvexIRCallee = PyObject_GetAttrString(pyvex_module, "IRCallee");
	pyvexIRRegArray = PyObject_GetAttrString(pyvex_module, "IRRegArray");

	// ir constants
	pyvexIRConst = PyObject_GetAttrString(pyvex_module, "IRConst");
	pyvexIRConstU1 = PyObject_GetAttrString(pyvexIRConst, "U1");
	pyvexIRConstU8 = PyObject_GetAttrString(pyvexIRConst, "U8");
	pyvexIRConstU16 = PyObject_GetAttrString(pyvexIRConst, "U16");
	pyvexIRConstU32 = PyObject_GetAttrString(pyvexIRConst, "U32");
	pyvexIRConstU64 = PyObject_GetAttrString(pyvexIRConst, "U64");
	pyvexIRConstF32 = PyObject_GetAttrString(pyvexIRConst, "F32");
	pyvexIRConstF32i = PyObject_GetAttrString(pyvexIRConst, "F32i");
	pyvexIRConstF64 = PyObject_GetAttrString(pyvexIRConst, "F64");
	pyvexIRConstF64i = PyObject_GetAttrString(pyvexIRConst, "F64i");
	pyvexIRConstV128 = PyObject_GetAttrString(pyvexIRConst, "V128");
	pyvexIRConstV256 = PyObject_GetAttrString(pyvexIRConst, "V256");

	// statements
	pyvexIRStmt = PyObject_GetAttrString(pyvex_module, "IRStmt");
	pyvexIRStmtNoOp = PyObject_GetAttrString(pyvexIRStmt, "NoOp");
	pyvexIRStmtIMark = PyObject_GetAttrString(pyvexIRStmt, "IMark");
	pyvexIRStmtAbiHint = PyObject_GetAttrString(pyvexIRStmt, "AbiHint");
	pyvexIRStmtPut = PyObject_GetAttrString(pyvexIRStmt, "Put");
	pyvexIRStmtPutI = PyObject_GetAttrString(pyvexIRStmt, "PutI");
	pyvexIRStmtWrTmp = PyObject_GetAttrString(pyvexIRStmt, "WrTmp");
	pyvexIRStmtStore = PyObject_GetAttrString(pyvexIRStmt, "Store");
	pyvexIRStmtCAS = PyObject_GetAttrString(pyvexIRStmt, "CAS");
	pyvexIRStmtLLSC = PyObject_GetAttrString(pyvexIRStmt, "LLSC");
	pyvexIRStmtMBE = PyObject_GetAttrString(pyvexIRStmt, "MBE");
	pyvexIRStmtDirty = PyObject_GetAttrString(pyvexIRStmt, "Dirty");
	pyvexIRStmtExit = PyObject_GetAttrString(pyvexIRStmt, "Exit");
	pyvexIRStmtLoadG = PyObject_GetAttrString(pyvexIRStmt, "LoadG");
	pyvexIRStmtStoreG = PyObject_GetAttrString(pyvexIRStmt, "StoreG");

	// expressions
	pyvexIRExpr = PyObject_GetAttrString(pyvex_module, "IRExpr");
	pyvexIRExprBinder = PyObject_GetAttrString(pyvexIRExpr, "Binder");
	pyvexIRExprBBPTR = PyObject_GetAttrString(pyvexIRExpr, "BBPTR");
	pyvexIRExprVECRET = PyObject_GetAttrString(pyvexIRExpr, "VECRET");
	pyvexIRExprGetI = PyObject_GetAttrString(pyvexIRExpr, "GetI");
	pyvexIRExprRdTmp = PyObject_GetAttrString(pyvexIRExpr, "RdTmp");
	pyvexIRExprGet = PyObject_GetAttrString(pyvexIRExpr, "Get");
	pyvexIRExprQop = PyObject_GetAttrString(pyvexIRExpr, "Qop");
	pyvexIRExprTriop = PyObject_GetAttrString(pyvexIRExpr, "Triop");
	pyvexIRExprBinop = PyObject_GetAttrString(pyvexIRExpr, "Binop");
	pyvexIRExprUnop = PyObject_GetAttrString(pyvexIRExpr, "Unop");
	pyvexIRExprLoad = PyObject_GetAttrString(pyvexIRExpr, "Load");
	pyvexIRExprConst = PyObject_GetAttrString(pyvexIRExpr, "Const");
	pyvexIRExprITE = PyObject_GetAttrString(pyvexIRExpr, "ITE");
	pyvexIRExprCCall = PyObject_GetAttrString(pyvexIRExpr, "CCall");

	PyVEXError = PyObject_GetAttrString(pyvex_module, "PyVEXError");
	pyvex_init_enums(module);

	Py_RETURN_NONE;
}

PyObject *typeOfIROp(PyObject *self, PyObject *op)
{
	IRSB *irsb = emptyIRSB();
	IRTemp t = newIRTemp(irsb->tyenv, Ity_I8);
	IRExpr *e = IRExpr_Unop(pystr_to_IROp(op), IRExpr_RdTmp(t));
	return IRType_to_pystr(typeOfIRExpr(irsb->tyenv, e));
}

static PyMethodDef module_methods[] = {
	{"init", actual_init, METH_O},
	{"init_IRSB", init_IRSB, METH_VARARGS | METH_KEYWORDS},
	{"typeOfIROp", typeOfIROp, METH_O},
	{NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif

PyMODINIT_FUNC initpyvex_c(void) 
{
	//printf("Module loading...\n");
	module = Py_InitModule3("pyvex_c", module_methods, "Python interface to Valgrind's VEX.");
	if (module == NULL) return;

	vex_init();
}
