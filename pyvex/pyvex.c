// This code is GPLed by Yan Shoshitaishvili

#include <Python.h>
#include "pyvex_static.h"
#include "pyvex_logging.h"
#include "pyvex_types.h"
#include "pyvex_enums.h"

PyObject *VexException;
PyObject *PyMareError;
PyObject *module;

static PyMethodDef module_methods[] = {
	{NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initpyvex(void) 
{
	//printf("Module loading...\n");
	module = Py_InitModule3("pyvex", module_methods, "Python interface to Valgrind's VEX.");
	if (module == NULL) return;

	//
	// Ready types
	//
	PYMARE_INITTYPE(IRSB);
	PYMARE_INITTYPE(IRTypeEnv);
	PYMARE_INITTYPE(IRCallee);
	PYMARE_INITTYPE(IRRegArray);

	// ir constants
	PYMARE_INITTYPE(IRConst);
	PYMARE_INITSUBTYPE(IRConst, U1);
	PYMARE_INITSUBTYPE(IRConst, U8);
	PYMARE_INITSUBTYPE(IRConst, U16);
	PYMARE_INITSUBTYPE(IRConst, U32);
	PYMARE_INITSUBTYPE(IRConst, U64);
	PYMARE_INITSUBTYPE(IRConst, F32);
	PYMARE_INITSUBTYPE(IRConst, F32i);
	PYMARE_INITSUBTYPE(IRConst, F64);
	PYMARE_INITSUBTYPE(IRConst, F64i);
	PYMARE_INITSUBTYPE(IRConst, V128);
	PYMARE_INITSUBTYPE(IRConst, V256);

	// statements
	PYMARE_INITTYPE(IRStmt);
	PYMARE_INITSUBTYPE(IRStmt, NoOp);
	PYMARE_INITSUBTYPE(IRStmt, IMark);
	PYMARE_INITSUBTYPE(IRStmt, AbiHint);
	PYMARE_INITSUBTYPE(IRStmt, Put);
	PYMARE_INITSUBTYPE(IRStmt, PutI);
	PYMARE_INITSUBTYPE(IRStmt, WrTmp);
	PYMARE_INITSUBTYPE(IRStmt, Store);
	PYMARE_INITSUBTYPE(IRStmt, CAS);
	PYMARE_INITSUBTYPE(IRStmt, LLSC);
	PYMARE_INITSUBTYPE(IRStmt, MBE);
	PYMARE_INITSUBTYPE(IRStmt, Dirty);
	PYMARE_INITSUBTYPE(IRStmt, Exit);
	PYMARE_INITSUBTYPE(IRStmt, LoadG);
	PYMARE_INITSUBTYPE(IRStmt, StoreG);

	// expressions
	PYMARE_INITTYPE(IRExpr);
	PYMARE_INITSUBTYPE(IRExpr, Binder);
	PYMARE_INITSUBTYPE(IRExpr, GetI);
	PYMARE_INITSUBTYPE(IRExpr, RdTmp);
	PYMARE_INITSUBTYPE(IRExpr, Get);
	PYMARE_INITSUBTYPE(IRExpr, Qop);
	PYMARE_INITSUBTYPE(IRExpr, Triop);
	PYMARE_INITSUBTYPE(IRExpr, Binop);
	PYMARE_INITSUBTYPE(IRExpr, Unop);
	PYMARE_INITSUBTYPE(IRExpr, Load);
	PYMARE_INITSUBTYPE(IRExpr, Const);
	PYMARE_INITSUBTYPE(IRExpr, ITE);
	PYMARE_INITSUBTYPE(IRExpr, CCall);

	VexException = PyErr_NewException("pyvex.VexException", NULL, NULL);
	PyMareError = VexException;
	PyModule_AddObject(module, "VexException", VexException);
	//printf("VexException added...\n");

	pyvex_init_enums(module);

	//debug_on = 1;
#ifdef PYVEX_STATIC
	vex_init();
#endif
	//printf("Done\n");
}

#ifdef PYVEX_STATIC_PYTHON
int main(int argc, char **argv) {
	PyImport_AppendInittab("pyvex", initpyvex);
	return Py_Main(argc, argv);
}
#endif
