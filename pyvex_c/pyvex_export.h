#include <Python.h>
#include "libvex.h"

#define PYVEX_SETATTRSTRING(obj, name, attr) \
	{ PyObject *o = attr; PyObject_SetAttrString(obj, name, o); Py_DECREF(o); }

PyObject *export_IRSB(PyObject *, IRSB*);
PyObject *export_IRStmt(IRStmt*, IRTypeEnv *);
PyObject *export_IRExpr(IRExpr*, IRTypeEnv *);
PyObject *export_IRRegArray(IRRegArray*);
PyObject *export_IRCallee(IRCallee*);
PyObject *export_IRConst(IRConst*);
PyObject *export_IRTypeEnv(IRTypeEnv*);

// enums
PyObject *export_IRJumpKind(IRJumpKind);
PyObject *export_IREndness(IREndness);
PyObject *export_IRMBusEvent(IRMBusEvent);
PyObject *export_IREffect(IREffect);
PyObject *export_IRLoadGOp(IRLoadGOp);
PyObject *export_IRType(IRType);
PyObject *export_IRStmtTag(IRStmtTag);
PyObject *export_IRExprTag(IRExprTag);
PyObject *export_IROp(IROp);
PyObject *export_IRConstTag(IRConstTag);
