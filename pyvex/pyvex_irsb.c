// This code is GPLed by Yan Shoshitaishvili

#include <Python.h>
#include <structmember.h>
#include <libvex.h>

#include "pyvex_enums.h"
#include "pyvex_types.h"
#include "pyvex_macros.h"

#ifdef PYVEX_STATIC
	#include "pyvex_static.h"
	#include "pyvex_deepcopy.h"
#endif

extern VexTranslateArgs vta;

PYMARE_NEW(IRSB)
PYMARE_DEALLOC(IRSB)
PYMARE_WRAP(IRSB)
PYVEX_METH_STANDARD(IRSB)

static int
pyIRSB_init(pyIRSB *self, PyObject *args, PyObject *kwargs)
{
	if (!kwargs) { self->wrapped = PYVEX_COPYOUT(IRSB, emptyIRSB()); return 0; }
	PYMARE_WRAP_CONSTRUCTOR(IRSB);

#ifdef PYVEX_STATIC
	unsigned char *bytes = NULL;
	unsigned int mem_addr = 0;
	int num_inst = -1;
	int num_bytes = -1;
	const char *arch_str = NULL;
        const char *endness_str = NULL;
	VexArch arch = VexArch_INVALID;
        VexEndness endness = VexEndness_INVALID;
	int basic = 0;
	int bytes_offset = 0;
	int traceflags = 0;

	static char *kwlist[] = {"bytes", "mem_addr", "num_inst", "arch", "endness", "basic", "bytes_offset", "traceflags", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s#IIssIiI", kwlist, &bytes, &num_bytes, &mem_addr, &num_inst, &arch_str, &endness_str, &basic, &bytes_offset, &traceflags)) return -1;

	if (!arch_str) arch_str = "VexArchAMD64";
	PYMARE_ENUM_FROMSTR(VexArch, arch, arch_str, return -1);
	if (!endness_str) endness_str = "VexEndnessLE";
    PYMARE_ENUM_FROMSTR(VexEndness, endness, endness_str, return -1);

	if (num_bytes == 0)
	{
		PyErr_SetString(VexException, "No bytes provided");
		return -1;
	}

	vta.traceflags = traceflags;

	if (num_bytes > 0)
	{
		vex_init();
		if (num_inst > -1) self->wrapped = vex_block_inst(arch, endness, bytes + bytes_offset, mem_addr, num_inst);
		else self->wrapped = vex_block_bytes(arch, endness, bytes + bytes_offset, mem_addr, num_bytes, basic);

		self->wrapped = PYVEX_COPYOUT(IRSB, self->wrapped);

		if (self->wrapped == NULL) { PyErr_SetString(VexException, "Error creating IR."); return -1; }
		return 0;
	}

	PyErr_SetString(VexException, "Not enough arguments provided.");
	return -1;
#else
	PyErr_SetString(VexException, "Statically creating IRSBs is disabled.");
	return -1;
#endif
}

static PyMemberDef pyIRSB_members[] = { {NULL} };

PYMARE_ACCESSOR_WRAPPED(IRSB, IRSB, self->wrapped, wrapped, IRSB)
PYMARE_ACCESSOR_WRAPPED(IRSB, IRSB, self->wrapped->tyenv, tyenv, IRTypeEnv)
PYMARE_ACCESSOR_WRAPPED(IRSB, IRSB, self->wrapped->next, next, IRExpr)
PYMARE_ACCESSOR_ENUM(IRSB, IRSB, self->wrapped->jumpkind, jumpkind, IRJumpKind)
PYMARE_ACCESSOR_BUILDVAL(IRSB, IRSB, self->wrapped->offsIP, offsIP, "i")

static PyGetSetDef pyIRSB_getseters[] =
{
	PYMARE_ACCESSOR_DEF(IRSB, wrapped),
	PYMARE_ACCESSOR_DEF(IRSB, tyenv),
	PYMARE_ACCESSOR_DEF(IRSB, next),
	PYMARE_ACCESSOR_DEF(IRSB, jumpkind),
	PYMARE_ACCESSOR_DEF(IRSB, offsIP),
	{NULL}  /* Sentinel */
};

static PyObject *
pyIRSB_statements(pyIRSB* self)
{
	PyObject *result = PyTuple_New(self->wrapped->stmts_used);
	for (int i = 0; i < self->wrapped->stmts_used; i++)
	{
		PyObject *wrapped = wrap_IRStmt(self->wrapped->stmts[i]);
		PyTuple_SetItem(result, i, wrapped);
	}
	return result;
}

static PyObject *pyIRSB_deepCopyExceptStmts(pyIRSB* self) { return (PyObject *)wrap_IRSB(deepCopyIRSBExceptStmts(self->wrapped)); }
static PyObject *pyIRSB_addStatement(pyIRSB* self, PyObject *stmt)
{
	PYMARE_CHECKTYPE(stmt, pyIRStmtType, return NULL);
	addStmtToIRSB(self->wrapped, ((pyIRStmt *)stmt)->wrapped);
	Py_RETURN_NONE;
}

static PyObject *pyIRSB_instructions(pyIRSB *self)
{
	long instructions = 0;
	for (int i = 0; i < self->wrapped->stmts_used; i++)
	{
		if (self->wrapped->stmts[i]->tag == Ist_IMark) instructions++;
	}

	return PyInt_FromLong(instructions);
}
static PyObject *pyIRSB_size(pyIRSB *self)
{
	long size = 0;
	for (int i = 0; i < self->wrapped->stmts_used; i++)
	{
		if (self->wrapped->stmts[i]->tag == Ist_IMark) size += self->wrapped->stmts[i]->Ist.IMark.len;
	}

	return PyInt_FromLong(size);
}

static PyMethodDef pyIRSB_methods[] =
{
	PYVEX_METHDEF_STANDARD(IRSB),
	{"addStatement", (PyCFunction)pyIRSB_addStatement, METH_O, "Adds a statement to the basic block."},
	{"deepCopyExceptStmts", (PyCFunction)pyIRSB_deepCopyExceptStmts, METH_NOARGS, "Copies the IRSB, without any statements."},
	{"statements", (PyCFunction)pyIRSB_statements, METH_NOARGS, "Returns a tuple of the IRStmts in the IRSB"},
	{"instructions", (PyCFunction)pyIRSB_instructions, METH_NOARGS, "Returns the number of host instructions in the IRSB"},
	{"size", (PyCFunction)pyIRSB_size, METH_NOARGS, "Returns the size, in bytes, of the host instructions represented by the IRSB"},
	{NULL}  /* Sentinel */
};

PYMARE_TYPEOBJECT("pyvex", IRSB);
