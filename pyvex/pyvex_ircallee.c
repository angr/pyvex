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

PYMARE_NEW(IRCallee)
PYMARE_DEALLOC(IRCallee)
PYMARE_WRAP(IRCallee)
PYVEX_METH_STANDARD(IRCallee)

static int
pyIRCallee_init(pyIRCallee *self, PyObject *args, PyObject *kwargs)
{
	PYMARE_WRAP_CONSTRUCTOR(IRCallee);

	Int regparms;
	char *name;
	UInt mcx_mask = 123456789;
	unsigned long long addr;

	static char *kwlist[] = {"regparms", "name", "addr", "mcx_mask", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "isK|I", kwlist, &regparms, &name, &addr, &mcx_mask)) return -1;
	if (regparms < 0 || regparms > 3) { PyErr_SetString(PyVEXError, "regparms out of range"); return -1; }

	self->wrapped = PYVEX_COPYOUT(IRCallee, mkIRCallee(regparms, name, (void *)addr));
	if (mcx_mask != 123456789) self->wrapped->mcx_mask = mcx_mask;
	return 0;
}

static PyMemberDef pyIRCallee_members[] = { {NULL} };

PYMARE_ACCESSOR_WRAPPED(IRCallee, IRCallee, self->wrapped, wrapped, IRCallee)
PYMARE_ACCESSOR_BUILDVAL(IRCallee, IRCallee, self->wrapped->regparms, regparms, "i")
PYMARE_ACCESSOR_BUILDVAL(IRCallee, IRCallee, self->wrapped->name, name, "s")
PYMARE_ACCESSOR_BUILDVAL(IRCallee, IRCallee, self->wrapped->mcx_mask, mcx_mask, "I")
PYMARE_ACCESSOR_BUILDVAL(IRCallee, IRCallee, self->wrapped->addr, addr, "K")

static PyGetSetDef pyIRCallee_getseters[] =
{
	PYMARE_ACCESSOR_DEF(IRCallee, wrapped),
	PYMARE_ACCESSOR_DEF(IRCallee, regparms),
	PYMARE_ACCESSOR_DEF(IRCallee, name),
	PYMARE_ACCESSOR_DEF(IRCallee, mcx_mask),
	PYMARE_ACCESSOR_DEF(IRCallee, addr),
	{NULL}
};

static PyMethodDef pyIRCallee_methods[] =
{
	PYVEX_METHDEF_STANDARD(IRCallee),
	{NULL}  /* Sentinel */
};

PYMARE_TYPEOBJECT("pyvex", IRCallee);
