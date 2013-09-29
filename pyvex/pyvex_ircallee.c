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

PYVEX_NEW(IRCallee)
PYVEX_DEALLOC(IRCallee)
PYVEX_WRAP(IRCallee)
PYVEX_METH_STANDARD(IRCallee)

static int
pyIRCallee_init(pyIRCallee *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRCallee);

	Int regparms;
	char *name;
	UInt mcx_mask = 123456789;
	unsigned long long addr;

	static char *kwlist[] = {"regparms", "name", "addr", "mcx_mask", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "isK|I", kwlist, &regparms, &name, &addr, &mcx_mask)) return -1;
	if (regparms < 0 || regparms > 3) { PyErr_SetString(VexException, "regparms out of range"); return -1; }

	self->wrapped = PYVEX_COPYOUT(IRCallee, mkIRCallee(regparms, name, (void *)addr));
	if (mcx_mask != 123456789) self->wrapped->mcx_mask = mcx_mask;
	return 0;
}

static PyMemberDef pyIRCallee_members[] = { {NULL} };

PYVEX_ACCESSOR_WRAPPED(IRCallee, IRCallee, self->wrapped, wrapped, IRCallee)
PYVEX_ACCESSOR_BUILDVAL(IRCallee, IRCallee, self->wrapped->regparms, regparms, "i")
PYVEX_ACCESSOR_BUILDVAL(IRCallee, IRCallee, self->wrapped->name, name, "s")
PYVEX_ACCESSOR_BUILDVAL(IRCallee, IRCallee, self->wrapped->mcx_mask, mcx_mask, "I")
PYVEX_ACCESSOR_BUILDVAL(IRCallee, IRCallee, self->wrapped->addr, addr, "K")

static PyGetSetDef pyIRCallee_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRCallee, wrapped),
	PYVEX_ACCESSOR_DEF(IRCallee, regparms),
	PYVEX_ACCESSOR_DEF(IRCallee, name),
	PYVEX_ACCESSOR_DEF(IRCallee, mcx_mask),
	PYVEX_ACCESSOR_DEF(IRCallee, addr),
	{NULL}
};

static PyMethodDef pyIRCallee_methods[] =
{
	PYVEX_METHDEF_STANDARD(IRCallee),
	{NULL}  /* Sentinel */
};

PYVEX_TYPEOBJECT(IRCallee);
