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

////////////////////////
// IRRegArray base class //
////////////////////////

PYVEX_NEW(IRRegArray)
PYVEX_DEALLOC(IRRegArray)
PYVEX_WRAP(IRRegArray)
PYVEX_METH_STANDARD(IRRegArray)

static int
pyIRRegArray_init(pyIRRegArray *self, PyObject *args, PyObject *kwargs)
{
	PYVEX_WRAP_CONSTRUCTOR(IRRegArray);

	Int base;
	IRType elemTy; const char *elemTy_str;
	Int nElems;

	static char *kwlist[] = {"base", "element_type", "num_elements", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "isi", kwlist, &base, &elemTy_str, &nElems)) return -1;
	PYVEX_ENUM_FROMSTR(IRType, elemTy, elemTy_str, return -1)

	self->wrapped = PYVEX_COPYOUT(IRRegArray, mkIRRegArray(base, elemTy, nElems));
	return 0;
}

PYVEX_ACCESSOR_WRAPPED(IRRegArray, IRRegArray, self->wrapped, wrapped, IRRegArray)
PYVEX_ACCESSOR_BUILDVAL(IRRegArray, IRRegArray, self->wrapped->base, base, "i")
PYVEX_ACCESSOR_ENUM(IRRegArray, IRRegArray, self->wrapped->elemTy, element_type, IRType)
PYVEX_ACCESSOR_BUILDVAL(IRRegArray, IRRegArray, self->wrapped->nElems, num_elements, "i")

PyObject *pyIRRegArray_equals(pyIRRegArray *self, pyIRRegArray *other)
{
	PYVEX_CHECKTYPE(other, pyIRRegArrayType, Py_RETURN_FALSE);

	if (!eqIRRegArray(self->wrapped, other->wrapped)) { Py_RETURN_FALSE; }
	Py_RETURN_TRUE;
}

static PyGetSetDef pyIRRegArray_getseters[] =
{
	PYVEX_ACCESSOR_DEF(IRRegArray, wrapped),
	PYVEX_ACCESSOR_DEF(IRRegArray, base),
	PYVEX_ACCESSOR_DEF(IRRegArray, element_type),
	PYVEX_ACCESSOR_DEF(IRRegArray, num_elements),
	{NULL}
};

static PyMethodDef pyIRRegArray_methods[] =
{
	PYVEX_METHDEF_STANDARD(IRRegArray),
	{"equals", (PyCFunction)pyIRRegArray_equals, METH_O, "Checks equality with another reg array."},
	{NULL}
};

static PyMemberDef pyIRRegArray_members[] = { {NULL} };
PYVEX_TYPEOBJECT(IRRegArray);
