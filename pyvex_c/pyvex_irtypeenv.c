// This code is GPLed by Yan Shoshitaishvili

#include <Python.h>
#include <libvex.h>

#include "pyvex_enums.h"
#include "pyvex_types.h"
#include "pyvex_export.h"

PyObject *export_IRTypeEnv(IRTypeEnv *t)
{
	if (!t) Py_RETURN_NONE;

	PyObject *types = PyTuple_New(t->types_used);
	for (int i = 0; i < t->types_used; i++)
	{
		PyTuple_SetItem(types, i, export_IRType(t->types[i]));
	}

	PyObject *r = PyObject_CallObject(pyvexIRTypeEnv, PyTuple_Pack(1, types));
	return r;
}
