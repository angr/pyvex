// This code is GPLed by Yan Shoshitaishvili

#include <Python.h>
#include <libvex.h>

#include "pyvex_enums.h"
#include "pyvex_types.h"
#include "pyvex_export.h"

// TODO: support for eqIRRegArray

PyObject *export_IRRegArray(IRRegArray *arr)
{
	PyObject *r = PyObject_CallObject(pyvexIRRegArray, NULL);

	PYVEX_SETATTRSTRING(r, "base", PyInt_FromLong(arr->base));
	PYVEX_SETATTRSTRING(r, "element_type", export_IRType(arr->elemTy));
	PYVEX_SETATTRSTRING(r, "elemTy", export_IRType(arr->elemTy));
	PYVEX_SETATTRSTRING(r, "nElems", PyInt_FromLong(arr->nElems));

	return r;
}
