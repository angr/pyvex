// This code is GPLed by Yan Shoshitaishvili

#include <Python.h>
#include <structmember.h>
#include <libvex.h>

#include "pyvex_enums.h"
#include "pyvex_types.h"
#include "pyvex_export.h"

PyObject *export_IRCallee(IRCallee *c)
{
	if (!c) Py_RETURN_NONE;

	PyObject *r = PyObject_CallObject(pyvexIRCallee, PyTuple_Pack(4,
        PyInt_FromLong(c->regparms),
        PyString_FromString(c->name),
        PyInt_FromLong((unsigned long long)c->addr),
        PyInt_FromLong(c->mcx_mask)));

	return r;
}
