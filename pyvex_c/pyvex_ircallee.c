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

	PyObject *regparms = PyInt_FromLong(c->regparms);
	PyObject *name = PyString_FromString(c->name);
	PyObject *addr = PyInt_FromLong((unsigned long long)c->addr);
	PyObject *mcx_mask = PyInt_FromLong(c->mcx_mask);
	PyObject *args = PyTuple_Pack(4, regparms, name, addr, mcx_mask);

	PyObject *r = PyObject_CallObject(pyvexIRCallee, args);

	Py_DECREF(regparms);
	Py_DECREF(name);
	Py_DECREF(addr);
	Py_DECREF(mcx_mask);
	Py_DECREF(args);

	return r;
}
