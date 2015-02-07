// This code is GPLed by Yan Shoshitaishvili

#include <Python.h>
#include <structmember.h>
#include <libvex.h>

#include "pyvex_enums.h"
#include "pyvex_types.h"
#include "pyvex_export.h"

PyObject *export_IRCallee(IRCallee *c)
{
	PyObject *r = PyObject_CallObject(pyvexIRCallee, NULL);

	PYVEX_SETATTRSTRING(r, "regparms", PyInt_FromLong(c->regparms));
	PYVEX_SETATTRSTRING(r, "name", PyString_FromString(c->name));
	PYVEX_SETATTRSTRING(r, "mcx_mask", PyInt_FromLong(c->mcx_mask));
	PYVEX_SETATTRSTRING(r, "addr", PyInt_FromLong((unsigned long long)c->addr));

	return r;
}
