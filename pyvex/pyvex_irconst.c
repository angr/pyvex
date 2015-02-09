// This code is GPLed by Yan Shoshitaishvili

#include <Python.h>
#include <libvex.h>

#include "pyvex_enums.h"
#include "pyvex_types.h"
#include "pyvex_export.h"
#include "pyvex_logging.h"


#define PYVEX_EXPORT_CONST(name, type, format) \
PyObject *export_IRConst##name(IRConst *c) \
{ \
	PyObject *r = PyObject_CallObject(pyvexIRConst##name, NULL); \
	PYVEX_SETATTRSTRING(r, "value", Py_BuildValue(format, c->Ico.name)); \
	return r; \
}

PYVEX_EXPORT_CONST(U1, unsigned char, "b");
PYVEX_EXPORT_CONST(U8, unsigned char, "b");
PYVEX_EXPORT_CONST(U16, unsigned short int, "H");
PYVEX_EXPORT_CONST(U32, unsigned int, "I");
PYVEX_EXPORT_CONST(U64, unsigned long long, "K");
PYVEX_EXPORT_CONST(F32, float, "f");
PYVEX_EXPORT_CONST(F32i, unsigned int, "I");
PYVEX_EXPORT_CONST(F64, double, "d");
PYVEX_EXPORT_CONST(F64i, unsigned long long, "K");
PYVEX_EXPORT_CONST(V128, unsigned short int, "H");
PYVEX_EXPORT_CONST(V256, unsigned int, "I");

PyObject *export_IRConst(IRConst *c)
{
	if (!c) Py_RETURN_NONE;

	PyObject *r;

	switch (c->tag)
	{
		case Ico_U1: r = export_IRConstU1(c); break;
		case Ico_U8: r = export_IRConstU8(c); break;
		case Ico_U16: r = export_IRConstU16(c); break;
		case Ico_U32: r = export_IRConstU32(c); break;
		case Ico_U64: r = export_IRConstU64(c); break;
		case Ico_F32: r = export_IRConstF32(c); break;
		case Ico_F32i: r = export_IRConstF32i(c); break;
		case Ico_F64: r = export_IRConstF64(c); break;
		case Ico_F64i: r = export_IRConstF64i(c); break;
		case Ico_V128: r = export_IRConstV128(c); break;
		case Ico_V256: r = export_IRConstV256(c); break;
		default:
			pyvex_error("PyVEX: Unknown/unsupported IRConstTag %s\n", IRConstTag_to_str(c->tag));
			Py_RETURN_NONE;
	}

	PYVEX_SETATTRSTRING(r, "tag", export_IRConstTag(c->tag));
	PYVEX_SETATTRSTRING(r, "type", export_IRType(typeOfIRConst(c)));

	return r;
}
