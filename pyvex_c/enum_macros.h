// This code is GPLed by Yan Shoshitaishvili

#ifndef __ENUM_MACROS_H
#define __ENUM_MACROS_H

extern PyObject *PyMareError;

///////////////////////////////////////////////////////////////////////////////
//
// Now we get to handle enums. Oh yay.
//

// conversion between C enums and Python strings
#define PYMARE_ENUM_FUNCS(type) \
	type pystr_to_##type(PyObject *o) \
	{ \
		PyObject *e = PyDict_GetItem(dict_##type##_fromstr, o); \
		if (!e) return -1; \
		return PyLong_AsLong(e); \
	} \
	PyObject *type##_to_pystr(type e) \
	{ \
		PyObject *pe = PyInt_FromLong(e); \
		PyObject *s = PyDict_GetItem(dict_##type##_tostr, pe); \
		Py_DECREF(pe); \
		if (s) Py_INCREF(s); /*else __asm__("int3");*/ \
		return s; \
	} \
	PyObject *export_##type(type e) { return type##_to_pystr(e); } \
	type str_to_##type(const char *s) \
	{ \
		PyObject *e = PyDict_GetItemString(dict_##type##_fromstr, s); \
		if (!e) return -1; \
		return PyLong_AsLong(e); \
	} \
	const char *type##_to_str(type e) \
	{ \
		PyObject *pe = PyInt_FromLong(e); \
		PyObject *s = PyDict_GetItem(dict_##type##_tostr, pe); \
		Py_DECREF(pe); \
		if (s) return PyString_AsString(s); \
		else return NULL; \
	}

// put this in the enum header file
#define PYMARE_ENUM_HEADER(type) \
	PyObject *type##_to_pystr(type e); type pystr_to_##type(PyObject *s); \
	const char *type##_to_str(type e); type str_to_##type(const char *s); \
	extern PyObject *dict_##type##_fromstr; \
	extern PyObject *dict_##type##_tostr; \

#define PYMARE_ENUM_OBJECTS(type) \
	PyObject *dict_##type##_fromstr; \
	PyObject *dict_##type##_tostr; \

// and put it all together with the dict (int the C file)
#define PYMARE_ENUM_CONVERSION(type) \
	PYMARE_ENUM_OBJECTS(type) \
	PYMARE_ENUM_FUNCS(type)

#define PYMARE_ENUM_INIT(type, module) \
	dict_##type##_fromstr = PyDict_New(); \
	dict_##type##_tostr = PyDict_New(); \
	if (module) \
	{ \
		PyModule_AddObject(module, "enum_"#type"_fromstr", dict_##type##_fromstr); \
		PyModule_AddObject(module, "enum_"#type"_tostr", dict_##type##_tostr); \
	}

// and then use these to add the enums themselves
#define PYMARE_ENUM_ADD(type, e) \
	PyDict_SetItemString(dict_##type##_fromstr, #e, PyLong_FromLong(e)); \
	PyDict_SetItem(dict_##type##_tostr, PyLong_FromLong(e), PyString_FromString(#e));

// compatibility
#define PYMARE_ENUM_FROMSTR(type, v, v_str, fail) \
	{ v = str_to_##type(v_str); \
	if (v == -1) { PyErr_SetString(PyVEXError, "Unrecognized "#type); fail; } }
#define PYMARE_ENUM_TOSTR(type, v, v_str, fail) \
	{ v_str = type##_to_str(v); \
	if (v_str == NULL) { PyErr_SetString(PyVEXError, "Unrecognized "#type); fail; } }




// Are your eyes bleeding yet?
#endif
