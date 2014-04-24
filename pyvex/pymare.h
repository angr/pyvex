// This code is GPLed by Yan Shoshitaishvili
//
// pymare is a set of nightmarish macros designed to make any attempt at
// making reasonably-OO Python bindings to C structures a complete and utter
// disaster. With any luck, I've succeeded in my goals.
//
// Use with great abandon (of your sanity).


#ifndef __PYMARE_H
#define __PYMARE_H

extern PyObject *PyMareError;

//////////////////////////////////////////////////////////////////////////////
//
// First, we're going to make some macros to make creating classes as hard as
// possible.
//
// Buckle up.
//

// this defines the python struct itself. Basically, we just have a pointer to
// the C object.
#define PYMARE_STRUCT(type) typedef struct { PyObject_HEAD type *wrapped; } py##type;

// we have a default allocator that sets the wrapped struct to NULL
#define PYMARE_NEW(type) \
	static PyObject * \
	py##type##_new(PyTypeObject *type, PyObject *args, PyObject *kwds) \
  	{ \
  		py##type *self; \
		self = (py##type *)type->tp_alloc(type, 0); \
		if (self != NULL) self->wrapped = NULL; \
		return (PyObject *)self; \
	}

// and a default deallocator that doesn't do anything useful. You might want to
// override this if you don't want your shit to leak everywhere.
#define PYMARE_DEALLOC(type) static void py##type##_dealloc(py##type* self) { self->ob_type->tp_free((PyObject*)self); }

// You stick this in your header file, cry a little, and hope for the best.
#define PYMARE_TYPEHEADER(type) \
	extern PyTypeObject py##type##Type; \
	PYMARE_STRUCT(type); \
	PyObject *wrap_##type(type *);

// this macro creates a base type object with some various defaults. It expects
// you to provide your own init function!
#define PYMARE_TYPEOBJECT(base, type) \
	PyTypeObject py##type##Type = \
	{ \
		PyObject_HEAD_INIT(NULL) \
		0,						/*ob_size*/ \
		base"."#type,					/*tp_name*/ \
		sizeof(py##type),				/*tp_basicsize*/ \
		0,						/*tp_itemsize*/ \
		(destructor)py##type##_dealloc,			/*tp_dealloc*/ \
		0,						/*tp_print*/ \
		0,						/*tp_getattr*/ \
		0,						/*tp_setattr*/ \
		0,						/*tp_compare*/ \
		0,						/*tp_repr*/ \
		0,						/*tp_as_number*/ \
		0,						/*tp_as_sequence*/ \
		0,						/*tp_as_mapping*/ \
		0,						/*tp_hash */ \
		0,						/*tp_call*/ \
		0,						/*tp_str*/ \
		0,						/*tp_getattro*/ \
		0,						/*tp_setattro*/ \
		0,						/*tp_as_buffer*/ \
		Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/*tp_flags*/ \
		"Bindings for "#type" objects",		 	/* tp_doc */ \
		0,					 	/* tp_traverse */ \
		0,					 	/* tp_clear */ \
		0,					 	/* tp_richcompare */ \
		0,					 	/* tp_weaklistoffset */ \
		0,					 	/* tp_iter */ \
		0,					 	/* tp_iternext */ \
		py##type##_methods,				/* tp_methods */ \
		py##type##_members,				/* tp_members */ \
		py##type##_getseters,				/* tp_getset */ \
		0,						/* tp_base */ \
		0,						/* tp_dict */ \
		0,						/* tp_descr_get */ \
		0,						/* tp_descr_set */ \
		0,						/* tp_dictoffset */ \
		(initproc)py##type##_init,	  		/* tp_init */ \
		0,						/* tp_alloc */ \
		py##type##_new,					/* tp_new */ \
	};

//////////////////////////////////////////////////////////////////////////////
// 
// Now we'll facilitate some really painful access to struct members.
//
//
#define PYMARE_ACCESSOR_DEF(type, attr) {#attr, (getter)py##type##_##get##_##attr, (setter)py##type##_##set##_##attr, #attr, NULL}

// these getters and setters use Py_BuildValue and Py_ArgParse for
// facilitating access to primitive and Python types
#define PYMARE_GETTER_BUILDVAL(type, intype, attr, name, format) \
	static PyObject *py##type##_get_##name(py##intype *self, void *closure) \
	{ \
		PyObject *o = Py_BuildValue(format, attr); \
		if (!o) { PyErr_SetString(PyMareError, "Error in py"#type"_get_"#name"\n"); return NULL; } \
		return o; \
	}
#define PYMARE_SETTER_BUILDVAL(type, intype, attr, name, format) \
	static int py##type##_set_##name(py##intype *self, PyObject *value, void *closure) \
	{ \
		if (!PyArg_Parse(value, format, &(attr))) return -1; \
		return 0; \
	}
#define PYMARE_ACCESSOR_BUILDVAL(a,b,c,d,e) PYMARE_SETTER_BUILDVAL(a,b,c,d,e) PYMARE_GETTER_BUILDVAL(a,b,c,d,e)

// these getters and setters encapsulate C pointer members using PyCapsule
#define PYMARE_GETTER_CAPSULE(type, intype, attr, name, ctype) \
	static PyObject *py##type##_get_##name(py##intype *self, void *closure) \
	{ \
		if (attr == NULL) { Py_RETURN_NONE; } \
		return PyCapsule_New(attr, #ctype, NULL); \
	}
#define PYMARE_SETTER_CAPSULE(type, intype, attr, name, ctype) \
	static int py##type##_set_##name(py##intype *self, PyObject *value, void *closure) \
	{ \
		ctype *i = (ctype *)PyCapsule_GetPointer(value, #ctype); \
		if (i) { attr = i; return 0; } \
		else return -1; \
	}
#define PYMARE_ACCESSOR_CAPSULE(a,b,c,d,e) PYMARE_SETTER_CAPSULE(a,b,c,d,e) PYMARE_GETTER_CAPSULE(a,b,c,d,e)

// these getters and setters wrap members in the proper pymare-exposed classes
#define PYMARE_GETTER_WRAPPED(type, intype, attr, name, attrtype) \
	static PyObject *py##type##_get_##name(py##intype *self, void *closure) \
	{ \
		if (attr == NULL) { Py_RETURN_NONE; } \
		PyObject *o = wrap_##attrtype(attr); \
		if (!o) { PyErr_SetString(PyMareError, "Error in py"#type"_get_"#name"\n"); return NULL; } \
		return o; \
	}
#define PYMARE_SETTER_WRAPPED(type, intype, attr, name, attrtype) \
	static int py##type##_set_##name(py##intype *self, PyObject *value, void *closure) \
	{ \
		PYMARE_CHECKTYPE(value, py##attrtype##Type, return -1); \
		attr = ((py##attrtype *) value)->wrapped; \
		return 0; \
	}
#define PYMARE_ACCESSOR_WRAPPED(a,b,c,d,e) PYMARE_SETTER_WRAPPED(a,b,c,d,e) PYMARE_GETTER_WRAPPED(a,b,c,d,e)

// these getters and setters wrap members in the proper pymare-exposed classes
#define PYMARE_GETTER_DIRECT_WRAPPED(type, attr, name, attrtype) \
	static PyObject *py##type##_get_##name(py##type *self, void *closure) \
	{ \
		if (attr == NULL) { Py_RETURN_NONE; } \
		PyObject *o = wrap_direct_##attrtype(attr); \
		if (!o) { PyErr_SetString(PyMareError, "Error in py"#type"_get_"#name"\n"); return NULL; } \
		return o; \
	}
#define PYMARE_SETTER_DIRECT_WRAPPED(type, attr, name, attrtype) \
	static int py##type##_set_##name(py##type *self, PyObject *value, void *closure) \
	{ \
		PYMARE_CHECKTYPE(value, py##attrtype##Type, return -1); \
		attr = ((py##attrtype *) value)->wrapped; \
		return 0; \
	}
#define PYMARE_ACCESSOR_DIRECT_WRAPPED(a,b,c,d) PYMARE_SETTER_DIRECT_WRAPPED(a,b,c,d) PYMARE_GETTER_DIRECT_WRAPPED(a,b,c,d)

// these getters and setters translate between a C enum and a Python string
#define PYMARE_GETTER_ENUM(type, intype, attr, name, e) \
	static PyObject *py##type##_get_##name(py##intype *self, void *closure) \
	{ \
		PyObject *tstr = e##_to_pystr(attr); \
		if (tstr) return tstr; \
		PyErr_SetString(PyMareError, "Unrecognized "#e); \
		return NULL; \
	}
#define PYMARE_SETTER_ENUM(type, intype, attr, name, e) \
	static int py##type##_set_##name(py##intype *self, PyObject *value, void *closure) \
	{ \
		e t = pystr_to_##e(value); \
		if (t != -1) { attr = t; return 0; } \
		else { PyErr_SetString(PyMareError, "Unrecognized "#e); return -1; } \
	}
#define PYMARE_ACCESSOR_ENUM(a,b,c,d,e) PYMARE_SETTER_ENUM(a,b,c,d,e) PYMARE_GETTER_ENUM(a,b,c,d,e)

///////////////////////////////////////////////////////////////////////////////
//
// Now we move on to wrapping pointers to structs in the PyMare types above

// type-checking is important in some cases
#define PYMARE_CHECKTYPE(object, type, fail) if (!PyObject_TypeCheck((PyObject *)object, &type)) { PyErr_SetString(PyMareError, "Incorrect type passed in. Needs "#type); fail; }

// this can be put in a constructor to check for the presense of a "wrap"
// keyword argument containing a PyCapsule object, and use that for the
// wrapped thingy
#define PYMARE_WRAP_CONSTRUCTOR(type) \
	{ \
		PyObject *wrap_object; \
		if (kwargs) \
		{ \
			wrap_object = PyDict_GetItemString(kwargs, "wrap"); \
			if (wrap_object) \
			{ \
				self->wrapped = PyCapsule_GetPointer(wrap_object, #type); \
				if (!self->wrapped) return -1; \
				return 0; \
			} \
		} \
	}

// this is a wrap helper. It takes a pointer to the type and calls the
// constructor with a "wrap" argument. This should probably be changed to
// use alloc and set the "wrapped" member directly.
#define PYMARE_WRAP(type) \
	PyObject *wrap_##type(type *i) \
	{ \
		PyObject *args = Py_BuildValue(""); \
		PyObject *kwargs = Py_BuildValue("{s:O}", "wrap", PyCapsule_New(i, #type, NULL)); \
		PyObject *o = PyObject_Call((PyObject *)&py##type##Type, args, kwargs); \
		Py_DECREF(args); \
		Py_DECREF(kwargs); \
		return (PyObject *)o; \
	}

#define PYMARE_DIRECT_WRAP(type) \
	PyObject *wrap_direct_##type(type *w) \
	{ \
  		py##type *self; \
		self = (py##type *)type->tp_alloc(type, 0); \
		if (self != NULL) self->wrapped = w; \
		return (PyObject *)self; \
	}

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
		if (s) Py_INCREF(s); \
		return s; \
	} \
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
	if (v == -1) { PyErr_SetString(PyMareError, "Unrecognized "#type); fail; } }
#define PYMARE_ENUM_TOSTR(type, v, v_str, fail) \
	{ v_str = type##_to_str(v); \
	if (v_str == NULL) { PyErr_SetString(PyMareError, "Unrecognized "#type); fail; } }

///////////////////////////////////////////////////////////////////////////////
//
// And, lastly, the actual initialization stuff for the module.
// 
#define PYMARE_INITTYPE(type) \
	{ if (PyType_Ready(&py##type##Type) < 0) { fprintf(stderr, "py"#type"Type not ready...\n"); return; } \
	Py_INCREF(&py##type##Type); PyModule_AddObject(module, #type, (PyObject *)&py##type##Type); }

#define PYMARE_INITSUBTYPE(base, sub) \
	{ if (PyType_Ready(&py##base##sub##Type) < 0) { fprintf(stderr, "py"#base#sub"Type not ready...\n"); return; } \
	Py_INCREF(&py##base##sub##Type); \
	if (PyDict_SetItemString((PyObject *)py##base##Type.tp_dict, #sub, (PyObject *)&py##base##sub##Type) == -1) \
	{ \
		fprintf(stderr, "failed to set "#sub" as attribute of py"#base"Type...\n"); \
		return; \
	} }





// Are your eyes bleeding yet?
#endif
