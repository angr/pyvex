// This code is GPLed by Yan Shoshitaishvili

#ifndef __MACROS_H
#define __MACROS_H

///////////////////////////////////////////////////////////////////////////////
// Memory management crap. VEX does its own memory management, so if we don't
// want the structures freed out from under us, we need to copy them out
#ifdef PYVEX_STATIC
	#define PYVEX_COPYOUT(type, x) pyvex_deepCopy##type(x)
#else
	#define PYVEX_COPYOUT(type, x) x
#endif

///////////////////////////////////////////////////////////////////////////////
// These are various macros to make defining PyVEX python classes easier
// - method declarations for Python
#define PYVEX_METHDEF_PP(type) {"pp", (PyCFunction)py##type##_pp, METH_NOARGS, "Prints the "#type}
#define PYVEX_METHDEF_DEEPCOPY(type) {"deepCopy", (PyCFunction)py##type##_deepCopy, METH_NOARGS, "Deep-copies the "#type}
#define PYVEX_METHDEF_STANDARD(type) PYVEX_METHDEF_PP(type), PYVEX_METHDEF_DEEPCOPY(type)

// - the methods themselves
#define PYVEX_METH_PP(type) static PyObject * py##type##_pp(py##type* self) { pp##type(self->wrapped); Py_RETURN_NONE; }

#ifdef PYVEX_STATIC
	#define PYVEX_METH_DEEPCOPY(type) \
		static PyObject * py##type##_deepCopy(py##type* self) { return (PyObject *)wrap_##type(pyvex_deepCopy##type(self->wrapped)); }
#else
	#define PYVEX_METH_DEEPCOPY(type) \
		static PyObject * py##type##_deepCopy(py##type* self) { return (PyObject *)wrap_##type(deepCopy##type(self->wrapped)); }
#endif

#define PYVEX_METH_STANDARD(type) PYVEX_METH_PP(type) PYVEX_METH_DEEPCOPY(type)

// this is to handle VEX's union-style subtyping
#define PYVEX_SUBTYPEOBJECT(type, base) \
	typedef struct { py##base base; } py##base##type; \
	PyTypeObject py##base##type##Type = \
	{ \
		PyObject_HEAD_INIT(NULL) \
		0,						/*ob_size*/ \
		"pyvex."#base"."#type,				/*tp_name*/ \
		sizeof(py##base##type),				/*tp_basicsize*/ \
		0,						/*tp_itemsize*/ \
		0,						/*tp_dealloc*/ \
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
		Py_TPFLAGS_DEFAULT,				/*tp_flags*/ \
		"Binding for "#type"-type "#base" objects",	/* tp_doc */ \
		0,					 	/* tp_traverse */ \
		0,					 	/* tp_clear */ \
		0,					 	/* tp_richcompare */ \
		0,					 	/* tp_weaklistoffset */ \
		0,					 	/* tp_iter */ \
		0,					 	/* tp_iternext */ \
		py##base##type##_methods,			/* tp_methods */ \
		0,						/* tp_members */ \
		py##base##type##_getseters,			/* tp_getset */ \
		&py##base##Type,				/* tp_base */ \
		0,						/* tp_dict */ \
		0,						/* tp_descr_get */ \
		0,						/* tp_descr_set */ \
		0,						/* tp_dictoffset */ \
		(initproc)py##base##type##_init,		/* tp_init */ \
		0,						/* tp_alloc */ \
		0,						/* tp_new */ \
	};

#define PYVEX_INITSUBTYPE(base, sub) \
	{ if (PyType_Ready(&py##base##sub##Type) < 0) { fprintf(stderr, "py"#base#sub"Type not ready...\n"); return; } \
	Py_INCREF(&py##base##sub##Type); \
	if (PyDict_SetItemString((PyObject *)py##base##Type.tp_dict, #sub, (PyObject *)&py##base##sub##Type) == -1) \
	{ \
		fprintf(stderr, "failed to set "#sub" as attribute of py"#base"Type...\n"); \
		return; \
	} }

#define PYVEX_WRAPCASE(vtype, tagtype, tag) case tagtype##tag: t = &py##vtype##tag##Type; break;

#define PYVEX_CATCH_VEX_ERROR catch (VEXError) { \
		PyErr_SetString(PyVEXError, E4C_EXCEPTION.message); \
		return NULL; \
	}

#endif
