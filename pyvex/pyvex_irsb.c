// This code is GPLed by Yan Shoshitaishvili

#include <Python.h>
#include <libvex.h>

#include "pyvex_enums.h"
#include "pyvex_types.h"
#include "pyvex_export.h"
#include "pyvex_static.h"
#include "enum_macros.h"

extern VexTranslateArgs vta;

PyObject *init_IRSB(PyObject *self, PyObject *args, PyObject *kwargs)
{
	if (!kwargs || PyDict_Size(kwargs) == 0)
	{
		PyErr_SetString(PyVEXError, "no arguments provided");
		return NULL;
	}

	unsigned char *bytes = NULL;
	unsigned long long int mem_addr = 0;
	int num_inst = -1;
	int num_bytes = -1;
	const char *arch_str = NULL;
	const char *endness_str = NULL;
	VexArch arch = VexArch_INVALID;
	VexEndness endness = VexEndness_INVALID;
	int basic = 0;
	int bytes_offset = 0;
	int traceflags = 0;
	IRSB *irsb = NULL;
	PyObject *py_irsb = NULL;

	static char *kwlist[] = {"py_irsb", "bytes", "mem_addr", "num_inst", "arch", "endness", "basic", "bytes_offset", "traceflags", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|s#KIssIiI", kwlist, &py_irsb, &bytes, &num_bytes, &mem_addr, &num_inst, &arch_str, &endness_str, &basic, &bytes_offset, &traceflags)) return NULL;

	if (!arch_str) arch_str = "VexArchAMD64";
	PYMARE_ENUM_FROMSTR(VexArch, arch, arch_str, return NULL);
	if (!endness_str) endness_str = "VexEndnessLE";
	PYMARE_ENUM_FROMSTR(VexEndness, endness, endness_str, return NULL);

	if (num_bytes == 0)
	{
		PyErr_SetString(PyVEXError, "No bytes provided");
		return NULL;
	}

	vta.traceflags = traceflags;

	if (num_bytes > 0)
	{
		try
		{
			vex_init();
			if (num_inst > -1)
			{
				irsb = vex_block_inst(arch, endness, bytes + bytes_offset, mem_addr, num_inst);
			}
			else
			{
				irsb = vex_block_bytes(arch, endness, bytes + bytes_offset, mem_addr, num_bytes, basic);
			}
		}
		catch (VEXError)
		{
			irsb = NULL;
			PyErr_SetString(PyVEXError, E4C_EXCEPTION.message);
		}
		if (irsb == NULL) return NULL;

		//ppIRSB(irsb);
		export_IRSB(py_irsb, irsb);
		Py_RETURN_NONE;
	}

	PyErr_SetString(PyVEXError, "Not enough arguments provided.");
	return NULL;
}

PyObject *export_IRSB(PyObject *r, IRSB *irsb)
{
	PYVEX_SETATTRSTRING(r, "offsIP", PyInt_FromLong(irsb->offsIP));
	PYVEX_SETATTRSTRING(r, "stmts_used", PyInt_FromLong(irsb->stmts_used));
	PYVEX_SETATTRSTRING(r, "jumpkind", export_IRJumpKind(irsb->jumpkind));
	PYVEX_SETATTRSTRING(r, "tyenv", export_IRTypeEnv(irsb->tyenv));
	PYVEX_SETATTRSTRING(r, "next", export_IRExpr(irsb->next, irsb->tyenv));

	// statements
	PyObject *statements = PyTuple_New(irsb->stmts_used);
	for (int i = 0; i < irsb->stmts_used; i++)
	{
		PyTuple_SetItem(statements, i, export_IRStmt(irsb->stmts[i], irsb->tyenv));
	}
	PYVEX_SETATTRSTRING(r, "statements", statements);

	// instructions
	long instructions = 0;
	for (int i = 0; i < irsb->stmts_used; i++) if (irsb->stmts[i]->tag == Ist_IMark) instructions++;
	PYVEX_SETATTRSTRING(r, "instructions", PyInt_FromLong(instructions));

	// size
	long size = 0;
	for (int i = 0; i < irsb->stmts_used; i++)
	{
		if (irsb->stmts[i]->tag == Ist_IMark) size += irsb->stmts[i]->Ist.IMark.len;
	}
	PYVEX_SETATTRSTRING(r, "size", PyInt_FromLong(size));

	return r;
}
