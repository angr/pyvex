
/*--------------------------------------------------------------------*/
/*--- Nulgrind: The minimal Valgrind tool.			   pg_main.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Nulgrind, the minimal Valgrind tool,
   which does no instrumentation or analysis.

   Copyright (C) 2002-2012 Nicholas Nethercote
	  njn@valgrind.org

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_options.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include <dlfcn.h>

static const HChar* clo_python = "";
static const HChar* clo_module = "";

static Bool pg_process_cmd_line_option(const HChar* arg)
{
   if VG_STR_CLO(arg, "--python", clo_python) {}
   if VG_STR_CLO(arg, "--module", clo_module) {}
   else
	  return False;

   tl_assert(clo_module);
   tl_assert(clo_module[0]);
   tl_assert(clo_python);
   tl_assert(clo_python[0]);
   return True;
}

static void pg_print_usage(void)
{ 
   VG_(printf)(
"	--python=<path>		   path to python shared object\n"
"	--module=<name>		   python module to load\n"
   );
}

static void pg_print_debug_usage(void)
{ 
   VG_(printf)(
"(none)\n"
   );
}

//////////////////
// Python stuff //
//////////////////
void (*Py_Initialize)();
int (*PyRun_SimpleString)(const char *);
void *python_pointer;

static void pg_post_clo_init(void)
{
	python_pointer = dlopen(clo_python, RTLD_NOW | RTLD_GLOBAL);
	tl_assert(python_pointer);

	Py_Initialize = dlsym(python_pointer, "Py_Initialize");
	PyRun_SimpleString = dlsym(python_pointer, "PyRun_SimpleString");
	tl_assert(Py_Initialize);

	Py_Initialize();
	PyRun_SimpleString("print 'test success'");

	// add sys path
	//if (clo_module_dir[0])
	//{
	//	PyRun_SimpleString("import sys");
	//	char mod_dir[1024];
	//	VG_(snprintf)(mod_dir, 1024, "sys.path.append('%s')", clo_module_dir);
	//	PyRun_SimpleString(mod_dir);
	//}

	//mod_name = PyString_FromString(clo_module);
	//module = PyImport_Import(mod_name);
	//tl_assert(module);
	//mod_dict = PyModule_GetDict(module);
	//py_instrument = PyDict_GetItemString(module, "instrument");
}

static
IRSB* pg_instrument ( VgCallbackClosure* closure,
					  IRSB* bb,
					  VexGuestLayout* layout, 
					  VexGuestExtents* vge,
					  IRType gWordTy, IRType hWordTy )
{
	//PyObject_CallObject(py_instrument, PyTuple_New(0));
	return bb;
}

static void pg_fini(Int exitcode)
{
}

static void pg_pre_clo_init(void)
{
	VG_(details_name)			("Nulgrind");
	VG_(details_version)			(NULL);
	VG_(details_description)		("the minimal Valgrind tool");
	VG_(details_copyright_author)		("Copyright (C) 2002-2012, and GNU GPL'd, by Yan Shoshitaishvili.");
	VG_(details_bug_reports_to)		(VG_BUGS_TO);
	
	VG_(details_avg_translation_sizeB)	( 275 );
	VG_(basic_tool_funcs)			(pg_post_clo_init,
	     					 pg_instrument,
	     					 pg_fini);
	VG_(needs_command_line_options)		(pg_process_cmd_line_option,
						pg_print_usage,
						pg_print_debug_usage);
}

VG_DETERMINE_INTERFACE_VERSION(pg_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end														  ---*/
/*--------------------------------------------------------------------*/
