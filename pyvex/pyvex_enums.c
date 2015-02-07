#include <Python.h>
#include <libvex.h>
#include <stdio.h>
#include <string.h>
#include "pyvex_logging.h"
#include "pyvex_enums.h"
#include "enum_macros.h"

PYMARE_ENUM_CONVERSION(VexArch)
PYMARE_ENUM_CONVERSION(VexEndness)
PYMARE_ENUM_CONVERSION(IRExprTag)
PYMARE_ENUM_CONVERSION(IRStmtTag)
PYMARE_ENUM_CONVERSION(IREndness)
PYMARE_ENUM_CONVERSION(IRMBusEvent)
PYMARE_ENUM_CONVERSION(IREffect)
PYMARE_ENUM_CONVERSION(IRJumpKind)
PYMARE_ENUM_CONVERSION(IRConstTag)
PYMARE_ENUM_CONVERSION(IRType)
PYMARE_ENUM_CONVERSION(IROp)
PYMARE_ENUM_CONVERSION(IRLoadGOp)

void pyvex_init_enums(PyObject *module)
{
	PYMARE_ENUM_INIT(VexArch, module)
	PYMARE_ENUM_INIT(VexEndness, module)
	PYMARE_ENUM_INIT(IRExprTag, module)
	PYMARE_ENUM_INIT(IRStmtTag, module)
	PYMARE_ENUM_INIT(IREndness, module)
	PYMARE_ENUM_INIT(IRMBusEvent, module)
	PYMARE_ENUM_INIT(IREffect, module)
	PYMARE_ENUM_INIT(IRJumpKind, module)
	PYMARE_ENUM_INIT(IRConstTag, module)
	PYMARE_ENUM_INIT(IRType, module)
	PYMARE_ENUM_INIT(IROp, module)
	PYMARE_ENUM_INIT(IRLoadGOp, module)

	#include "generated_enums"
}
