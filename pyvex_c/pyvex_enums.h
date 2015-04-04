// This code is GPLed by Yan Shoshitaishvili

#pragma once

#include "libvex_ir.h"
#include <Python.h>
#include "enum_macros.h"

PYMARE_ENUM_HEADER(VexArch)
PYMARE_ENUM_HEADER(VexEndness)
PYMARE_ENUM_HEADER(IRExprTag)
PYMARE_ENUM_HEADER(IRStmtTag)
PYMARE_ENUM_HEADER(IREndness)
PYMARE_ENUM_HEADER(IRMBusEvent)
PYMARE_ENUM_HEADER(IREffect)
PYMARE_ENUM_HEADER(IRJumpKind)
PYMARE_ENUM_HEADER(IRConstTag)
PYMARE_ENUM_HEADER(IRType)
PYMARE_ENUM_HEADER(IROp)
PYMARE_ENUM_HEADER(IRLoadGOp)
void pyvex_init_enums(PyObject *module);
