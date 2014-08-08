#!/usr/bin/env python

import re
import sys

vex_home = sys.argv[1] if len(sys.argv) > 1 else "/home/yans/vex"

input = open(vex_home + "/pub/libvex_ir.h").read()
input += open(vex_home + "/pub/libvex.h").read()

out = """
#include <libvex.h>
#include <stdio.h>
#include <string.h>
#include "pyvex_macros.h"
#include "pyvex_logging.h"

"""

errors = ["VexArchInfo"]

enums = [
	("VexArch", r"VexArch\w+"),
	("VexEndness", r"VexEndness\w+"),
	("IRExprTag", r"Iex_\w+"),
	("IRStmtTag", r"Ist_\w+"),
	("IREndness", r"Iend_\w+"),
	("IRMBusEvent", r"Imbe_\w+"),
	("IREffect", r"Ifx_\w+"),
	("IRJumpKind", r"Ijk_\w+"),
	("IRConstTag", r"Ico_\w+"),
	("IRType", r"Ity_[\w\d]+"),
	("IROp", r"Iop_\w+"),
	("IRLoadGOp", r"ILGop_\w+"),
]

ignore = { "Ity_I", "Ity_Bit", "Iex_Tmp", "Iex_Store", "Ijk_Sys_", "Iop_PwFoo16x4", "Iop_PAddL16Ux4", "Iop_PAddL16Ux4" }

to_str = """
const char *{0}_to_str({0} e)
{{
	switch(e)
	{{
{1}
		default:
			error("PyVEX: Unknown {0}");
			return NULL;
	}}
}}
"""	

from_str = """
{0} str_to_{0}(const char *s)
{{
{1}

	return -1;
}}
"""

# http://stackoverflow.com/questions/480214
def uniq(seq):
    seen = set()
    seen_add = seen.add
    return [ x for x in seq if x not in seen and not seen_add(x)]

for ty,enum in enums:
	insts = uniq(re.findall(enum, input))
	insts = [x for x in insts if x not in errors and x not in ignore ]
	for i in insts:
		print "PYMARE_ENUM_ADD(%s, %s)" % (ty, i)

#print out
