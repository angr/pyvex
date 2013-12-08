#!/usr/bin/env python

import re

valgrind_home = "/usr"

input = open(valgrind_home + "/include/valgrind/libvex_ir.h").read()
input += open(valgrind_home + "/include/valgrind/libvex.h").read()

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
	("IRExprTag", r"Iex_\w+"),
	("IRStmtTag", r"Ist_\w+"),
	("IREndness", r"Iend_\w+"),
	("IRMBusEvent", r"Imbe_\w+"),
	("IREffect", r"Ifx_\w+"),
	("IRJumpKind", r"Ijk_\w+"),
	("IRConstTag", r"Ico_\w+"),
	("IRType", r"Ity_\w+"),
	("IROp", r"Iop_\w+"),
]

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
	insts = [x for x in insts if x not in errors]
	to_strs = "\n".join("\t\tPYVEX_ENUMCONV_TOSTRCASE("+x+")" for x in insts)
	out += to_str.format(ty, to_strs)
	from_strs = "\n".join("\tPYVEX_ENUMCONV_FROMSTR("+x+")" for x in insts)
	out += from_str.format(ty, from_strs)

print out
