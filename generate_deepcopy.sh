#!/bin/bash

VALGRIND_HOME=~/valgrind/valgrind-3.8.1/

cat > pyvex/pyvex_deepcopy.c <<END
#include <libvex_ir.h>
#include <stdlib.h>
#include <assert.h>

#include "pyvex_logging.h"
#include "pyvex_deepcopy.h"

#define vpanic(x) { error(x "\n"); assert(0); }

END

cat $VALGRIND_HOME/VEX/priv/ir_defs.c  | grep -A1000000 "(Deep) copy constructors" | grep -B10000000 "Primop types" | sed -e "s/shallowCopy/pyvex_shallowCopy/g" -e "s/deepCopy/pyvex_deepCopy/g" -e "s/LibVEX_Alloc/malloc/g" >> pyvex/pyvex_deepcopy.c
