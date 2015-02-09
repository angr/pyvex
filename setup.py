from distutils.core import setup, Extension

#import os
#vgprefix = os.environ["HOME"] + "/valgrind/inst39"
#vgprefix = "/usr"
#vgprefix = "/usr"

VEX_INCLUDE = "./vex_include"
VEX_LIB = "./vex_lib"
VEX_LIB_NAME = "vex" # can also be vex-amd64-linux

c_files = [ "pyvex_c/pyvex.c", "pyvex_c/pyvex_irsb.c", "pyvex_c/pyvex_irstmt.c", "pyvex_c/pyvex_irtypeenv.c", "pyvex_c/pyvex_irexpr.c", "pyvex_c/pyvex_enums.c", "pyvex_c/pyvex_irconst.c", "pyvex_c/pyvex_ircallee.c", "pyvex_c/pyvex_irregarray.c", "pyvex_c/pyvex_logging.c", "pyvex_c/pyvex_static.c"]

setup(name="pyvex", version="1.0",
	 packages=['pyvex', 'pyvex.IRConst', 'pyvex.IRExpr', 'pyvex.IRStmt'],
      ext_modules=[Extension(
		"pyvex_c",
		c_files,
		include_dirs=[VEX_INCLUDE],
		library_dirs=[VEX_LIB],
		libraries=[VEX_LIB_NAME],
		extra_objects=[], #, vgprefix + "/lib/valgrind/libvex-amd64-linux.a"],
	        define_macros=[('PYVEX_STATIC', '1')],
		extra_compile_args=["--std=c99"]),
	],
     )
