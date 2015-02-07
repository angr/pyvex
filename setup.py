from distutils.core import setup, Extension

#import os
#vgprefix = os.environ["HOME"] + "/valgrind/inst39"
#vgprefix = "/usr"
#vgprefix = "/usr"

VEX_INCLUDE = "./vex_include"
VEX_LIB = "./vex_lib"
VEX_LIB_NAME = "vex" # can also be vex-amd64-linux

c_files = [ "pyvex/pyvex.c", "pyvex/pyvex_irsb.c", "pyvex/pyvex_irstmt.c", "pyvex/pyvex_irtypeenv.c", "pyvex/pyvex_irexpr.c", "pyvex/pyvex_enums.c", "pyvex/pyvex_irconst.c", "pyvex/pyvex_ircallee.c", "pyvex/pyvex_irregarray.c", "pyvex/pyvex_logging.c", "pyvex/pyvex_static.c"]

setup(name="pyvex", version="1.0",
	 py_modules=['pyvex'],
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
