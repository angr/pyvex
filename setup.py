from distutils.core import setup, Extension, Command
from distutils.ccompiler import new_compiler
from distutils import sysconfig

import os
import subprocess
vgprefix = os.environ["HOME"] + "/valgrind/inst39"
#vgprefix = "/usr"

common_files = ["pyvex/pyvex.c", "pyvex/pyvex_irsb.c", "pyvex/pyvex_irstmt.c", "pyvex/pyvex_irtypeenv.c", "pyvex/pyvex_irexpr.c", "pyvex/pyvex_enums.c", 
"pyvex/pyvex_irconst.c", "pyvex/pyvex_ircallee.c", "pyvex/pyvex_irregarray.c", "pyvex/pyvex_logging.c" ]
static_files = common_files + [ "pyvex/pyvex_static.c", "pyvex/pyvex_deepcopy.c"]

class StaticPythonCmd(Command):
	description = "build a static version of python with pyvex included"
	user_options = []
	def initialize_options(self): pass
	def finalize_options(self): pass
	def run(self):
		comp = new_compiler()
		comp.add_include_dir(vgprefix + "/include/valgrind")
		comp.add_library_dir(vgprefix + "/lib/valgrind")
		comp.add_library("vex-amd64-linux")
		comp.define_macro("PYVEX_STATIC", "1")
		comp.define_macro("PYVEX_STATIC_PYTHON", "1")
		comp.add_include_dir(sysconfig.get_python_inc())
		comp.add_library_dir(sysconfig.get_python_lib())
		comp.add_library("python2.7")
		os = comp.compile(static_files, extra_preargs=["--std=c99"], output_dir="build")
		comp.link_executable(os, "pyvex_python")

setup(name="pyvex", version="1.0",
      ext_modules=[Extension(
		"pyvex",
		static_files,
		include_dirs=[vgprefix + "/include/valgrind"],
		library_dirs=[vgprefix + "/lib/valgrind"],
		libraries=["vex-amd64-linux"],
		extra_objects=[], #, vgprefix + "/lib/valgrind/libvex-amd64-linux.a"],
	        define_macros=[('PYVEX_STATIC', '1')],
		extra_compile_args=["--std=c99"]),
     # Extension(
	#	"pyvex_dynamic",
	#        common_files,
	#	include_dirs=[vgprefix + "/include/valgrind"],
	#	library_dirs=[vgprefix + "/lib/valgrind"],
	#	libraries=["vex-amd64-linux"],
	#	extra_objects=[], #, vgprefix + "/lib/valgrind/libvex-amd64-linux.a"],
	#	extra_compile_args=["--std=c99"])
	],
	cmdclass = {'build_static': StaticPythonCmd}
     )
