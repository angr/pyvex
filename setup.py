import os
import urllib2
import subprocess
from distutils.errors import LibError
from distutils.core import setup, Extension
from distutils.command.build import build as _build


VEX_LIB_NAME = "vex" # can also be vex-amd64-linux
VEX_PATH = "./vex"
if not os.path.exists(VEX_PATH):
    VEX_URL = 'https://git.seclab.cs.ucsb.edu/gitlab/angr/vex/repository/archive.tar.gz?ref=dev'
    with open('vex.tar.gz', 'w') as v:
        v.write(urllib2.urlopen(VEX_URL).read())
    if subprocess.call(['tar', 'xzf', 'vex.tar.gz']) != 0:
        raise LibError("Unable to retrieve libVEX.")
    VEX_PATH='./vex.git'

c_files = [ "pyvex_c/pyvex.c", "pyvex_c/pyvex_irsb.c", "pyvex_c/pyvex_irstmt.c", "pyvex_c/pyvex_irtypeenv.c", "pyvex_c/pyvex_irexpr.c", "pyvex_c/pyvex_enums.c", "pyvex_c/pyvex_irconst.c", "pyvex_c/pyvex_ircallee.c", "pyvex_c/pyvex_irregarray.c", "pyvex_c/pyvex_logging.c", "pyvex_c/pyvex_static.c"]

class build(_build):
    @staticmethod
    def _build_vex():
        if subprocess.call(['make'], cwd=VEX_PATH) != 0:
            raise LibError("Unable to build libVEX.")

    def run(self):
        self.execute(self._build_vex, (), msg="Building libVEX")
        _build.run(self)

setup(
    name="pyvex", version="1.0",
    packages=['pyvex', 'pyvex.IRConst', 'pyvex.IRExpr', 'pyvex.IRStmt'],
    ext_modules=[
        Extension(
            "pyvex_c", c_files, include_dirs=[os.path.join(VEX_PATH, 'pub')],
            library_dirs=[VEX_PATH], libraries=[VEX_LIB_NAME],
            extra_objects=[], define_macros=[('PYVEX_STATIC', '1')],
            extra_compile_args=["--std=c99"]
        )
    ],
    cmdclass={'build': build},
)
