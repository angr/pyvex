import os
import urllib2
import subprocess
from distutils.errors import LibError
from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext as _build_ext

VEX_LIB_NAME = "vex" # can also be vex-amd64-linux
VEX_PATH = "./vex"
if not os.path.exists(VEX_PATH):
    VEX_URL = 'https://git.seclab.cs.ucsb.edu/gitlab/angr/vex/repository/archive.tar.gz?ref=dev'
    with open('vex.tar.gz', 'w') as v:
        v.write(urllib2.urlopen(VEX_URL).read())
    if subprocess.call(['tar', 'xzf', 'vex.tar.gz']) != 0:
        raise LibError("Unable to retrieve libVEX.")
    VEX_PATH='./vex.git'

class build_ext(_build_ext):
    @staticmethod
    def _build_vex():
        if subprocess.call(['make'], cwd=VEX_PATH) != 0:
            raise LibError("Unable to build libVEX.")

    def run(self):
        self.execute(self._build_vex, (), msg="Building libVEX")
        _build_ext.run(self)

setup(
    name="pyvex", version="1.0",
    packages=['pyvex', 'pyvex.IRConst', 'pyvex.IRExpr', 'pyvex.IRStmt'],
    ext_modules=[
        Extension(
            "pyvex_c", ['pyvex_c/pyvex_static.c'], include_dirs=[os.path.join(VEX_PATH, 'pub')],
            library_dirs=[VEX_PATH], libraries=[VEX_LIB_NAME],
            extra_objects=[], define_macros=[('PYVEX_STATIC', '1')],
            extra_compile_args=["--std=c99"]
        )
    ],
    data_files=[
        ('lib', (os.path.join(VEX_PATH, 'libvex.so'),)),
    ],
    cmdclass={'build_ext': build_ext},
)
