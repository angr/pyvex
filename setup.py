import os
import urllib2
import subprocess
import sys
from distutils.errors import LibError
from distutils.core import setup
from distutils.command.build import build as _build

if sys.platform == 'darwin':
    library_file = "pyvex_static.dylib"
else:
    library_file = "pyvex_static.so"


VEX_LIB_NAME = "vex" # can also be vex-amd64-linux
VEX_PATH = "vex"
if not os.path.exists(VEX_PATH):
    VEX_URL = 'https://github.com/angr/vex/archive/dev.tar.gz'
    with open('dev.tar.gz', 'w') as v:
        v.write(urllib2.urlopen(VEX_URL).read())
    if subprocess.call(['tar', 'xzf', 'dev.tar.gz']) != 0:
        raise LibError("Unable to retrieve libVEX.")
    VEX_PATH='./vex-dev'

def _build_vex():
    if subprocess.call(['make'], cwd=VEX_PATH) != 0:
        raise LibError("Unable to build libVEX.")

def _build_pyvex():
    e = os.environ.copy()
    e['VEX_PATH'] = '../' + VEX_PATH
    if subprocess.call(['make'], cwd='pyvex_c', env=e) != 0:
        raise LibError("Unable to build pyvex-static.")

def _build_ffi():
    if subprocess.call(['python', 'make_ffi.py', os.path.join(VEX_PATH,'pub')]) != 0:
        raise LibError("Unable to generate cffi file.")

class build(_build):
    def run(self):
        self.execute(_build_vex, (), msg="Building libVEX")
        self.execute(_build_pyvex, (), msg="Building pyvex-static")
        self.execute(_build_ffi, (), msg="Creating CFFI defs file")
        _build.run(self)
cmdclass = { 'build': build }

try:
    from setuptools.command.develop import develop as _develop
    class develop(_develop):
        def run(self):
            self.execute(_build_vex, (), msg="Building libVEX")
            self.execute(_build_pyvex, (), msg="Building pyvex-static")
            self.execute(_build_ffi, (), msg="Creating CFFI defs file")
            _develop.run(self)
    cmdclass['develop'] = develop
except ImportError:
    print "Proper 'develop' support unavailable."

setup(
    name="pyvex", version='4.5.9.29', description="A Python interface to libVEX and VEX IR.",
    packages=['pyvex', 'pyvex.IRConst', 'pyvex.IRExpr', 'pyvex.IRStmt'],
    data_files=[
        ('lib', (os.path.join('pyvex_c', library_file),),),
    ],
    cmdclass=cmdclass,
    install_requires=[ 'pycparser', 'cffi>=1.0.3', 'archinfo' ]
)
