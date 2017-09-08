# pylint: disable=no-name-in-module,import-error
import os
import subprocess
import sys
import shutil
import glob
import tarfile
import multiprocessing

IS_PYTHON2 = sys.version_info < (3, 0)
if IS_PYTHON2:
    from urllib2 import urlopen
else:
    from urllib.request import urlopen

import platform

PROJECT_DIR = os.path.dirname(os.path.realpath(__file__))

try:
    from setuptools import setup
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    from distutils.core import setup
    packages = []
    for root, _, filenames in os.walk(PROJECT_DIR):
        if "__init__.py" in filenames:
            packages.append(root)

from distutils.util import get_platform
from distutils.errors import LibError
from distutils.command.build import build as _build

if sys.platform in ('win32', 'cygwin'):
    LIBRARY_FILE = 'pyvex.dll'
    STATIC_LIBRARY_FILE = 'pyvex.lib'
elif sys.platform == 'darwin':
    LIBRARY_FILE = "libpyvex.dylib"
    STATIC_LIBRARY_FILE = 'libpyvex.a'
else:
    LIBRARY_FILE = "libpyvex.so"
    STATIC_LIBRARY_FILE = 'libpyvex.a'


VEX_LIB_NAME = "vex" # can also be vex-amd64-linux
VEX_PATH = os.path.abspath(os.path.join(PROJECT_DIR, '..', 'vex'))

if not os.path.exists(VEX_PATH):
    VEX_URL = 'https://github.com/angr/vex/archive/master.tar.gz'
    with open('master.tar.gz', 'wb') as v:
        v.write(urlopen(VEX_URL).read())
    with tarfile.open('master.tar.gz') as tar:
        tar.extractall()
    VEX_PATH = os.path.abspath('vex-master')

def _build_vex():
    e = os.environ.copy()
    e['MULTIARCH'] = '1'
    e['DEBUG'] = '1'

    cmd1 = ['nmake', '/f', 'Makefile-msvc', 'all']
    cmd2 = ['make', '-f', 'Makefile-gcc', '-j', str(multiprocessing.cpu_count()), 'all']
    for cmd in (cmd1, cmd2):
        try:
            if subprocess.call(cmd, cwd=VEX_PATH, env=e) == 0:
                break
        except OSError:
            continue
    else:
        raise LibError("Unable to build libVEX.")

def _build_pyvex():
    e = os.environ.copy()
    e['VEX_LIB_PATH'] = VEX_PATH
    e['VEX_INCLUDE_PATH'] = os.path.join(VEX_PATH, 'pub')
    e['VEX_LIB_FILE'] = os.path.join(VEX_PATH, 'libvex.lib')

    cmd1 = ['nmake', '/f', 'Makefile-msvc']
    cmd2 = ['make', '-j', str(multiprocessing.cpu_count())]
    for cmd in (cmd1, cmd2):
        try:
            if subprocess.call(cmd, cwd='pyvex_c', env=e) == 0:
                break
        except OSError as err:
            continue
    else:
        raise LibError("Unable to build libpyvex.")

def _shuffle_files():
    pyvex_lib_dir = os.path.join(PROJECT_DIR, 'pyvex', 'lib')
    pyvex_include_dir = os.path.join(PROJECT_DIR, 'pyvex', 'include')

    shutil.rmtree(pyvex_lib_dir, ignore_errors=True)
    shutil.rmtree(pyvex_include_dir, ignore_errors=True)
    os.mkdir(pyvex_lib_dir)
    os.mkdir(pyvex_include_dir)

    pyvex_c_dir = os.path.join(PROJECT_DIR, 'pyvex_c')

    shutil.copy(os.path.join(pyvex_c_dir, LIBRARY_FILE), pyvex_lib_dir)
    shutil.copy(os.path.join(pyvex_c_dir, STATIC_LIBRARY_FILE), pyvex_lib_dir)
    shutil.copy(os.path.join(pyvex_c_dir, 'pyvex.h'), pyvex_include_dir)
    for f in glob.glob(os.path.join(VEX_PATH, 'pub', '*')):
        shutil.copy(f, pyvex_include_dir)

def _build_ffi():
    import make_ffi
    try:
        make_ffi.doit(os.path.join(VEX_PATH, 'pub'))
    except Exception as e:
        print(repr(e))
        raise

class build(_build):
    def run(self):
        self.execute(_build_vex, (), msg="Building libVEX")
        self.execute(_build_pyvex, (), msg="Building libpyvex")
        self.execute(_shuffle_files, (), msg="Copying libraries and headers")
        self.execute(_build_ffi, (), msg="Creating CFFI defs file")
        _build.run(self)
cmdclass = { 'build': build }

try:
    from setuptools.command.develop import develop as _develop
    from setuptools.command.bdist_egg import bdist_egg as _bdist_egg
    class develop(_develop):
        def run(self):
            self.execute(_build_vex, (), msg="Building libVEX")
            self.execute(_build_pyvex, (), msg="Building libpyvex")
            self.execute(_shuffle_files, (), msg="Copying libraries and headers")
            self.execute(_build_ffi, (), msg="Creating CFFI defs file")
            _develop.run(self)
    cmdclass['develop'] = develop

    class bdist_egg(_bdist_egg):
        def run(self):
            self.run_command('build')
            _bdist_egg.run(self)
    cmdclass['bdist_egg'] = bdist_egg
except ImportError:
    print("Proper 'develop' support unavailable.")

if 'bdist_wheel' in sys.argv and '--plat-name' not in sys.argv:
    sys.argv.append('--plat-name')
    name = get_platform()
    if 'linux' in name:
        # linux_* platform tags are disallowed because the python ecosystem is fubar
        # linux builds should be built in the centos 5 vm for maximum compatibility
        sys.argv.append('manylinux1_' + platform.machine())
    else:
        # https://www.python.org/dev/peps/pep-0425/
        sys.argv.append(name.replace('.', '_').replace('-', '_'))

setup(
    name="pyvex", version='7.0.0.0rc1', description="A Python interface to libVEX and VEX IR.",
    packages=['pyvex', 'pyvex.lift', 'pyvex.lift.util'],
    cmdclass=cmdclass,
    install_requires=[ 'pycparser', 'cffi>=1.0.3', 'archinfo', 'bitstring' ],
    setup_requires=[ 'pycparser', 'cffi>=1.0.3' ],
    include_package_data=True,
    package_data={
        'pyvex': ['lib/*', 'include/*']
    }
)
