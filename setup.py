# pylint: disable=no-name-in-module,import-error
import os
import subprocess
import sys
import shutil
import glob
import tarfile
import multiprocessing
import time
from urllib.request import urlopen
import platform

if bytes is str:
    raise Exception("This module is designed for python 3 only. Please install an older version to use python 2.")

PROJECT_DIR = os.path.dirname(os.path.realpath(__file__))
LIB_DIR = os.path.join(PROJECT_DIR, 'pyvex', 'lib')
INCLUDE_DIR = os.path.join(PROJECT_DIR, 'pyvex', 'include')

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
from distutils.command.sdist import sdist as _sdist

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
    VEX_PATH = os.path.join(PROJECT_DIR, 'vex')

if not os.path.exists(VEX_PATH):
    VEX_PATH = os.path.join(PROJECT_DIR, 'vex-master')

if not os.path.exists(VEX_PATH):
    sys.__stderr__.write('###########################################################################\n')
    sys.__stderr__.write('WARNING: downloading vex sources directly from github.\n')
    sys.__stderr__.write('If this strikes you as a bad idea, please abort and clone the angr/vex repo\n')
    sys.__stderr__.write('into the same folder containing the pyvex repo.\n')
    sys.__stderr__.write('###########################################################################\n')
    sys.__stderr__.flush()
    time.sleep(10)

    VEX_URL = 'https://github.com/angr/vex/archive/master.tar.gz'
    with open('vex-master.tar.gz', 'wb') as v:
        v.write(urlopen(VEX_URL).read())
    with tarfile.open('vex-master.tar.gz') as tar:
        tar.extractall()

def _build_vex():
    e = os.environ.copy()
    e['MULTIARCH'] = '1'
    e['DEBUG'] = '1'

    cmd1 = ['nmake', '/f', 'Makefile-msvc', 'all']
    cmd2 = ['make', '-f', 'Makefile-gcc', '-j', str(multiprocessing.cpu_count()), 'all']
    cmd3 = ['gmake', '-f', 'Makefile-gcc', '-j', str(multiprocessing.cpu_count()), 'all']
    for cmd in (cmd1, cmd2, cmd3):
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
    cmd3 = ['gmake', '-j', str(multiprocessing.cpu_count())]
    for cmd in (cmd1, cmd2, cmd3):
        try:
            if subprocess.call(cmd, cwd='pyvex_c', env=e) == 0:
                break
        except OSError as err:
            continue
    else:
        raise LibError("Unable to build libpyvex.")

def _shuffle_files():
    shutil.rmtree(LIB_DIR, ignore_errors=True)
    shutil.rmtree(INCLUDE_DIR, ignore_errors=True)
    os.mkdir(LIB_DIR)
    os.mkdir(INCLUDE_DIR)

    pyvex_c_dir = os.path.join(PROJECT_DIR, 'pyvex_c')

    shutil.copy(os.path.join(pyvex_c_dir, LIBRARY_FILE), LIB_DIR)
    shutil.copy(os.path.join(pyvex_c_dir, STATIC_LIBRARY_FILE), LIB_DIR)
    shutil.copy(os.path.join(pyvex_c_dir, 'pyvex.h'), INCLUDE_DIR)
    for f in glob.glob(os.path.join(VEX_PATH, 'pub', '*')):
        shutil.copy(f, INCLUDE_DIR)

def _clean_bins():
    shutil.rmtree(LIB_DIR, ignore_errors=True)
    shutil.rmtree(INCLUDE_DIR, ignore_errors=True)

def _copy_sources():
    local_vex_path = os.path.join(PROJECT_DIR, 'vex')
    assert local_vex_path != VEX_PATH
    shutil.rmtree(local_vex_path, ignore_errors=True)
    os.mkdir(local_vex_path)

    vex_src = ['LICENSE.GPL', 'LICENSE.README', 'Makefile-gcc', 'Makefile-msvc', 'common.mk', 'pub/*.h', 'priv/*.c', 'priv/*.h', 'auxprogs/*.c']
    for spec in vex_src:
        dest_dir = os.path.join(local_vex_path, os.path.dirname(spec))
        if not os.path.isdir(dest_dir):
            os.mkdir(dest_dir)
        for srcfile in glob.glob(os.path.join(VEX_PATH, spec)):
            shutil.copy(srcfile, dest_dir)

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

class sdist(_sdist):
    def run(self):
        self.execute(_clean_bins, (), msg="Removing binaries")
        self.execute(_copy_sources, (), msg="Copying VEX sources")
        _sdist.run(self)

cmdclass = { 'build': build, 'sdist': sdist }

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
    name="pyvex", version='8.20.6.1', description="A Python interface to libVEX and VEX IR",
    python_requires='>=3.6',
    url='https://github.com/angr/pyvex',
    packages=packages,
    cmdclass=cmdclass,
    install_requires=[
        'pycparser',
        'cffi>=1.0.3',
        'archinfo==8.20.6.1',
        'bitstring',
        'future',
    ],
    setup_requires=[ 'pycparser', 'cffi>=1.0.3' ],
    include_package_data=True,
    package_data={
        'pyvex': ['lib/*', 'include/*', 'py.typed']
    }
)
