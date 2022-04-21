# pylint: disable=no-name-in-module,import-error,missing-class-docstring
import os
import subprocess
import sys
import shutil
import glob
import multiprocessing
import platform
from distutils.command.build import build as st_build
from distutils.util import get_platform

from setuptools import setup
from setuptools.command.develop import develop as st_develop
from setuptools.command.sdist import sdist as st_sdist
from setuptools.errors import LibError

PROJECT_DIR = os.path.dirname(os.path.realpath(__file__))
LIB_DIR = os.path.join(PROJECT_DIR, 'pyvex', 'lib')
INCLUDE_DIR = os.path.join(PROJECT_DIR, 'pyvex', 'include')


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
VEX_PATH = os.path.abspath(os.path.join(PROJECT_DIR, 'vex'))


def _build_vex():
    if len(os.listdir(VEX_PATH)) == 0:
        raise LibError("vex submodule not cloned correctly, aborting.\n"
                "This may be fixed with `git submodule update --init`")

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

def _build_ffi():
    sys.path.append(".") # PEP 517 doesn't include . in sys.path
    import make_ffi
    sys.path.pop()
    try:
        make_ffi.doit(os.path.join(VEX_PATH, 'pub'))
    except Exception as e:
        raise

class build(st_build):
    def run(self, *args):
        self.execute(_build_vex, (), msg="Building libVEX")
        self.execute(_build_pyvex, (), msg="Building libpyvex")
        self.execute(_shuffle_files, (), msg="Copying libraries and headers")
        self.execute(_build_ffi, (), msg="Creating CFFI defs file")
        super().run(*args)

class develop(st_develop):
    def run(self):
        self.run_command("build")
        super().run()

class sdist(st_sdist):
    def run(self, *args):
        self.execute(_clean_bins, (), msg="Removing binaries")
        super().run(*args)

cmdclass = {
    'build': build,
    'develop': develop,
    'sdist': sdist,
}

if 'bdist_wheel' in sys.argv and '--plat-name' not in sys.argv:
    sys.argv.append('--plat-name')
    name = get_platform()
    if 'linux' in name:
        sys.argv.append('manylinux2014_' + platform.machine())
    else:
        # https://www.python.org/dev/peps/pep-0425/
        sys.argv.append(name.replace('.', '_').replace('-', '_'))

setup(cmdclass=cmdclass)
