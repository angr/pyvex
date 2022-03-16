# pylint: disable=no-name-in-module,import-error,missing-class-docstring
import os
import subprocess
import sys
import shutil
import glob
import tarfile
import multiprocessing
import time
from urllib.request import urlopen

from setuptools import setup, find_packages
from setuptools.command.build_ext import build_ext as st_build_ext
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
        raise

class build_ext(st_build_ext):
    def run(self):
        self.execute(_build_vex, (), msg="Building libVEX")
        self.execute(_build_pyvex, (), msg="Building libpyvex")
        self.execute(_shuffle_files, (), msg="Copying libraries and headers")
        self.execute(_build_ffi, (), msg="Creating CFFI defs file")
        super().run()

class sdist(st_sdist):
    def run(self):
        self.execute(_clean_bins, (), msg="Removing binaries")
        self.execute(_copy_sources, (), msg="Copying VEX sources")
        super().run()

cmdclass = {
    'build_ext': build_ext,
    'clean': sdist,
}

setup(
    name="pyvex",
    version='9.1.gitrolling',
    description="A Python interface to libVEX and VEX IR",
    python_requires='>=3.6',
    url='https://github.com/angr/pyvex',
    packages=find_packages(),
    cmdclass=cmdclass,
    install_requires=[
        'pycparser',
        'cffi>=1.0.3',
        'archinfo==9.1.gitrolling',
        'bitstring',
        'future',
    ],
    setup_requires=[ 'pycparser', 'cffi>=1.0.3' ],
    include_package_data=True,
    package_data={
        'pyvex': ['lib/*', 'include/*', 'py.typed']
    }
)
