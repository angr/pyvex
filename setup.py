import os
import urllib2
import subprocess
from distutils.errors import LibError
from distutils.core import setup
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

def _build_vex():
	if subprocess.call(['make'], cwd=VEX_PATH) != 0:
		raise LibError("Unable to build libVEX.")

def _build_pyvex():
	e = os.environ.copy()
	e['VEX_PATH'] = os.path.join('..', VEX_PATH)
	if subprocess.call(['make'], cwd='pyvex_c', env=e) != 0:
		raise LibError("Unable to build pyvex-static.")

class build(_build):
	def run(self):
		self.execute(_build_vex, (), msg="Building libVEX")
		self.execute(_build_pyvex, (), msg="Building pyvex-static")
		_build.run(self)
cmdclass = { 'build': build }

try:
	from setuptools.command.develop import develop as _develop
	class develop(_develop):
		def run(self):
			self.execute(_build_vex, (), msg="Building libVEX")
			self.execute(_build_pyvex, (), msg="Building pyvex-static")
			_develop.run(self)
	cmdclass['develop'] = develop
except ImportError:
	print "Proper 'develop' support unavailable."

setup(
	name="pyvex", version="1.0",
	packages=['pyvex', 'pyvex.IRConst', 'pyvex.IRExpr', 'pyvex.IRStmt'],
	install_requires=[i.strip() for i in open('requirements.txt').readlines() if 'git' not in i],
	data_files=[
		('lib', ('pyvex_c/pyvex_static.so',),),
	],
	cmdclass=cmdclass,
)
