# pyvex

A python interface into Valgrind's VEX IR! This was created mainly to utilize VEX for static analysis, but it would be cool to integrate this with Valgrind as well. To that end, I've started writing pygrind to pass instrumentation over to Python, but this doesn't work yet.

## Build

For now, pyvex requires valgrind to be compiled with fPIC:

	mkdir ~/valgrind
	cd ~/valgrind
	wget http://valgrind.org/downloads/valgrind-3.8.1.tar.bz2
	tar xvfj valgrind-3.8.1.tar.bz2
	cd valgrind-3.8.1
	CFLAGS=-fPIC ./configure --prefix=$HOME/valgrind/inst
	make
	make install

Great! Now you can build pyvex.

	python setup.py build

Sweet! Now you'll notice that two libraries are built. pyvex.so is pyvex with all the functionality, and pyvex\_dynamic is pyvex without the ability to statically create IRSBs from provided bytes. With the latter, the only pre-made IRSBs would presumably come from Valgrind at runtime, but since that doesn't work yet, the latter one is rather useless.

## Use

You can use pyvex pretty easily. For now, it only supports translation and pretty printing:

	import pyvex
	irsb = pyvex.IRSB(bytes="\x55\xc3") # translates "push ebp; ret" to VEX IR
	irsb.pp() # prints the VEX IR

Awesome stuff!

## Next steps

- Get pyvex working in Valgrind, dynamically.
 - this requires getting the python interpreter to play nice with Valgrind. It's unclear if this is possible.
- Debug this stuff.

## Bugs

- help() is sorely lacking
- pretty-printing an emptyIRSB segfaults
- there is no memory management. VEX is kind of weird with this, so care will have to be taken... It shouldn't be an issue when doing the normal VEX workflow, but for long-running static analysis, the blocks will probably have to be copied out with a rewritten deepCopier.
- converting from string to tag is currently very slow (a hastily written consecutive bunch of strcmps)
- IRCallee assumes that addresses are 64-bytes long, and will corrupt memory otherwise. This can be fixed by writing a getter/setter instead of using the macroed ones.
- CCalls are created by creating the IRCallee and manually building the args list, instead of by calling the helper functions. Not sure if this is good or bad. On the other hand, Dirty statements are created through helper functions.
- deepCopying a binder IRExpr seems to crash VEX
- IRDirty's fxState array access is untested
- equality (for those things that easily have it) should be implemented as a rich comparator
