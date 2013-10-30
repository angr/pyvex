# pyvex

A python interface into Valgrind's VEX IR! This was created mainly to utilize VEX for static analysis, but it would be cool to integrate this with Valgrind as well. To that end, I've started writing pygrind to pass instrumentation over to Python, but this doesn't work yet.

## Build

### Compiling VEX

First, get the VEX code.

	mkdir ~/valgrind
	cd ~/valgrind
	wget http://valgrind.org/downloads/valgrind-3.8.1.tar.bz2
	tar xvfj valgrind-3.8.1.tar.bz2
	cd valgrind-3.8.1

If you want to be able to VEX stuff for different platforms than what you're running on, you need to disable VEX's native code generation, as that'll just make everything crash. You can apply a patch to disable this:

	patch -p1 < /path/to/pyvex/valgrind_static_3.8.1.patch

For now, pyvex requires valgrind to be compiled with fPIC:

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

## Static gotchas

To use PyVEX statically, VEX's memory management needs to be worked around. The issue is that all of the nice, helpful, constructor functions (ie, emptyIRSB(), mkIRCallee(), etc) allocate memory managed by VEX, and VEX is liable to free it or reuse it at any time. Thus, everything needs to be deepCopied out of VEX.

There are a few approaches to solving this. To work around the issue, we could simply pull all of these functions out of VEX and use our local copies, using reasonable memory management. However, that's a lot of functions to pull out and keep synced. We took the (possibly worse) approach of deepCopying everything away from VEX. The file generate\_deepcopy.sh copies out the deepCopy operations out of VEX, does some sedding to rename the functions, and we call those to pull everything out from VEX.

One issue with that the fact that we need to explicitly replace functions, hence the giant list of defines in that shell script. Whenever Valgrind adds more of these, pyvex might silently segfault until they're added to the replacement list.

## Next steps

- Get pyvex working in Valgrind, dynamically.
 - this requires getting the python interpreter to play nice with Valgrind. It's unclear if this is possible.
- Debug this stuff.

## Bugs/Issues

- Some class members are named incorrectly. I started out trying to name things nicer, but then realized that the naming should be consistent with the C structs. The inconsistencies should be fixed.
- help() is sorely lacking
- The class objects for the different sub-statements, sub-expressions, and sub-constants get inherited for instances of these classes. This is kindof ugly (ie, pyvex.IRStmt.NoOp().WrTmp is a valid reference to the WrTmp class).
- pretty-printing an emptyIRSB segfaults
- when used statically, memory is never freed
- converting from string to tag is currently very slow (a hastily written consecutive bunch of strcmps)
- IRCallee assumes that addresses are 64-bytes long, and will corrupt memory otherwise. This can be fixed by writing a getter/setter instead of using the macroed ones.
- CCalls are created by creating the IRCallee and manually building the args list, instead of by calling the helper functions. Not sure if this is good or bad. On the other hand, Dirty statements are created through helper functions.
- deepCopying a binder IRExpr seems to crash VEX
- deepCopying a V256 const is not implemented by VEX's deepCopy stuff
- IRDirty's fxState array access is untested
- equality (for those things that easily have it) should be implemented as a rich comparator
- the hwcaps for the various guest architectures are currently hardcoded. It should be possible to set them from Python.
- You may come acorss a "a.out.h not found" error while compiling the Valgrind. Please turn to http://git.buildroot.net/buildroot/plain/package/valgrind/valgrind-dont-include-a-out-header.patch for a workaround.
