# Building for Linux

Usually this just works out of the box without any special considerations from the user.

# Building for Windows

PyVEX requires compiling. On Windows, this gets non-trivial since Windows doesn't come with the same compilation support by default that Linux does. For that reason, extra packages such as CygWin64 are required.

While it might be possible to utilize MinGW-64 to compile PyVex, the solution that seems to work the best is to use CygWin64 (https://cygwin.com/install.html). Use the 64-bit version and be sure to include the basic make file/gcc support.

From there, so long as your path includes the bin directory and it is in the defualt install location (%root%:\Cygwin64\bin), PyVEX should compile.

Note: For the moment, there's a build issue with building archinfo, or more specifically it's dependency capstone. For that reason, you may wish to compile PyVEX without the requirement for archinfo. To do this, simply remove "archinfo" from the setup.py file install dependencies list. While it is still a dependency, you can build them separately.
