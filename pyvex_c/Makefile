VEX_PATH?=../../vex/

UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LIBRARY_FILE=libpyvex.dylib
	SONAME_CMD=-Wl,-install_name,${LIBRARY_FILE}
endif
ifeq ($(UNAME), Linux)
	LIBRARY_FILE=libpyvex.so
	SONAME_CMD=-Wl,-soname,${LIBRARY_FILE}
endif
ifeq ($(findstring MINGW,$(UNAME)), MINGW)
	LIBRARY_FILE=pyvex.dll
	SONAME_CMD=
endif


${LIBRARY_FILE}: pyvex.c logging.c ${VEX_PATH}/libvex.a
	gcc -O2 -shared -fPIC -I${VEX_PATH}/pub --std=c99 -o ${LIBRARY_FILE} pyvex.c logging.c ${VEX_PATH}/libvex.a ${SONAME_CMD}

clean:
	rm -f ${LIBRARY_FILE}
