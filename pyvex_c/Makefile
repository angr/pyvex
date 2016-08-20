VEX_PATH?=../vex/

UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LIBRARY_FILE=libpyvex.dylib
endif
ifeq ($(UNAME), Linux)
	LIBRARY_FILE=libpyvex.so
endif

${LIBRARY_FILE}: pyvex.c logging.c ${VEX_PATH}/libvex.a
	gcc -O2 -shared -fPIC -I${VEX_PATH}/pub --std=c99 -o ${LIBRARY_FILE} pyvex.c logging.c ${VEX_PATH}/libvex.a -Wl,-soname,libpyvex.so

clean:
	rm -f ${LIBRARY_FILE}
