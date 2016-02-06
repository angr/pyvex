VEX_PATH?=../vex/

UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LIBRARY_FILE=pyvex_static.dylib
endif
ifeq ($(UNAME), Linux)
	LIBRARY_FILE=pyvex_static.so
endif
ifeq (CYGWIN_NT,$(findstring CYGWIN_NT,$(UNAME)))
	LIBRARY_FILE=pyvex_static.dll
endif

${LIBRARY_FILE}: pyvex_static.c pyvex_logging.c ${VEX_PATH}/libvex.a
	gcc -shared -fPIC -I${VEX_PATH}/pub --std=c99 -o ${LIBRARY_FILE} pyvex_static.c pyvex_logging.c ${VEX_PATH}/libvex.a

clean:
	rm -f ${LIBRARY_FILE}
