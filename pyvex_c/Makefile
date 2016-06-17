VEX_PATH?=../vex/

UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LIBRARY_FILE=pyvex_static.dylib
endif
ifeq ($(UNAME), Linux)
	LIBRARY_FILE=pyvex_static.so
endif

${LIBRARY_FILE}: pyvex_static.c pyvex_logging.c ${VEX_PATH}/libvex.a
	gcc -O2 -shared -fPIC -I${VEX_PATH}/pub --std=c99 -o ${LIBRARY_FILE} pyvex_static.c pyvex_logging.c ${VEX_PATH}/libvex.a

clean:
	rm -f ${LIBRARY_FILE}
