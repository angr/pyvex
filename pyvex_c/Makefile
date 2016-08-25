VEX_PATH?=../vex/

UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LIBRARY_FILE=libpyvex.dylib
	LINKER_NAME_SWITCH=install_name
endif
ifeq ($(UNAME), Linux)
	LIBRARY_FILE=libpyvex.so
	LINKER_NAME_SWITCH=soname
endif

${LIBRARY_FILE}: pyvex.c logging.c ${VEX_PATH}/libvex.a
	gcc -O2 -shared -fPIC -I${VEX_PATH}/pub --std=c99 -o ${LIBRARY_FILE} pyvex.c logging.c ${VEX_PATH}/libvex.a -Wl,-${LINKER_NAME_SWITCH},${LIBRARY_FILE}

clean:
	rm -f ${LIBRARY_FILE}
