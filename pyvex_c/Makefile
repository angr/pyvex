VEX_PATH?=../vex/

pyvex_static.so: pyvex_static.c pyvex_logging.c ${VEX_PATH}/libvex.a
	gcc -shared -fPIC -I${VEX_PATH}/pub --std=c99 -o pyvex_static.so pyvex_static.c pyvex_logging.c ${VEX_PATH}/libvex.a

clean:
	rm -f pyvex_static.so
