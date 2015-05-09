pyvex_static.so: pyvex_static.c pyvex_logging.c
	gcc -shared -fPIC -I../vex/pub --std=c99 -o pyvex_static.so pyvex_static.c pyvex_logging.c ../vex/libvex.a

clean:
	rm -f pyvex_static.so
