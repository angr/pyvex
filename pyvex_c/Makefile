UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LIBRARY_FILE=libpyvex.dylib
	LDFLAGS=-Wl,-install_name,$(LIBRARY_FILE)
endif
ifeq ($(UNAME), Linux)
	LIBRARY_FILE=libpyvex.so
	LDFLAGS=-Wl,-soname,$(LIBRARY_FILE)
endif
ifeq ($(findstring MINGW,$(UNAME)), MINGW)
	LIBRARY_FILE=pyvex.dll
	LDFLAGS=
endif

CC=gcc
INCFLAGS=-I $(VEX_INCLUDE_PATH)
CFLAGS=-O2 -shared -fPIC --std=c99 $(INCFLAGS)

$(LIBRARY_FILE): pyvex.c logging.c
	$(CC) $(CFLAGS) -o $(LIBRARY_FILE) pyvex.c logging.c $(VEX_LIB_PATH)/libvex.a $(LDFLAGS)

clean:
	rm -f $(LIBRARY_FILE)
