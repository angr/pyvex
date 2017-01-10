UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LIBRARY_FILE=libpyvex.dylib
	STATIC_LIBRARY_FILE=libpyvex.a
	LDFLAGS=-Wl,-install_name,$(LIBRARY_FILE)
endif
ifeq ($(UNAME), Linux)
	LIBRARY_FILE=libpyvex.so
	STATIC_LIBRARY_FILE=libpyvex.a
	LDFLAGS=-Wl,-soname,$(LIBRARY_FILE)
endif
ifeq ($(findstring MINGW,$(UNAME)), MINGW)
	LIBRARY_FILE=pyvex.dll
	STATIC_LIBRARY_FILE=libpyvex.a
	LDFLAGS=
endif

CC=gcc
AR=ar
INCFLAGS=-I $(VEX_INCLUDE_PATH)
CFLAGS=-O2 -shared -fPIC --std=c99 $(INCFLAGS)

OBJECTS=pyvex.o logging.o

all: $(LIBRARY_FILE) $(STATIC_LIBRARY_FILE)

%.o: %.c
	$(CC) -c $(CFLAGS) $<

$(LIBRARY_FILE): pyvex.o logging.o $(VEX_LIB_PATH)/libvex.a
	$(CC) $(CFLAGS) -o $(LIBRARY_FILE) pyvex.o logging.o $(VEX_LIB_PATH)/libvex.a $(LDFLAGS)

$(STATIC_LIBRARY_FILE): pyvex.o logging.o $(VEX_LIB_PATH)/libvex.a
	$(AR) rcs $(STATIC_LIBRARY_FILE) pyvex.o logging.o

clean:
	rm -f $(LIBRARY_FILE)
