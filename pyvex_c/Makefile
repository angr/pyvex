UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LIBRARY_FILE=libpyvex.dylib
	STATIC_LIBRARY_FILE=libpyvex.a
	LDFLAGS=-Wl,-install_name,@rpath/$(LIBRARY_FILE)
endif
ifeq ($(UNAME), Linux)
	LIBRARY_FILE=libpyvex.so
	STATIC_LIBRARY_FILE=libpyvex.a
	LDFLAGS=-Wl,-soname,$(LIBRARY_FILE)
endif
ifeq ($(UNAME), FreeBSD)
	LIBRARY_FILE=libpyvex.so
	STATIC_LIBRARY_FILE=libpyvex.a
	LDFLAGS=-Wl,-soname,$(LIBRARY_FILE)
endif
ifeq ($(UNAME), NetBSD)
	LIBRARY_FILE=libpyvex.so
	STATIC_LIBRARY_FILE=libpyvex.a
	LDFLAGS=-Wl,-soname,$(LIBRARY_FILE)
endif
ifeq ($(UNAME), OpenBSD)
	LIBRARY_FILE=libpyvex.so
	LDFLAGS=-Wl,-soname,$(LIBRARY_FILE) -L/usr/local/lib -lvex
endif
ifeq ($(findstring MINGW,$(UNAME)), MINGW)
	LIBRARY_FILE=pyvex.dll
	STATIC_LIBRARY_FILE=libpyvex.a
	LDFLAGS=
endif

# deeply evil
# https://www.cmcrossroads.com/article/gnu-make-meets-file-names-spaces-them
sp =$(null) $(null)
qs = $(subst ?,$(sp),$1)
sq = $(subst $(sp),?,$1)

CC?=gcc
AR=ar
INCFLAGS=-I "$(VEX_INCLUDE_PATH)"
CFLAGS=-g -O2 -Wall -shared -fPIC -std=c99 $(INCFLAGS)

OBJECTS=pyvex.o logging.o analysis.o postprocess.o
HEADERS=pyvex.h

all: $(LIBRARY_FILE) $(STATIC_LIBRARY_FILE)

%.o: %.c
	$(CC) -c $(CFLAGS) $<

$(LIBRARY_FILE): $(OBJECTS) $(HEADERS) $(call sq,$(VEX_LIB_PATH)/libvex.a)
	$(CC) $(CFLAGS) -o $(LIBRARY_FILE) $(OBJECTS) "$(VEX_LIB_PATH)/libvex.a" $(LDFLAGS)

$(STATIC_LIBRARY_FILE): $(OBJECTS) $(HEADERS) $(call sq,$(VEX_LIB_PATH)/libvex.a)
	$(AR) rcs $(STATIC_LIBRARY_FILE) $(OBJECTS)

clean:
	rm -f $(LIBRARY_FILE) $(STATIC_LIBRARY_FILE) *.o
