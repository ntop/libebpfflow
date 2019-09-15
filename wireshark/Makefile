
###############################################################

HAS_JSON=$(shell pkg-config --exists json-c; echo $$?)
ifeq ($(HAS_JSON), 0)
	JSON_INC = $(shell pkg-config --cflags json-c) -DHAVE_JSONC
	JSON_LIB = $(shell pkg-config --libs json-c)
endif

###############################################################

HAS_LIBCURL=$(shell pkg-config --exists libcurl; echo $$?)
ifeq ($(HAS_LIBCURL), 0)
	LIBCURL_INC = $(shell pkg-config --cflags libcurl) -DHAVE_LIBCURL
	LIBCURL_LIB = $(shell pkg-config --libs libcurl)
endif

###############################################################

CFLAGS=-g -I.. $(JSON_INC) $(LIBCURL_INC)
LIBS=-L .. -lebpfflow -lbcc $(JSON_LIB) $(LIBCURL_LIB)

ebpfdump: ebpfdump.c Makefile
	g++ $(CFLAGS) -g ebpfdump.c -o ebpfdump $(LIBS)

clean:
	/bin/rm -f ebpfdump

