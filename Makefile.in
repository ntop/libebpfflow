#
# (C) 2018-19 - ntop.org
#

###############################################################

HAS_JSON=$(shell pkg-config --exists json-c; echo $$?)
ifeq ($(HAS_JSON), 0)
	JSON_INC = "$(shell pkg-config --cflags json-c) -DHAVE_JSONC"
	JSON_LIB = $(shell pkg-config --libs json-c)
endif

###############################################################

HAS_LIBCURL=$(shell pkg-config --exists libcurl; echo $$?)
ifeq ($(HAS_LIBCURL), 0)
	LIBCURL_INC = "$(shell pkg-config --cflags libcurl) -DHAVE_LIBCURL"
	LIBCURL_LIB = $(shell pkg-config --libs libcurl)
endif

###############################################################

#
# Important
# Remove the comment below to use the development version of bcc
#
CFLAGS=-g $(JSON_INC) $(LIBCURL_INC)
LIBS=-lbcc $(JSON_LIB) $(LIBCURL_LIB)


all: ebpftest

libebpfflow.a: ebpf_flow.cpp ebpf_flow.h docker_api.hpp ebpflow.ebpf.enc
	g++ -c $(CFLAGS) ebpf_flow.cpp -o ebpf_flow.o
	ar rvs $@ ebpf_flow.o

ebpftest: ebpftest.cpp libebpfflow.a Makefile
	g++ $(CFLAGS) ebpftest.cpp -o $@ libebpfflow.a $(LIBS)

toolebpflow: toolebpflow.cpp libebpfflow.a Makefile
	g++ $(CFLAGS) toolebpflow.cpp -o $@ libebpfflow.a $(LIBS)

ebpflow.ebpf.enc: ebpflow.ebpf Makefile
	echo -n "const char * ebpf_code = R\"(" > ebpflow.ebpf.enc
	base64 -w 0 ebpflow.ebpf >> ebpflow.ebpf.enc
	echo ")\";" >> ebpflow.ebpf.enc

clean:
	/bin/rm -f *~ ebpftest libebpfflow.a *.o ebpflow.ebpf.enc #*
