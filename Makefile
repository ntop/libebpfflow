#
# (C) 2018-19 - ntop.org
#

#
# Important
# Remove the comment below to use the development version of bcc
#
EBPF=#-DNEW_EBF=1
CFLAGS=-g $(EBPF)
LIBS=-lbcc


all: ebpftest

libebpfflow.a: ebpf_flow.cpp ebpf_flow.h ebpflow.ebpf.enc
	g++ -c $(CFLAGS) ebpf_flow.cpp -o ebpf_flow.o
	ar rvs $@ ebpf_flow.o

ebpftest: ebpftest.cpp libebpfflow.a Makefile
	g++ $(CFLAGS) ebpftest.cpp -o $@ libebpfflow.a $(LIBS)

ebpflow.ebpf.enc: ebpflow.ebpf Makefile
	echo -n "const char * ebpf_code = R\"(" > ebpflow.ebpf.enc
	base64 -w 0 ebpflow.ebpf >> ebpflow.ebpf.enc
	echo ")\";" >> ebpflow.ebpf.enc

clean:
	/bin/rm -f *~ ebpftest libebpfflow.a *.o ebpflow.ebpf.enc #*
