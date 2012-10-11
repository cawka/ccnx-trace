## Process this file with automake to produce Makefile.in

CC=cc
AM_CFLAGS=-g -Wall -Wpointer-arith -Wreturn-type -Wstrict-prototypes -I$(includedir) -L$(libdir)

bin_PROGRAMS = ccn_traced ccntrace

ccn_traced_SOURCES = trace_server.c
ccn_traced_LDADD = -lccn -lcrypto -lpthread

trace_SOURCES = trace_client.c
trace_LDADD = -lccn -lcrypto -lpthread

bin_PROGRAMS: ccn_traced ccntrace

ccn_traced:
	${CC} ${AM_CFLAGS} -o $@ ${ccn_traced_SOURCES} ${ccn_traced_LDADD}

ccntrace:
	${CC} ${AM_CFLAGS} -o $@ ${trace_SOURCES} ${trace_LDADD}
