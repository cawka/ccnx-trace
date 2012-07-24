CC = gcc
CFLAGS = -g -Wall -Wpointer-arith -Wreturn-type -Wstrict-prototypes
LIBS = -lccn -lcrypto

PROGRAM_CL = trace_client
PROGRAM_SR = trace_server

all: $(PROGRAM_CL) $(PROGRAM_SR)

trace_client: trace_client.o
	$(CC) $(CFLAGS) -o trace_client trace_client.o $(LIBS)

trace_client.o:
	$(CC) $(CFLAGS) -c trace_client.c

trace_server: trace_server.o
	$(CC) $(CFLAGS) -o trace_server trace_server.o $(LIBS)

trace_server.o:
	$(CC) $(CFLAGS) -c trace_server.c
clean:
	rm -f *.o
	rm -f $(PROGRAM_CL) $(PROGRAM_SR)
