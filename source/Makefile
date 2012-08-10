CC = gcc
CFLAGS = -g -Wall -Wpointer-arith -Wreturn-type -Wstrict-prototypes
LIBS = -lccn -lcrypto

PROGRAM_CL = trace
PROGRAM_SR = ccn_traced

INSTALL_DIR=/usr/local/bin

all: $(PROGRAM_CL) $(PROGRAM_SR)

trace: trace_client.o
	$(CC) $(CFLAGS) -o trace trace_client.o $(LIBS)

trace_client.o:
	$(CC) $(CFLAGS) -c trace_client.c

ccn_traced: trace_server.o
	$(CC) $(CFLAGS) -o ccn_traced trace_server.o $(LIBS)

trace_server.o:
	$(CC) $(CFLAGS) -c trace_server.c

install: 
	install -m 0755 $(PROGRAM_CL) $(PROGRAM_SR) $(INSTALL_DIR)

uninstall: 
	rm -f $(INSTALL_DIR)/$(PROGRAM_CL) $(INSTALL_DIR)/$(PROGRAM_SR)

clean:
	rm -f *.o
	rm -f $(PROGRAM_CL) $(PROGRAM_SR)
