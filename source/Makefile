CC = gcc
CFLAGS = -g -Wall -Wpointer-arith -Wreturn-type -Wstrict-prototypes
LIBS = -lccn -lcrypto

PROGRAM_CL = trace_client
PROGRAM_SR = trace_server

INSTALL_DIR=/usr/local/bin
	


all: $(PROGRAM_CL) $(PROGRAM_SR)


trace_client: trace_client.o
	$(CC) $(CFLAGS) -o trace_client trace_client.o $(LIBS)

trace_client.o:
	$(CC) $(CFLAGS) -c trace_client.c

trace_server: trace_server.o
	$(CC) $(CFLAGS) -o trace_server trace_server.o $(LIBS)

trace_server.o:
	$(CC) $(CFLAGS) -c trace_server.c

install: 
	install -m 0755 $(PROGRAM_CL) $(PROGRAM_SR) $(INSTALL_DIR)

uninstall: 
	rm -f $(INSTALL_DIR)/$(PROGRAM_CL) $(INSTALL_DIR)/$(PROGRAM_SR)

clean:
	rm -f *.o
	rm -f $(PROGRAM_CL) $(PROGRAM_SR)
