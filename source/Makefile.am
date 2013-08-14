bin_PROGRAMS =  ndn_traced ndntrace

ndn_traced_SOURCES = trace_server.c conf.h node_id.h
ndn_traced_LDADD   = $(NDNX_LIBS) $(OPENSSL_LIBS) $(BOOST_LIBS)
ndn_traced_LDFLAGS = $(NDNX_LDFLAGS) $(OPENSSL_LDFLAGS) $(BOOST_LDFLAGS)
ndn_traced_CFLAGS  = $(NDNX_CFLAGS) $(OPENSSL_INCLUDES) $(BOOST_INCLUDES)

ndntrace_SOURCES   = trace_client.c conf.h node_id.h
ndntrace_LDADD     = $(NDNX_LIBS) $(OPENSSL_LIBS) $(BOOST_LIBS)
ndntrace_LDFLAGS   = $(NDNX_LDFLAGS) $(OPENSSL_LDFLAGS) $(BOOST_LDFLAGS)
ndntrace_CFLAGS    = $(NDNX_CFLAGS) $(OPENSSL_INCLUDES)
