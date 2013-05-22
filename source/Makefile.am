bin_PROGRAMS =  ccn_traced ccntrace

ccn_traced_SOURCES = trace_server.c conf.h node_id.h
ccn_traced_LDADD   = $(CCNX_LIBS) $(OPENSSL_LIBS) $(BOOST_LIBS)
ccn_traced_LDFLAGS = $(CCNX_LDFLAGS) $(OPENSSL_LDFLAGS) $(BOOST_LDFLAGS)
ccn_traced_CFLAGS  = $(CCNX_CFLAGS) $(OPENSSL_INCLUDES) $(BOOST_INCLUDES)

ccntrace_SOURCES   = trace_client.c conf.h node_id.h
ccntrace_LDADD     = $(CCNX_LIBS) $(OPENSSL_LIBS) $(BOOST_LIBS)
ccntrace_LDFLAGS   = $(CCNX_LDFLAGS) $(OPENSSL_LDFLAGS) $(BOOST_LDFLAGS)
ccntrace_CFLAGS    = $(CCNX_CFLAGS) $(OPENSSL_INCLUDES)
