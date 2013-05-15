#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([ccnx-trace], [1.1.1], [susmit@cs.colostate.edu])
AC_CONFIG_SRCDIR([source/conf.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

AM_INIT_AUTOMAKE
AM_PROG_CC_C_O

AX_CCNX([0.6.1],,[AC_MSG_ERROR([Required CCNx library not found])])
AX_CHECK_OPENSSL(,[AC_MSG_ERROR([Required OpenSSL not found])])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strrchr strstr])

AC_CONFIG_FILES([Makefile
				 source/Makefile])
AC_OUTPUT
