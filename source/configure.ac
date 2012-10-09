#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([ccnx-trace], [1.1.1], [susmit@cs.colostate.edu])
AC_CONFIG_SRCDIR([conf.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

AM_INIT_AUTOMAKE

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lccn':
AC_CHECK_LIB([ccn], [main])
# FIXME: Replace `main' with a function in `-lcrypto':
AC_CHECK_LIB([crypto], [main])
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [main])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strrchr strstr])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
