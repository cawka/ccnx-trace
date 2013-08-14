#####################################################################
# NDNx libraries
#####################################################################
#   AX_NDNX([MINIMUM-API-VERSION], [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
#
# DESCRIPTION
#
#	If no path to the installed NDNx library is given the macro searches
#	under /usr, /usr/local, /opt and /opt/local
#
#   This macro calls:
#
#     AC_SUBST(NDNX_CFLAGS) / AC_SUBST(NDNX_LDFLAGS) / AC_SUBST(NDNX_LIBS)
#
#   And calls ACTION-IF-FOUND or ACTION-IF-NOT-FOUND appropriately
#
# LICENSE
#	Copyright (c) 2011 Alexander Afanasyev <alexander.afanasyev@ucla.edu>
#
#	Copying and distribution of this file, with or without modification, are
#	permitted in any medium without royalty provided the copyright notice
#	and this notice are preserved. This file is offered as-is, without any
#	warranty.

AC_DEFUN([AX_NDNX],
[
  AC_ARG_WITH([ndnx],
    [AS_HELP_STRING([--with-ndnx=DIR],
      [root directory for NDNx library])],
    [
      case "$withval" in
      "" | y | ye | yes | n | no)
        AC_MSG_ERROR([Invalid --with-ndnx value])
        ;;
      *)
        basedirs="$withval"
        indir="in $withval"
        ;;
      esac
    ],
    [
      basedirs="/usr /usr/local /opt /opt/local"
      indir=""
    ]
  )
 
  ndnx_lib_version_req=ifelse([$1], ,0.4.0,$1)
  ndnx_lib_version_req_major=`expr $ndnx_lib_version_req : '\([[0-9]]*\)'`
  ndnx_lib_version_req_minor=`expr $ndnx_lib_version_req : '[[0-9]]*\.\([[0-9]]*\)'`
  ndnx_lib_version_req_sub_minor=`expr $ndnx_lib_version_req : '[[0-9]]*\.[[0-9]]*\.\([[0-9]]*\)'`
  if test "x$ndnx_lib_version_req_sub_minor" = "x" ; then
    ndnx_lib_version_req_sub_minor="0"
  fi
  WANT_NDNX_VERSION=`expr $ndnx_lib_version_req_major \* 100000 \+  $ndnx_lib_version_req_minor \* 1000 \+ $ndnx_lib_version_req_sub_minor`

  AC_MSG_CHECKING(for NDNx library with API version >= $ndnx_lib_version_req $indir)
  succeeded=no
  found=false

  libsubdirs="lib64 lib"
  
  for ndnx_base_tmp in $basedirs ; do
    if test -d "$ndnx_base_tmp/include/ndn" && test -r "$ndnx_base_tmp/include/ndn"; then
      for libsubdir in $libsubdirs ; do
        if ls "$ndnx_base_tmp/$libsubdir/libndn"* >/dev/null 2>&1 ; then break; fi
      done
      NDNX_LDFLAGS="-L$ndnx_base_tmp/$libsubdir"
      NDNX_CFLAGS="-I$ndnx_base_tmp/include"
      NDNX_LIBS="-lndn"
      NDNX_DIR="$ndnx_base_tmp"
      found=true
      break;
    fi
  done

  if ! $found; then
    AC_MSG_RESULT([no])
  else
    save_LIBS="$LIBS"
    save_LDFLAGS="$LDFLAGS"
    save_CFLAGS="$CFLAGS"
    LDFLAGS="$LDFLAGS $NDNX_LDFLAGS"
    LIBS="$NDNX_LIBS $LIBS"
    CFLAGS="$NDNX_CFLAGS $CFLAGS"

    AC_REQUIRE([AC_PROG_CC])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
        @%:@include <ndn/ndn.h>
      ]], [[
        #if NDN_API_VERSION >= $WANT_NDNX_VERSION
        // Everything is okay
        #else
        #  error NDNx API version is too old
        #endif
    ]])],[
      AC_MSG_RESULT([yes])
      succeeded=yes
    ],[
    ])

    CFLAGS="$save_CFLAGS"
    LDFLAGS="$save_LDFLAGS"
    LIBS="$save_LIBS"
  fi

  if test "$succeeded" != "yes" ; then
    # execute ACTION-IF-NOT-FOUND (if present):
    ifelse([$3], , :, [$3])
  else
    AC_SUBST(NDNX_CFLAGS)
    AC_SUBST(NDNX_LDFLAGS)
    AC_SUBST(NDNX_LIBS)
    AC_SUBST(NDNX_DIR)
    AC_DEFINE_UNQUOTED(NDNX_DIR, ["$NDNX_DIR"], [Root path for NDNx installation])
    # execute ACTION-IF-FOUND (if present):
    ifelse([$2], , :, [$2])
  fi

])

