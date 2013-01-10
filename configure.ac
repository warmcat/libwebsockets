#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT(libwebsockets, 1.0, andy@warmcat.com)
AC_CONFIG_SRCDIR([test-server/test-server.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_PROG_AR
LT_INIT(shared)

#AX_PTHREAD

# Checks for programs.
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_CONFIG_MACRO_DIR([m4])

#
#
#
AC_ARG_ENABLE(openssl,
 [  --enable-openssl  Enables https support and needs openssl libs],
 [ openssl=yes
 ])

if test "x$openssl" = "xyes" ; then
AC_CHECK_LIB([ssl], [SSL_library_init])
CFLAGS="$CFLAGS -DLWS_OPENSSL_SUPPORT"
fi

#
#
#
AC_ARG_ENABLE(nofork,
 [  --enable-nofork  Disables fork-related options],
 [ nofork=yes
 ])

if test "x$nofork" = "xyes" ; then
CFLAGS="$CFLAGS -DLWS_NO_FORK"
else
AC_FUNC_FORK
fi

#
#
#
AC_ARG_ENABLE(libcrypto,
 [  --enable-libcrypto  Use libcrypto MD5 and SHA1 implementations],
 [ libcrypto=yes
 ])

if test "x$libcrypto" = "xyes" ; then
CFLAGS="$CFLAGS -DLWS_LIBCRYPTO"
LDFLAGS="$LDFLAGS -lcrypto"
fi
AM_CONDITIONAL(LIBCRYPTO, test x$libcrypto = xyes)


#
#
#
AC_ARG_ENABLE(x-google-mux,
 [  --enable-x-google-mux  Build experimental x-google-mux],
 [ x_google_mux=yes
 ])
if test "x$x_google_mux" = "xyes" ; then
CFLAGS="$CFLAGS -DLWS_EXT_GOOGLE_MUX"
fi
AM_CONDITIONAL(EXT_GOOGLE_MUX, test x$x_google_mux = xyes)

#                                                                               
#                                                                               
#                                                                               
AC_ARG_ENABLE(mingw,                                                          
 [  --enable-mingw  Using mingw compilers, disables ping test build],            
 [ mingw=yes
   noping=yes
 ])                                                                             
                                                                                
if test "x$mingw" = "xyes" ; then                                             
CFLAGS="$CFLAGS -DLWS_MINGW_SUPPORT"                                          
fi
AM_CONDITIONAL(MINGW, test x$mingw = xyes)

#
#
#
AC_ARG_WITH([client-cert-dir],
[AS_HELP_STRING([--with-client-cert-dir],[directory containing client certs, defaults to /etc/pki/tls/certs/])],
[clientcertdir=$withval],
[clientcertdir=/etc/pki/tls/certs/]
)
AC_SUBST([clientcertdir])

AC_SUBST([CFLAGS])


#
#
#
AC_ARG_ENABLE(noping,
 [  --enable-noping  Do not build ping test app, which has some unixy stuff in sources],
 [ noping=yes
 ])

AM_CONDITIONAL(NOPING, test x$noping = xyes)



# Checks for header files.
AC_CHECK_HEADERS([zlib.h fcntl.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h sys/prctl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.

AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([bzero memset socket strerror])

AC_CONFIG_FILES([Makefile
                 lib/Makefile
                 test-server/Makefile])

AC_OUTPUT([
libwebsockets.pc
])
