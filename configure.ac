#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT(libwebsockets, 1.2, andy@warmcat.com, libwebsockets, http://libwebsockets.org)
AC_CONFIG_SRCDIR([test-server/test-server.c])
AC_CONFIG_HEADERS([config.h])

: ${CFLAGS=""}
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_PROG_AR
LT_INIT(shared)

#AX_PTHREAD

# Checks for programs.
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_CONFIG_MACRO_DIR([m4])

applyhash='CFLAGS+= -DLWS_LIBRARY_VERSION=\"$(PACKAGE_VERSION)\" -DLWS_BUILD_HASH=\"${shell git log -n 1 --pretty=%h}\"'
AC_SUBST([applyhash])
AM_SUBST_NOTMAKE([applyhash])

# Check for existance of the inline keyword.
AC_C_INLINE

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
AC_ARG_WITH(testapps,
 [  --without-testapps  dont build the libwebsocket-test- apps],
 [ no_testapps=yes
 ])

AM_CONDITIONAL(NO_TESTAPPS, test x$no_testapps = xyes)

# 
#
#
AC_ARG_WITH(client,
 [  --without-client  dont build the client part of the library ],
 [ no_client=yes
 ])

if test "x$no_client" = "xyes" ; then                                             
CFLAGS="$CFLAGS -DLWS_NO_CLIENT"                                          
fi
AM_CONDITIONAL(NO_CLIENT, test x$no_client = xyes)

# 
#
#
AC_ARG_WITH(server,
 [  --without-server  dont build the client part of the library ],
 [ no_server=yes
 ])

if test "x$no_server" = "xyes" ; then                                             
CFLAGS="$CFLAGS -DLWS_NO_SERVER"                                          
fi
AM_CONDITIONAL(NO_SERVER, test x$no_server = xyes)

# 
#
#
AC_ARG_WITH(extensions,
 [  --without-extensions  dont build any stuff related to extensions ],
 [ no_extensions=yes
 ])

if test "x$no_extensions" = "xyes" ; then                                             
CFLAGS="$CFLAGS -DLWS_NO_EXTENSIONS"                                          
fi
AM_CONDITIONAL(NO_EXTENSIONS, test x$no_extensions = xyes)

# 
#
#
AC_ARG_WITH(latency,
 [  --with-latency  Build latency measuring code into the library ],
 [ latency=yes
 ])

if test "x$latency" = "xyes" ; then                                             
CFLAGS="$CFLAGS -DLWS_LATENCY"                                          
fi
AM_CONDITIONAL(LATENCY, test x$latency = xyes)

# 
#
#
AC_ARG_WITH(daemonize,
 [  --without-daemonize  dont build the daemonization api ],
 [ no_daemonize=yes
 ])

if test "x$no_daemonize" = "xyes" ; then                                             
CFLAGS="$CFLAGS -DLWS_NO_DAEMONIZE"                                          
fi
AM_CONDITIONAL(NO_DAEMONIZE, test x$no_daemonize = xyes)

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

#
#
#
AC_ARG_ENABLE(debug,
 [  --disable-debug  Stops debug-related code from even being compiled in, useful for best speed],
 [ disable_debug=yes
 ])

if test "x$disable_debug" != "xyes" ; then
CFLAGS="$CFLAGS -D_DEBUG"
fi
AM_CONDITIONAL(DISABLE_DEBUG, test x$disable_debug = xyes)


#
#
#
AC_ARG_ENABLE(builtin-getifaddrs,
 [  --enable-builtin-getifaddrs  Use BSD getifaddrs implementation from libwebsockets... default is your libc provides it],
 [ builtin_getifaddrs=yes
 ])
if test "x$builtin-getifaddrs" = "xyes" ; then
CFLAGS="$CFLAGS -DLWS_BUILTIN_GETIFADDRS"
fi
AM_CONDITIONAL(USE_BUILTIN_GETIFADDRS, test x$builtin_getifaddrs = xyes)

# 
#
#
AC_ARG_WITH(cyassl,
 [  --with-cyassl  Use CyaSSL instead of OpenSSL ],
 [ use_cyassl=yes
 ])

if test "x$use_cyassl" = "xyes" ; then                                     
CFLAGS="$CFLAGS -DUSE_CYASSL -DLWS_OPENSSL_SUPPORT"
fi
AM_CONDITIONAL(USE_CYASSL, test x$use_cyassl = xyes)


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
