#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.66])
AC_INIT(libwebsockets, 0.1, andy@warmcat.com)
AC_CONFIG_SRCDIR([test-server/test-server.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
LT_INIT(shared)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_CONFIG_MACRO_DIR([m4])


AC_ARG_ENABLE(openssl,
 [  --enable-openssl  Enables https support and needs openssl libs],
 [ openssl=yes
 ])

if test "x$openssl" = "xyes" ; then
AC_CHECK_LIB([ssl], [SSL_library_init])
CFLAGS="$CFLAGS -DLWS_OPENSSL_SUPPORT"
fi



# Checks for header files.
AC_CHECK_HEADERS([fcntl.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([bzero memset socket strerror])

AC_CONFIG_FILES([Makefile
                 lib/Makefile
                 test-server/Makefile])

AC_OUTPUT
