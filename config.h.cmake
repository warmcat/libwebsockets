/* config.h.in.  Generated from configure.ac by autoheader.  */

#ifndef WIN32
#cmakedefine _DEBUG
#endif

/* Define to 1 to use CyaSSL as a replacement for OpenSSL. 
 * LWS_OPENSSL_SUPPORT needs to be set also for this to work. */
#cmakedefine USE_CYASSL

/* The Libwebsocket version */
#cmakedefine LWS_LIBRARY_VERSION "${LWS_LIBRARY_VERSION}"

/* The current git commit hash that we're building from */
#cmakedefine LWS_BUILD_HASH "${LWS_BUILD_HASH}"

/* Build with OpenSSL support */
#cmakedefine LWS_OPENSSL_SUPPORT

/* Sets the path where the client certs should be installed. */
#cmakedefine LWS_OPENSSL_CLIENT_CERTS "${LWS_OPENSSL_CLIENT_CERTS}"

/* Turn off websocket extensions */
#cmakedefine LWS_NO_EXTENSIONS

/* Turn on latency measuring code */
#cmakedefine LWS_LATENCY

/* Don't build the daemonizeation api */
#cmakedefine LWS_NO_DAEMONIZE

/* Build without server support */
#cmakedefine LWS_NO_SERVER

/* Build without client support */
#cmakedefine LWS_NO_CLIENT

/* If we should compile with MinGW support */
#cmakedefine LWS_MINGW_SUPPORT

/* Use the BSD getifaddrs that comes with libwebsocket, for uclibc support */
#cmakedefine LWS_BUILTIN_GETIFADDRS

/* Define to 1 if you have the `bzero' function. */
#cmakedefine HAVE_BZERO

/* Define to 1 if you have the <dlfcn.h> header file. */
#cmakedefine HAVE_DLFCN_H

/* Define to 1 if you have the <fcntl.h> header file. */
#cmakedefine HAVE_FCNTL_H

/* Define to 1 if you have the `fork' function. */
#cmakedefine HAVE_FORK

/* Define to 1 if you have the <inttypes.h> header file. */
#cmakedefine HAVE_INTTYPES_H

/* Define to 1 if you have the `ssl' library (-lssl). */
//#cmakedefine HAVE_LIBSSL

/* Define to 1 if your system has a GNU libc compatible `malloc' function, and
   to 0 otherwise. */
#cmakedefine HAVE_MALLOC

/* Define to 1 if you have the <memory.h> header file. */
#cmakedefine HAVE_MEMORY_H

/* Define to 1 if you have the `memset' function. */
#cmakedefine HAVE_MEMSET

/* Define to 1 if you have the <netinet/in.h> header file. */
#cmakedefine HAVE_NETINET_IN_H

/* Define to 1 if your system has a GNU libc compatible `realloc' function,
   and to 0 otherwise. */
#cmakedefine HAVE_REALLOC

/* Define to 1 if you have the `socket' function. */
#cmakedefine HAVE_SOCKET

/* Define to 1 if you have the <stdint.h> header file. */
#cmakedefine HAVE_STDINT_H

/* Define to 1 if you have the <stdlib.h> header file. */
#cmakedefine HAVE_STDLIB_H

/* Define to 1 if you have the `strerror' function. */
#cmakedefine HAVE_STRERROR

/* Define to 1 if you have the <strings.h> header file. */
#cmakedefine HAVE_STRINGS_H

/* Define to 1 if you have the <string.h> header file. */
#cmakedefine HAVE_STRING_H

/* Define to 1 if you have the <sys/prctl.h> header file. */
#cmakedefine HAVE_SYS_PRCTL_H

/* Define to 1 if you have the <sys/socket.h> header file. */
#cmakedefine HAVE_SYS_SOCKET_H

/* Define to 1 if you have the <sys/stat.h> header file. */
#cmakedefine HAVE_SYS_STAT_H

/* Define to 1 if you have the <sys/types.h> header file. */
#cmakedefine HAVE_SYS_TYPES_H

/* Define to 1 if you have the <unistd.h> header file. */
#cmakedefine HAVE_UNISTD_H

/* Define to 1 if you have the `vfork' function. */
#cmakedefine HAVE_VFORK

/* Define to 1 if you have the <vfork.h> header file. */
#cmakedefine HAVE_VFORK_H

/* Define to 1 if `fork' works. */
#cmakedefine HAVE_WORKING_FORK

/* Define to 1 if `vfork' works. */
#cmakedefine HAVE_WORKING_VFORK

/* Define to 1 if you have the <zlib.h> header file. */
#cmakedefine HAVE_ZLIB_H

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#undef LT_OBJDIR // We're not using libtool

/* Define to 1 if you have the ANSI C header files. */
#cmakedefine STDC_HEADERS

/* Version number of package */
#cmakedefine VERSION

/* Define to rpl_malloc if the replacement function should be used. */
#cmakedefine malloc

/* Define to `int' if <sys/types.h> does not define. */
#cmakedefine pid_t

/* Define to rpl_realloc if the replacement function should be used. */
#cmakedefine realloc

/* Define to `unsigned int' if <sys/types.h> does not define. */
#cmakedefine size_t

/* Define to 1 if we have getifaddrs */
#cmakedefine HAVE_GETIFADDRS

/* Define as `fork' if `vfork' does not work. */
//#cmakedefine vfork

/* Define if the inline keyword doesn't exist. */
#cmakedefine inline
