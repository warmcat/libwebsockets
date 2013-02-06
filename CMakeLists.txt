cmake_minimum_required(VERSION 2.6)

project(libwebsockets)

set(PACKAGE "libwebsockets")
set(PACKAGE_VERSION "1.1")
set(PACKAGE_BUGREPORT "andy@warmcat.com")
set(PACKAGE_NAME "${PACKAGE}")
set(PACKAGE_STRING "${PACKAGE} ${PACKAGE_VERSION}")
set(PACKAGE_TARNAME "${PACKAGE}")
set(PACKAGE_URL "http://libwebsockets.org")
set(VERSION "{PACKAGE_VERSION}")

option(WITH_SSL "Include SSL support (default OpenSSL, CyaSSL if USE_CYASSL is set)" ON)
option(USE_INCLUDED_WIN32_ZLIB "Use the internal version of ZLib instead of searching the system" ON)
option(USE_CYASSL "Use CyaSSL replacement for OpenSSL" OFF)
option(WITH_BUILTIN_GETIFADDRS "Use BSD getifaddrs implementation from libwebsockets... default is your libc provides it" OFF)
option(WITHOUT_TESTAPPS "Don't build the libwebsocket-test-apps" OFF)
option(WITHOUT_CLIENT "Don't build the client part of the library" OFF)
option(WITHOUT_SERVER "Don't build the server part of the library" OFF)
option(WITH_LIBCRYPTO "Use libcrypto MD5 and SHA1 implementations" ON)
option(WITHOUT_PING "Don't build the ping test application" OFF)
option(WITHOUT_DEBUG "Don't compile debug related code" OFF)

set(CYASSL_LIB ON CACHE STRING "")
set(CYASSL_INCLUDE_DIRS ON CACHE STRING "")

if (USE_CYASSL)
	if (NOT CYASSL_LIB OR NOT CYASSL_INCLUDE_DIRS)
		error("You must set CYASSL_LIB and CYASSL_INCLUDE_DIRS when USE_CYASSL is turned on")
	endif()
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/")
include_directories(${PROJECT_BINARY_DIR})

include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckLibraryExists)

CHECK_FUNCTION_EXISTS(bzero HAVE_BZERO)
CHECK_FUNCTION_EXISTS(fork HAVE_FORK)
CHECK_FUNCTION_EXISTS(malloc HAVE_MALLOC)
CHECK_FUNCTION_EXISTS(memset HAVE_MEMSET)
CHECK_FUNCTION_EXISTS(realloc HAVE_REALLOC)
CHECK_FUNCTION_EXISTS(socket HAVE_SOCKET)
CHECK_FUNCTION_EXISTS(strerror HAVE_STRERROR)
CHECK_FUNCTION_EXISTS(vfork HAVE_VFORK)
CHECK_FUNCTION_EXISTS(getifaddrs HAVE_GETIFADDRS)

CHECK_INCLUDE_FILE(dlfcn.h HAVE_DLFCN_H)
CHECK_INCLUDE_FILE(fcntl.h HAVE_FCNTL_H)
CHECK_INCLUDE_FILE(inttypes.h HAVE_INTTYPES_H)
CHECK_INCLUDE_FILE(memory.h HAVE_MEMORY_H)
CHECK_INCLUDE_FILE(netinet/in.h HAVE_NETINET_IN_H)
CHECK_INCLUDE_FILE(stdint.h HAVE_STDINT_H)
CHECK_INCLUDE_FILE(stdlib.h HAVE_STDLIB_H)
CHECK_INCLUDE_FILE(strings.h HAVE_STRINGS_H)
CHECK_INCLUDE_FILE(string.h HAVE_STRING_H)
CHECK_INCLUDE_FILE(sys/prctl.h HAVE_SYS_PRCTL_H)
CHECK_INCLUDE_FILE(sys/socket.h HAVE_SYS_SOCKET_H)
CHECK_INCLUDE_FILE(sys/stat.h HAVE_SYS_STAT_H)
CHECK_INCLUDE_FILE(sys/types.h HAVE_SYS_TYPES_H)
CHECK_INCLUDE_FILE(unistd.h HAVE_UNISTD_H)
CHECK_INCLUDE_FILE(vfork.h HAVE_VFORK_H)
CHECK_INCLUDE_FILE(zlib.h HAVE_ZLIB_H)

# TODO: These can be tested if they actually work also...
set(HAVE_WORKING_FORK HAVE_FORK)
set(HAVE_WORKING_VFORK HAVE_VFORK)

CHECK_INCLUDE_FILES("stdlib.h;stdarg.h;string.h;float.h" STDC_HEADERS)

if (NOT HAVE_SYS_TYPES_H)
	set(pid_t int)
	set(size_t "unsigned int")
endif()

if (NOT HAVE_MALLOC)
	set(malloc rpl_malloc)
endif()

if (NOT HAVE_REALLOC)
	set(realloc rpl_realloc)
endif()

if (WITH_SSL)
	set(LWS_OPENSSL_SUPPORT)
endif()

# Generate the config.h that includes all the compilation settings.
configure_file(
		${PROJECT_SOURCE_DIR}/config.h.cmake 
		${PROJECT_BINARY_DIR}/config.h)

set(LIB_LIST)

if (MSVC)
	# Turn off stupid microsoft security warnings.
	add_definitions(-D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE)
endif()

if (WIN32)
	# For windows, do not allow the compiler to use default target (Vista).
	add_definitions(-D_WIN32_WINNT=0x0501)
endif(WIN32)

# Group headers and sources.
# Some IDEs use this for nicer file structure.
set(HDR_PRIVATE
	lib/private-libwebsockets.h
	lib/extension-deflate-frame.h
	lib/lib/extension-deflate-stream.h)

set(HDR_PUBLIC	
	lib/libwebsockets.h
	)

set(SOURCES
	lib/base64-decode.c
	lib/client.c
	lib/client-handshake.c
	lib/client-parser.c
	lib/daemonize.c
	lib/extension.c
	lib/extension-deflate-frame.c
	lib/extension-deflate-stream.c
	lib/handshake.c
	lib/libwebsockets.c
	lib/minilex.c
	lib/output.c
	lib/parsers.c
	lib/server.c
	lib/server-handshake.c
	lib/sha-1.c
	)

# Add helper files for Windows.
if (WIN32)
	set(WIN32_HELPERS_PATH ${PROJECT_SOURCE_DIR}/win32port/win32helpers)

	list(APPEND HDR_PRIVATE
		${WIN32_HELPERS_PATH}/websock-w32.h
		${WIN32_HELPERS_PATH}/gettimeofday.h
		)

	list(APPEND SOURCES 
		${WIN32_HELPERS_PATH}/websock-w32.c
		${WIN32_HELPERS_PATH}/gettimeofday.c
		)
endif()

if (UNIX)
	if (!WITH_BUILTIN_GETIFADDRS)
		list(APPEND HDR_PRIVATE lib/getifaddrs.h)
		list(APPEND SOURCES lib/getifaddrs.c)
	endif()
endif()

source_group("Headers Private"  FILES ${HDR_PRIVATE})
source_group("Headers Public"   FILES ${HDR_PUBLIC})
source_group("Sources"          FILES ${SOURCES})

#
# Create the lib.
#
add_library(websocket STATIC
			${HDR_PRIVATE}
			${HDR_PUBLIC}
			${SOURCES})

#
# Find libraries.
#

#
# ZLIB.
#
if (WIN32 AND USE_INCLUDED_WIN32_ZLIB)
	# Compile ZLib if needed.
	if (USE_INCLUDED_WIN32_ZLIB)
		set(WIN32_ZLIB_PATH "${PROJECT_SOURCE_DIR}/win32port/zlib")
		set(ZLIB_SRCS
			${WIN32_ZLIB_PATH}/adler32.c
			${WIN32_ZLIB_PATH}/compress.c
			${WIN32_ZLIB_PATH}/crc32.c
			${WIN32_ZLIB_PATH}/deflate.c
			${WIN32_ZLIB_PATH}/gzclose.c
			${WIN32_ZLIB_PATH}/gzio.c
			${WIN32_ZLIB_PATH}/gzlib.c
			${WIN32_ZLIB_PATH}/gzread.c
			${WIN32_ZLIB_PATH}/gzwrite.c
			${WIN32_ZLIB_PATH}/infback.c
			${WIN32_ZLIB_PATH}/inffast.c
			${WIN32_ZLIB_PATH}/inflate.c
			${WIN32_ZLIB_PATH}/inftrees.c
			${WIN32_ZLIB_PATH}/trees.c
			${WIN32_ZLIB_PATH}/uncompr.c
			${WIN32_ZLIB_PATH}/zutil.c
		)

		# Create the library.
		add_library(zlib STATIC ${ZLIB_SRCS})

		# Set the same variables as find_package would.
		set(${ZLIB_INCLUDE_DIRS} ${WIN32_ZLIB_PATH})
		get_property(ZLIB_LIBRARIES TARGET zlib PROPERTY LOCATION)
		set(ZLIB_FOUND 1)
	endif()
else()
	find_package(zlib REQUIRED)
endif()

include_directories(${ZLIB_INCLUDE_DIRS})
target_link_libraries(websocket ${ZLIB_LIBRARIES})

#
# OpenSSL
#
if (WITH_SSL)
	if (USE_CYASSL)
		# Use CyaSSL as OpenSSL replacement.
		set(OPENSSL_LIBRARIES ${CYASSL_LIB})
		set(OPENSSL_INCLUDE_DIRS ${CYASSL_INCLUDE_DIRS})
		set(OPENSSL_FOUND 1)
	else()
		# TODO: Add support for STATIC also.
		find_package(OpenSSL REQUIRED)
	endif()

	include_directories(${OPENSSL_INCLUDE_DIR})
	target_link_libraries(websocket ${OPENSSL_LIBRARIES})
endif()


