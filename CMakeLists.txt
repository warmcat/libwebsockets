cmake_minimum_required(VERSION 2.6)

project(libwebsockets)

set(PACKAGE "libwebsockets")
set(PACKAGE_VERSION "1.2")
set(PACKAGE_BUGREPORT "andy@warmcat.com")
set(PACKAGE_NAME "${PACKAGE}")
set(PACKAGE_STRING "${PACKAGE} ${PACKAGE_VERSION}")
set(PACKAGE_TARNAME "${PACKAGE}")
set(PACKAGE_URL "http://libwebsockets.org")
set(VERSION "{PACKAGE_VERSION}")
set(SOVERSION "3.0.0")

set(LWS_LIBRARY_VERSION ${PACKAGE_VERSION})

# Try to find the current Git hash.
find_package(Git)
if(GIT_EXECUTABLE)
	execute_process(
    COMMAND "${GIT_EXECUTABLE}" log -n 1 --pretty=%h
    OUTPUT_VARIABLE GIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    set(LWS_BUILD_HASH ${GIT_HASH})
    message("Git commit hash: ${LWS_BUILD_HASH}")
endif()

option(WITH_SSL "Include SSL support (default OpenSSL, CyaSSL if USE_CYASSL is set)" ON)
option(USE_EXTERNAL_ZLIB "Search the system for ZLib instead of using the included one (on Windows)" OFF)
option(USE_CYASSL "Use CyaSSL replacement for OpenSSL. When settings this, you also need to specify CYASSL_LIB and CYASSL_INCLUDE_DIRS" OFF)
option(WITH_BUILTIN_GETIFADDRS "Use BSD getifaddrs implementation from libwebsockets... default is your libc provides it" OFF)
option(WITHOUT_TESTAPPS "Don't build the libwebsocket-test-apps" OFF)
option(WITHOUT_CLIENT "Don't build the client part of the library" OFF)
option(WITHOUT_SERVER "Don't build the server part of the library" OFF)
option(WITHOUT_SERVER_EXTPOLL "Don't build a server version that uses external poll" OFF)
option(WITH_LIBCRYPTO "Use libcrypto MD5 and SHA1 implementations" ON)
option(WITHOUT_PING "Don't build the ping test application" OFF)
option(WITHOUT_DEBUG "Don't compile debug related code" OFF)
option(WITHOUT_EXTENSIONS "Don't compile with extensions" OFF)
option(WITH_LATENCY "Build latency measuring code into the library" OFF)
option(WITHOUT_DAEMONIZE "Don't build the daemonization api" OFF)

# The base dir where the SSL dirs should be looked for.
set(SSL_CERT_DIR CACHE STRING "")
set(SSL_CLIENT_CERT_DIR CACHE STRING "")

if ("${SSL_CERT_DIR}" STREQUAL "")
	set(SSL_CERT_DIR ".")
endif()

if ("${SSL_CLIENT_CERT_DIR}" STREQUAL "")
	set(LWS_OPENSSL_CLIENT_CERTS ".")
else()
	set(LWS_OPENSSL_CLIENT_CERTS "${SSL_CLIENT_CERT_DIR}")
endif()

set(CYASSL_LIB CACHE STRING "")
set(CYASSL_INCLUDE_DIRS CACHE STRING "")

if (USE_CYASSL)
	if ("${CYASSL_LIB}" STREQUAL "" OR "${CYASSL_INCLUDE_DIRS}" STREQUAL "")
		message(FATAL_ERROR "You must set CYASSL_LIB and CYASSL_INCLUDE_DIRS when USE_CYASSL is turned on")
	endif()
endif()

if (WITHOUT_EXTENSIONS)
	set(LWS_NO_EXTENSIONS 1)
endif()

if (WITH_SSL)
	set(LWS_OPENSSL_SUPPORT 1)
endif()

if (WITH_LATENCY)
	set(LWS_LATENCY 1)
endif()

if (WITHOUT_DAEMONIZE)
	set(LWS_NO_DAEMONIZE 1)
endif()

if (WITHOUT_SERVER)
	set(LWS_NO_SERVER 1)
endif()

if (WITHOUT_CLIENT)
	set(LWS_NO_CLIENT 1)
endif()

if (MINGW)
	set(LWS_MINGW_SUPPORT 1)
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/")
include_directories(${PROJECT_BINARY_DIR})

include(CheckCSourceCompiles)

# Check for different inline keyword versions.
foreach(KEYWORD "inline" "__inline__" "__inline")
	set(CMAKE_REQUIRED_DEFINITIONS "-DKEYWORD=${KEYWORD}")
	CHECK_C_SOURCE_COMPILES(
		"
		#include <stdio.h>
		KEYWORD void a() {}
		int main(int argc, char **argv) { a(); return 0; }
		" HAVE_${KEYWORD})
endforeach()

if (NOT HAVE_inline)
	if (HAVE___inline__)
		set(inline __inline__)
	elseif(HAVE___inline)
		set(inline __inline)
	endif()
endif()

# Put the libaries and binaries that get built into directories at the
# top of the build tree rather than in hard-to-find leaf directories. 
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

# So we can include the CMake generated config file only when
# building with CMAKE.
add_definitions(-DCMAKE_BUILD)

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

if (WITH_BUILTIN_GETIFADDRS)
	if (HAVE_GETIFADDRS)
		warning("getifaddrs already exists on the system, are you sure you want to build using the BSD version? (This is normally only needed on systems running uclibc)")
	endif()
	set(LWS_BUILTIN_GETIFADDRS 1)
endif()

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

# Generate the config.h that includes all the compilation settings.
configure_file(
		${PROJECT_SOURCE_DIR}/config.h.cmake 
		${PROJECT_BINARY_DIR}/lws_config.h)

if (MSVC)
	# Turn off stupid microsoft security warnings.
	add_definitions(-D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE)
endif()

include_directories(${PROJECT_SOURCE_DIR}/lib)

# Group headers and sources.
# Some IDEs use this for nicer file structure.
set(HDR_PRIVATE
	lib/private-libwebsockets.h
	lib/extension-deflate-frame.h
	lib/extension-deflate-stream.h
	${PROJECT_BINARY_DIR}/lws_config.h
	)

set(HDR_PUBLIC	
	lib/libwebsockets.h
	)

set(SOURCES
	lib/base64-decode.c
	lib/client.c
	lib/client-handshake.c
	lib/client-parser.c
	lib/extension.c
	lib/extension-deflate-frame.c
	lib/extension-deflate-stream.c
	lib/handshake.c
	lib/libwebsockets.c
	lib/output.c
	lib/parsers.c
	lib/server.c
	lib/server-handshake.c
	lib/sha-1.c
	)

# Add helper files for Windows.
if (WIN32)
	set(WIN32_HELPERS_PATH win32port/win32helpers)

	list(APPEND HDR_PRIVATE
		${WIN32_HELPERS_PATH}/websock-w32.h
		${WIN32_HELPERS_PATH}/gettimeofday.h
		)

	list(APPEND SOURCES 
		${WIN32_HELPERS_PATH}/websock-w32.c
		${WIN32_HELPERS_PATH}/gettimeofday.c
		)

	include_directories(${WIN32_HELPERS_PATH})
else()
	# Unix.
	if (NOT WITHOUT_DAEMONIZE)
		list(APPEND SOURCES
			lib/daemonize.c
			)
	endif()
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
add_library(websockets STATIC
			${HDR_PRIVATE}
			${HDR_PUBLIC}
			${SOURCES})
add_library(websockets_shared SHARED
			${HDR_PRIVATE}
			${HDR_PUBLIC}
			${SOURCES})

if (WIN32)
	# On Windows libs have the same file ending (.lib)
	# for both static and shared libraries, so we
	# need a unique name for the static one.
	set_target_properties(websockets 
		PROPERTIES
		OUTPUT_NAME websockets_static)

	# Compile as DLL (export function declarations)
	set_property(
		TARGET websockets_shared
		PROPERTY COMPILE_DEFINITIONS 
		LWS_DLL
		LWS_INTERNAL
		)
endif()

# We want the shared lib to be named "libwebsockets"
# not "libwebsocket_shared".
set_target_properties(websockets_shared
		PROPERTIES 
		OUTPUT_NAME websockets)

# Set the so version of the lib.
# Equivalent to LDFLAGS=-version-info 3:0:0
if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
	foreach(lib websockets websockets_shared)
		set_target_properties(${lib} 
			PROPERTIES
			SOVERSION ${SOVERSION})
	endforeach()
endif()

set(LIB_LIST)

#
# Find libraries.
#

#
# ZLIB.
#
if (WIN32 AND NOT USE_EXTERNAL_ZLIB)
	message("Using included Zlib version")

	# Compile ZLib if needed.
	set(WIN32_ZLIB_PATH "win32port/zlib")
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
	add_library(ZLIB STATIC ${ZLIB_SRCS})

	# Set the same variables as find_package would.
	set(ZLIB_INCLUDE_DIRS ${WIN32_ZLIB_PATH})
	get_property(ZLIB_LIBRARIES TARGET ZLIB PROPERTY LOCATION)
	set(ZLIB_FOUND 1)
else()
	find_package(ZLIB REQUIRED)
endif()

# Make sure ZLib is compiled before the libs.
foreach (lib websockets websockets_shared)
	add_dependencies(${lib} ZLIB)
endforeach()

message("ZLib include dirs: ${ZLIB_INCLUDE_DIRS}")
message("ZLib libraries: ${ZLIB_LIBRARIES}")
include_directories(${ZLIB_INCLUDE_DIRS})
list(APPEND LIB_LIST ${ZLIB_LIBRARIES})

#
# OpenSSL
#
if (WITH_SSL)
	message("Compiling with SSL support")

	if (USE_CYASSL)
		# Use CyaSSL as OpenSSL replacement.
		# TODO: Add a find_package command for this also.
		message("CyaSSL include dir: ${CYASSL_INCLUDE_DIRS}")
		message("CyaSSL libraries: ${CYASSL_LIB}")

		# Additional to the root directory we need to include
		# the cyassl/ subdirectory which contains the OpenSSL
		# compatability layer headers.
		foreach(inc ${CYASSL_INCLUDE_DIRS})
			include_directories(${inc} ${inc}/cyassl)
		endforeach()

		list(APPEND ${LIB_LIST} ${CYASSL_LIB})
	else()
		# TODO: Add support for STATIC also.
		find_package(OpenSSL REQUIRED)

		message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
		message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")

		include_directories(${OPENSSL_INCLUDE_DIR})
		list(APPEND LIB_LIST ${OPENSSL_LIBRARIES})
	endif()
endif(WITH_SSL)

#
# Platform specific libs.
#
if (WIN32)
	list(APPEND LIB_LIST ws2_32.lib)
endif()

if (UNIX)
	list(APPEND LIB_LIST m)
endif()

# Setup the linking for all libs.
foreach (lib websockets websockets_shared)
	target_link_libraries(${lib} ${LIB_LIST})
endforeach()

#
# Test applications
#
if (NOT WITHOUT_TESTAPPS)
	#
	# Helper function for adding a test app.
	#
	function(create_test_app TEST_NAME MAIN_SRC WIN32_SRCS WIN32_HDRS)
		
		set(TEST_SRCS ${MAIN_SRC})
		set(TEST_HDR)

		if (WIN32)
			list(APPEND TEST_SRCS 
				${WIN32_HELPERS_PATH}/getopt.c
				${WIN32_HELPERS_PATH}/getopt_long.c
				${WIN32_HELPERS_PATH}/gettimeofday.c
				${WIN32_SRCS})

			list(APPEND TEST_HDR 
				${WIN32_HELPERS_PATH}/getopt.h
				${WIN32_HELPERS_PATH}/gettimeofday.h
				${WIN32_HDRS})
		endif(WIN32)

		source_group("Headers Private"   FILES ${TEST_HDR})
		source_group("Sources"   FILES ${TEST_SRCS})
		add_executable(${TEST_NAME} ${TEST_SRCS} ${TEST_HDR})
		target_link_libraries(${TEST_NAME} websockets)
		add_dependencies(${TEST_NAME} websockets)
		set_property(
					TARGET ${TEST_NAME}
					PROPERTY COMPILE_DEFINITIONS 
						INSTALL_DATADIR="${SSL_CERT_DIR}"
					)
	endfunction()

	#
	# test-client
	#
	if (NOT WITHOUT_CLIENT)
		create_test_app(test-client
			"test-server/test-client.c"
			""
			"")
	endif()

	#
	# test-server
	#
	if (NOT WITHOUT_SERVER)
		create_test_app(test-server
			"test-server/test-server.c"
			""
			"${WIN32_HELPERS_PATH}/netdb.h;${WIN32_HELPERS_PATH}/strings.h;${WIN32_HELPERS_PATH}/unistd.h;${WIN32_HELPERS_PATH}/websock-w32.h")
	endif()

	#
	# test-server-extpoll
	#
	if (NOT WITHOUT_SERVER AND NOT WITHOUT_SERVER_EXTPOLL)
		create_test_app(test-server-extpoll
			"test-server/test-server.c"
			"win32port/win32helpers/websock-w32.c"
			"${WIN32_HELPERS_PATH}/netdb.h;${WIN32_HELPERS_PATH}/strings.h;${WIN32_HELPERS_PATH}/unistd.h;${WIN32_HELPERS_PATH}/websock-w32.h")
			
		# Set defines for this executable only.
		set_property(
			TARGET test-server-extpoll
			PROPERTY COMPILE_DEFINITIONS 
				EXTERNAL_POLL 
				INSTALL_DATADIR="${SSL_CERT_DIR}"
			)

		# We need to link against winsock code.
		if (WIN32)
			target_link_libraries(test-server-extpoll ws2_32.lib)
		endif()
	endif()

	#
	# test-fraggle
	#
	if (NOT WITHOUT_FRAGGLE)
		create_test_app(test-fraggle
			"test-server/test-fraggle.c"
			""
			"${WIN32_HELPERS_PATH}/unistd.h;${WIN32_HELPERS_PATH}/sys/time.h")
	endif()

	#
	# test-ping
	#
	if (NOT WITHOUT_PING)
		create_test_app(test-ping
			"test-server/test-ping.c"
			""
			"${WIN32_HELPERS_PATH}/unistd.h;${WIN32_HELPERS_PATH}/sys/time.h")
	endif()

	#
	# Copy OpenSSL dlls to the output directory on Windows.
	# (Otherwise we'll get an error when trying to run)
	#
	if (WIN32 AND WITH_SSL AND NOT USE_CYASSL)

		message("Searching for OpenSSL dlls")
		find_package(OpenSSLbins)

		if(OPENSSL_BIN_FOUND)
			message("OpenSSL dlls found, copying to output directory")
			message("Libeay: ${LIBEAY_BIN}")
			message("SSLeay: ${SSLEAY_BIN}")

			foreach(TARGET_BIN 
					test-client 
					test-server
					test-server-extpoll
					test-fraggle
					test-echo
					test-ping
					)			
				add_custom_command(TARGET ${TARGET_BIN}
					POST_BUILD 
					COMMAND ${CMAKE_COMMAND} -E copy ${LIBEAY_BIN} $<TARGET_FILE_DIR:${TARGET_BIN}> VERBATIM)
					
				add_custom_command(TARGET ${TARGET_BIN}
					POST_BUILD 
					COMMAND ${CMAKE_COMMAND} -E copy ${SSLEAY_BIN} $<TARGET_FILE_DIR:${TARGET_BIN}> VERBATIM)
			endforeach()
		endif()
	endif()
endif(NOT WITHOUT_TESTAPPS)
