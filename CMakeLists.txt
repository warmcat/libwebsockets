cmake_minimum_required(VERSION 2.6)

project(libwebsockets)

set(PACKAGE "libwebsockets")
set(CPACK_PACKAGE_NAME "${PACKAGE}")
set(CPACK_PACKAGE_VERSION_MAJOR "1")
set(CPACK_PACKAGE_VERSION_MINOR "3")
set(CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}")
set(CPACK_PACKAGE_VENDOR "andy@warmcat.com")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PACKAGE} ${PACKAGE_VERSION}")
set(SOVERSION "4.0.0")
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
set(VERSION "${CPACK_PACKAGE_VERSION}")

set(LWS_LIBRARY_VERSION ${CPACK_PACKAGE_VERSION})
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/")

message(STATUS "CMAKE_TOOLCHAIN_FILE='${CMAKE_TOOLCHAIN_FILE}'")

# Try to find the current Git hash.
find_package(Git)
if(GIT_EXECUTABLE)
	execute_process(
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
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
option(WITHOUT_BUILTIN_GETIFADDRS "Don't use BSD getifaddrs implementation from libwebsockets if it is missing (this will result in a compilation error) ... Default is your libc provides it. On some systems such as uclibc it doesn't exist." OFF)
option(WITHOUT_CLIENT "Don't build the client part of the library" OFF)
option(WITHOUT_SERVER "Don't build the server part of the library" OFF)
#option(WITH_LIBCRYPTO "Use libcrypto MD5 and SHA1 implementations" ON)
option(LINK_TESTAPPS_DYNAMIC "Link the test apps to the shared version of the library. Default is to link statically" OFF)
option(WITHOUT_TESTAPPS "Don't build the libwebsocket-test-apps" OFF)
option(WITHOUT_TEST_SERVER "Don't build the test server" OFF)
option(WITHOUT_TEST_SERVER_EXTPOLL "Don't build the test server version that uses external poll" OFF)
option(WITHOUT_TEST_PING "Don't build the ping test application" OFF)
option(WITHOUT_TEST_CLIENT "Don't build the client test application" OFF)
option(WITHOUT_TEST_FRAGGLE "Don't build the ping test application" OFF)
option(WITHOUT_DEBUG "Don't compile debug related code" OFF)
option(WITHOUT_EXTENSIONS "Don't compile with extensions" OFF)
option(WITH_LATENCY "Build latency measuring code into the library" OFF)
option(WITHOUT_DAEMONIZE "Don't build the daemonization api" OFF)

if (WITHOUT_CLIENT AND WITHOUT_SERVER)
	message(FATAL_ERROR "Makes no sense to compile without both client or server.")
endif()

# The base dir where the test-apps look for the SSL certs.
set(SSL_CERT_DIR CACHE STRING "")
set(SSL_CLIENT_CERT_DIR CACHE STRING "")

if ("${SSL_CERT_DIR}" STREQUAL "")
	set(SSL_CERT_DIR "../share")
endif()

if ("${SSL_CLIENT_CERT_DIR}" STREQUAL "")
	if (WIN32)
		set(LWS_OPENSSL_CLIENT_CERTS ".")
	else()
		set(LWS_OPENSSL_CLIENT_CERTS "/etc/pki/tls/certs/")
	endif()
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

if (WITHOUT_DEBUG)
	set(_DEBUG 0)
else()
	set(_DEBUG 1)
endif()

if (MINGW)
	set(LWS_MINGW_SUPPORT 1)
endif()

include_directories("${PROJECT_BINARY_DIR}")

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
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin")
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")
SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")

# Put absolute path of dynamic libraries into the object code. Some
# architectures, notably Mac OS X, need this.
SET(CMAKE_INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}")

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

if (NOT HAVE_GETIFADDRS)
	if (WITHOUT_BUILTIN_GETIFADDRS)
		message(FATAL_ERROR "No getifaddrs was found on the system. Turn off the WITHOUT_BUILTIN_GETIFADDRS compile option to use the supplied BSD version.")
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
       "${PROJECT_SOURCE_DIR}/config.h.cmake"
       "${PROJECT_BINARY_DIR}/lws_config.h")

if (MSVC)
	# Turn off stupid microsoft security warnings.
	add_definitions(-D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE)
endif(MSVC)

include_directories("${PROJECT_SOURCE_DIR}/lib")

# Group headers and sources.
# Some IDEs use this for nicer file structure.
set(HDR_PRIVATE
	lib/private-libwebsockets.h
	"${PROJECT_BINARY_DIR}/lws_config.h"
	)

set(HDR_PUBLIC	
	"${PROJECT_SOURCE_DIR}/lib/libwebsockets.h"
	)

set(SOURCES
	lib/base64-decode.c
	lib/handshake.c
	lib/libwebsockets.c
	lib/output.c
	lib/parsers.c
	lib/sha-1.c
	)

if (NOT WITHOUT_CLIENT)
	list(APPEND SOURCES
		lib/client.c
		lib/client-handshake.c
		lib/client-parser.c
		)
endif()

if (NOT WITHOUT_SERVER)
	list(APPEND SOURCES
		lib/server.c
		lib/server-handshake.c
		)
endif()

if (NOT WITHOUT_EXTENSIONS)
	list(APPEND HDR_PRIVATE
		lib/extension-deflate-frame.h
		lib/extension-deflate-stream.h
		)

	list(APPEND SOURCES
		lib/extension.c
		lib/extension-deflate-frame.c
		lib/extension-deflate-stream.c
		)
endif()

# Add helper files for Windows.
if (WIN32)
	set(WIN32_HELPERS_PATH win32port/win32helpers)

	list(APPEND HDR_PUBLIC
		${WIN32_HELPERS_PATH}/websock-w32.h
		${WIN32_HELPERS_PATH}/gettimeofday.h
		)
	if (MINGW)
		list(APPEND SOURCES
			${WIN32_HELPERS_PATH}/gettimeofday.c
			)
	else(MINGW)
		list(APPEND SOURCES
			${WIN32_HELPERS_PATH}/websock-w32.c
			${WIN32_HELPERS_PATH}/gettimeofday.c
			)
	endif(MINGW)
	include_directories(${WIN32_HELPERS_PATH})
else(WIN32)
	# Unix.
	if (NOT WITHOUT_DAEMONIZE)
		list(APPEND SOURCES
			lib/daemonize.c
			)
	endif()
endif(WIN32)

if (UNIX)
	if (NOT HAVE_GETIFADDRS)
		list(APPEND HDR_PRIVATE lib/getifaddrs.h)
		list(APPEND SOURCES lib/getifaddrs.c)
	endif()
endif(UNIX)


if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
	set( CMAKE_C_FLAGS "-Wall -Werror -O4 -fvisibility=hidden ${CMAKE_C_FLAGS}" )
endif ()

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
endif(WIN32)

# We want the shared lib to be named "libwebsockets"
# not "libwebsocket_shared".
set_target_properties(websockets_shared
		PROPERTIES 
		OUTPUT_NAME websockets)

# Set the so version of the lib.
# Equivalent to LDFLAGS=-version-info x:x:x
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
# ZLIB (Only needed for deflate extensions).
#
if (NOT WITHOUT_EXTENSIONS)
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
endif(NOT WITHOUT_EXTENSIONS)

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
			include_directories("${inc}" "${inc}/cyassl")
		endforeach()

		list(APPEND LIB_LIST "${CYASSL_LIB}")
	else()
		# TODO: Add support for STATIC also.
		find_package(OpenSSL REQUIRED)

		message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
		message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")

		include_directories("${OPENSSL_INCLUDE_DIR}")
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
set(TEST_APP_LIST)
if (NOT WITHOUT_TESTAPPS)
	#
	# Helper function for adding a test app.
	#
	macro(create_test_app TEST_NAME MAIN_SRC WIN32_SRCS WIN32_HDRS)
		
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
		
		if (LINK_TESTAPPS_DYNAMIC)
			target_link_libraries(${TEST_NAME} websockets_shared)
			add_dependencies(${TEST_NAME} websockets_shared)
		else(LINK_TESTAPPS_DYNAMIC)
			target_link_libraries(${TEST_NAME} websockets)
			add_dependencies(${TEST_NAME} websockets)
		endif(LINK_TESTAPPS_DYNAMIC)

		# Set test app specific defines.
		set_property(TARGET ${TEST_NAME}
					PROPERTY COMPILE_DEFINITIONS 
						INSTALL_DATADIR="${CMAKE_INSTALL_PREFIX}/share"
					)

		# Prefix the binary names with libwebsockets.
		set_target_properties(${TEST_NAME} 
			PROPERTIES
			OUTPUT_NAME libwebsockets-${TEST_NAME})

		# Add to the list of tests.
		list(APPEND TEST_APP_LIST ${TEST_NAME})
	endmacro()

	if (WITH_SSL AND NOT USE_CYASSL)
		message("Searching for OpenSSL executable and dlls")
		find_package(OpenSSLbins)
		message("OpenSSL executable: ${OPENSSL_EXECUTABLE}")
	endif()

	if (NOT WITHOUT_SERVER)
		#
		# test-server
		#
		if (NOT WITHOUT_TEST_SERVER)
			create_test_app(test-server
				"test-server/test-server.c"
				""
				"${WIN32_HELPERS_PATH}/netdb.h;${WIN32_HELPERS_PATH}/strings.h;${WIN32_HELPERS_PATH}/unistd.h;${WIN32_HELPERS_PATH}/websock-w32.h")
		endif()

		#
		# test-server-extpoll
		#
		if (NOT WITHOUT_TEST_SERVER_EXTPOLL)
			create_test_app(test-server-extpoll
				"test-server/test-server.c"
				"win32port/win32helpers/websock-w32.c"
				"${WIN32_HELPERS_PATH}/netdb.h;${WIN32_HELPERS_PATH}/strings.h;${WIN32_HELPERS_PATH}/unistd.h;${WIN32_HELPERS_PATH}/websock-w32.h")
			# Set defines for this executable only.
			set_property(
				TARGET test-server-extpoll
				PROPERTY COMPILE_DEFINITIONS 
					EXTERNAL_POLL 
					INSTALL_DATADIR="${CMAKE_INSTALL_PREFIX}/share"
				)

			# We need to link against winsock code.
			if (WIN32)
				target_link_libraries(test-server-extpoll ws2_32.lib)
			endif(WIN32)
		endif()

		# Data files for running the test server.
		set(TEST_SERVER_DATA
			"${PROJECT_SOURCE_DIR}/test-server/favicon.ico"
			"${PROJECT_SOURCE_DIR}/test-server/leaf.jpg"
			"${PROJECT_SOURCE_DIR}/test-server/libwebsockets.org-logo.png"
			"${PROJECT_SOURCE_DIR}/test-server/test.html")

		# Generate self-signed SSL certs for the test-server.
		if (WITH_SSL AND OPENSSL_EXECUTABLE)
			message("Generating SSL Certificates for the test-server...")

			set(TEST_SERVER_SSL_KEY "${PROJECT_BINARY_DIR}/libwebsockets-test-server.key.pem")
			set(TEST_SERVER_SSL_CERT "${PROJECT_BINARY_DIR}/libwebsockets-test-server.pem")

			if (WIN32)
				file(WRITE "${PROJECT_BINARY_DIR}/openssl_input.txt"
					"GB\n"
					"Erewhon\n"
					"All around\n"
					"libwebsockets-test\n"
					"localhost\n"
					"none@invalid.org\n\n"
					)
				
				# The "type" command is a bit picky with paths.
				file(TO_NATIVE_PATH "${PROJECT_BINARY_DIR}/openssl_input.txt" OPENSSL_INPUT_WIN_PATH)

				execute_process(
					COMMAND cmd /c type "${OPENSSL_INPUT_WIN_PATH}"
					COMMAND "${OPENSSL_EXECUTABLE}" req -new -newkey rsa:1024 -days 10000 -nodes -x509 -keyout "${TEST_SERVER_SSL_KEY}" -out "${TEST_SERVER_SSL_CERT}"
					RESULT_VARIABLE OPENSSL_RETURN_CODE)
				
				message("\n")

				if (OPENSSL_RETURN_CODE)
					message("!!! Failed to generate SSL certificate:\n${OPENSSL_RETURN_CODE} !!!")
				endif()
			else()
				execute_process(
					COMMAND printf "GB\\nErewhon\\nAll around\\nlibwebsockets-test\\n\\nlocalhost\\nnone@invalid.org\\n"
					COMMAND "${OPENSSL_EXECUTABLE}"
						req -new -newkey rsa:1024 -days 10000 -nodes -x509 -keyout "${TEST_SERVER_SSL_KEY}" -out "${TEST_SERVER_SSL_CERT}"
					)
			endif()

			list(APPEND TEST_SERVER_DATA 
				"${TEST_SERVER_SSL_KEY}"
				"${TEST_SERVER_SSL_CERT}")
		endif()

		# Copy the file needed to run the server so that the test apps can
		# reach them from their default output location
		foreach (TEST_FILE ${TEST_SERVER_DATA})
			add_custom_command(TARGET test-server
						POST_BUILD 
						COMMAND "${CMAKE_COMMAND}" -E make_directory "$<TARGET_FILE_DIR:test-server>/../share/libwebsockets-test-server"
						COMMAND "${CMAKE_COMMAND}" -E copy "${TEST_FILE}" "$<TARGET_FILE_DIR:test-server>/../share/libwebsockets-test-server" VERBATIM)
		endforeach()
	endif(NOT WITHOUT_SERVER)

	if (NOT WITHOUT_CLIENT)
		#
		# test-client
		#
		if (NOT WITHOUT_TEST_CLIENT)
			create_test_app(test-client
				"test-server/test-client.c"
				""
				"")
		endif()

		#
		# test-fraggle
		#
		if (NOT WITHOUT_TEST_FRAGGLE)
			create_test_app(test-fraggle
				"test-server/test-fraggle.c"
				""
				"${WIN32_HELPERS_PATH}/unistd.h;${WIN32_HELPERS_PATH}/sys/time.h")
		endif()

		#
		# test-ping
		#
		if (NOT WITHOUT_TEST_PING)
			create_test_app(test-ping
				"test-server/test-ping.c"
				""
				"${WIN32_HELPERS_PATH}/unistd.h;${WIN32_HELPERS_PATH}/sys/time.h")
		endif()
		#
		# test-echo
		#
		if (NOT WITHOUT_TEST_ECHO)
			create_test_app(test-echo
				"test-server/test-echo.c"
				""
				"${WIN32_HELPERS_PATH}/unistd.h;${WIN32_HELPERS_PATH}/sys/time.h")
		endif()

	endif(NOT WITHOUT_CLIENT)

	#
	# Copy OpenSSL dlls to the output directory on Windows.
	# (Otherwise we'll get an error when trying to run)
	#
	if (WIN32 AND WITH_SSL AND NOT USE_CYASSL)
		if(OPENSSL_BIN_FOUND)
			message("OpenSSL dlls found:")
			message("  Libeay: ${LIBEAY_BIN}")
			message("  SSLeay: ${SSLEAY_BIN}")

			foreach(TARGET_BIN ${TEST_APP_LIST})			
				add_custom_command(TARGET ${TARGET_BIN}
					POST_BUILD 
					COMMAND "${CMAKE_COMMAND}" -E copy "${LIBEAY_BIN}" "$<TARGET_FILE_DIR:${TARGET_BIN}>" VERBATIM)
					
				add_custom_command(TARGET ${TARGET_BIN}
					POST_BUILD 
					COMMAND "${CMAKE_COMMAND}" -E copy "${SSLEAY_BIN}" "$<TARGET_FILE_DIR:${TARGET_BIN}>" VERBATIM)
			endforeach()
		endif()
	endif()
endif(NOT WITHOUT_TESTAPPS)

if (UNIX)
	# Generate documentation.
	# TODO: Fix this on Windows.
	message("Generating API documentation")
	file(GLOB C_FILES "${PROJECT_SOURCE_DIR}/lib/*.c")
	execute_process(COMMAND "${CMAKE_COMMAND}" -E make_directory "${PROJECT_BINARY_DIR}/doc/")

	execute_process(
		COMMAND "${PROJECT_SOURCE_DIR}/scripts/kernel-doc" -html ${C_FILES} ${HDR_PUBLIC}
		OUTPUT_FILE "${PROJECT_BINARY_DIR}/doc/libwebsockets-api-doc.html"
		ERROR_QUIET)

	execute_process(
		COMMAND "${PROJECT_SOURCE_DIR}/scripts/kernel-doc" -text ${C_FILES} ${HDR_PUBLIC}
		OUTPUT_FILE "${PROJECT_BINARY_DIR}/doc/libwebsockets-api-doc.txt"
		ERROR_QUIET)

# Generate and install pkgconfig.
# (This is not indented, because the tabs will be part of the output)
file(WRITE "${PROJECT_BINARY_DIR}/libwebsockets.pc"
"prefix="${CMAKE_INSTALL_PREFIX}"
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib${LIB_SUFFIX}
includedir=\${prefix}/include

Name: libwebsockets
Description: Websockets server and client library
Version: ${PACKAGE_VERSION}

Libs: -L\${libdir} -lwebsockets
Cflags: -I\${includedir}"
)

	install(FILES "${PROJECT_BINARY_DIR}/libwebsockets.pc"
		DESTINATION lib${LIB_SUFFIX}/pkgconfig)
endif(UNIX)

# Install headers.
install(FILES ${HDR_PUBLIC} 
		DESTINATION include
		COMPONENT headers)
set(CPACK_COMPONENT_HEADERS_DISPLAY_NAME "Header files")

# Install libs.
install(TARGETS websockets websockets_shared
		LIBRARY DESTINATION lib${LIB_SUFFIX}
		ARCHIVE DESTINATION lib${LIB_SUFFIX}
		COMPONENT libraries)
set(CPACK_COMPONENT_LIBRARIES_DISPLAY_NAME "Libraries")

# Install test apps.
if (NOT WITHOUT_TESTAPPS)
	install(TARGETS test-client ${TEST_APP_LIST}
			RUNTIME DESTINATION bin
			COMPONENT examples)
	set(CPACK_COMPONENT_EXAMPLES_DISPLAY_NAME "Example Install")
endif()

# Programs shared files used by the test-server.
if (NOT WITHOUT_TESTAPPS AND NOT WITHOUT_SERVER)
	install(FILES ${TEST_SERVER_DATA}
			DESTINATION share/libwebsockets-test-server
			COMPONENT examples)
endif()

# build subdir is not part of sources
set(CPACK_SOURCE_IGNORE_FILES $(CPACK_SOURCE_IGNORE_FILES) ".git" "build" "tgz" "tar.gz")

# Most people are more used to "make dist" compared to "make package_source"
add_custom_target(dist COMMAND "${CMAKE_MAKE_PROGRAM}" package_source)

INCLUDE(UseRPMTools)
IF(RPMTools_FOUND)
	RPMTools_ADD_RPM_TARGETS(libwebsockets libwebsockets.spec)
ENDIF(RPMTools_FOUND)

# This must always be last!
include(CPack)
