project(lws-minimal-dbus-client)
cmake_minimum_required(VERSION 2.8)
include(CheckCSourceCompiles)
include(CheckLibraryExists)

set(SAMP lws-minimal-dbus-client)
set(SRCS minimal-dbus-client.c)

if (NOT LWS_WITH_MINIMAL_EXAMPLES)
	CHECK_LIBRARY_EXISTS(dbus-1 dbus_connection_set_watch_functions "" LWS_HAVE_LIBDBUS)
	if (NOT LWS_HAVE_LIBDBUS)
		message(FATAL_ERROR "Install dbus-devel, or libdbus-1-dev etc")
	endif()

	if (NOT LWS_DBUS_LIB)
		set(LWS_DBUS_LIB "dbus-1")
	endif()

	if (NOT LWS_DBUS_INCLUDE1)
		# look in fedora and debian / ubuntu place
		if (EXISTS "/usr/include/dbus-1.0")
			set(LWS_DBUS_INCLUDE1 "/usr/include/dbus-1.0")
		else()
			message(FATAL_ERROR "Set LWS_DBUS_INCLUDE1 to /usr/include/dbus-1.0 or wherever the main dbus includes are")
		endif()
	endif()

	if (NOT LWS_DBUS_INCLUDE2)
		# look in fedora... debian / ubuntu has the ARCH in the path...
		if (EXISTS "/usr/lib64/dbus-1.0/include")
			set(LWS_DBUS_INCLUDE2 "/usr/lib64/dbus-1.0/include")
		else()
			message(FATAL_ERROR "Set LWS_DBUS_INCLUDE2 to /usr/lib/ARCH-linux-gnu/dbus-1.0/include or wherever dbus-arch-deps.h is on your system")
		endif()
	endif()

	set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES};${LWS_DBUS_INCLUDE1};${LWS_DBUS_INCLUDE2})

	if (NOT LWS_DBUS_INCLUDE1 OR NOT LWS_DBUS_INCLUDE2)
		message(FATAL_ERROR "To build with libdbus, LWS_DBUS_INCLUDE1/2 must be given. See lib/roles/dbus/README.md")
	endif()

endif()

# If we are being built as part of lws, confirm current build config supports
# reqconfig, else skip building ourselves.
#
# If we are being built externally, confirm installed lws was configured to
# support reqconfig, else error out with a helpful message about the problem.
#
MACRO(require_lws_config reqconfig _val result)

	if (DEFINED ${reqconfig})
	if (${reqconfig})
		set (rq 1)
	else()
		set (rq 0)
	endif()
	else()
		set(rq 0)
	endif()

	if (${_val} EQUAL ${rq})
		set(SAME 1)
	else()
		set(SAME 0)
	endif()

	if (LWS_WITH_MINIMAL_EXAMPLES AND NOT ${SAME})
		if (${_val})
			message("${SAMP}: skipping as lws being built without ${reqconfig}")
		else()
			message("${SAMP}: skipping as lws built with ${reqconfig}")
		endif()
		set(${result} 0)
	else()
		if (LWS_WITH_MINIMAL_EXAMPLES)
			set(MET ${SAME})
		else()
			CHECK_C_SOURCE_COMPILES("#include <libwebsockets.h>\nint main(void) {\n#if defined(${reqconfig})\n return 0;\n#else\n fail;\n#endif\n return 0;\n}\n" HAS_${reqconfig})
			if (NOT DEFINED HAS_${reqconfig} OR NOT HAS_${reqconfig})
				set(HAS_${reqconfig} 0)
			else()
				set(HAS_${reqconfig} 1)
			endif()
			if ((HAS_${reqconfig} AND ${_val}) OR (NOT HAS_${reqconfig} AND NOT ${_val}))
				set(MET 1)
			else()
				set(MET 0)
			endif()
		endif()
		if (NOT MET)
			if (${_val})
				message(FATAL_ERROR "This project requires lws must have been configured with ${reqconfig}")
			else()
				message(FATAL_ERROR "Lws configuration of ${reqconfig} is incompatible with this project")
			endif()
		endif()

	endif()
ENDMACRO()


set(requirements 1)
require_lws_config(LWS_ROLE_DBUS 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	
	include_directories("${LWS_DBUS_INCLUDE1}")
	include_directories("${LWS_DBUS_INCLUDE2}")
	list(APPEND LIB_LIST dbus-1)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared)
		add_dependencies(${SAMP} websockets_shared ${LWS_DBUS_LIB})
	else()
		target_link_libraries(${SAMP} websockets ${LWS_DBUS_LIB})
	endif()
endif()
