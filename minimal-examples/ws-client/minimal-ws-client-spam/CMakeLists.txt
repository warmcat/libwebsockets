project(lws-minimal-ws-client-spam)
cmake_minimum_required(VERSION 2.8)
include(CheckIncludeFile)
include(CheckCSourceCompiles)

set(SAMP lws-minimal-ws-client-spam)
set(SRCS minimal-ws-client-spam.c)

MACRO(require_pthreads result)
	CHECK_INCLUDE_FILE(pthread.h LWS_HAVE_PTHREAD_H)
	if (NOT LWS_HAVE_PTHREAD_H)
		if (LWS_WITH_MINIMAL_EXAMPLES)
			set(${result} 0)
			message("${SAMP}: skipping as no pthreads")
		else()
			message(FATAL_ERROR "threading support requires pthreads")
		endif()
	else()
		if (WIN32)
			set(PTHREAD_LIB ${LWS_EXT_PTHREAD_LIBRARIES})
		else()
			set(PTHREAD_LIB pthread)
		endif()
	endif()
ENDMACRO()

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
require_pthreads(requirements)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
       #
       # instantiate the server per sai builder instance, they are running in the same
       # machine context in parallel so they can tread on each other otherwise
       #
       set(SPLOCALTESTPORT "7620")
       if ("$ENV{SAI_INSTANCE_IDX}" STREQUAL "0")
	       set(SPLOCALTESTPORT 7621)
       endif()
       if ("$ENV{SAI_INSTANCE_IDX}" STREQUAL "1")
	       set(SPLOCALTESTPORT 7622)
       endif()
       if ("$ENV{SAI_INSTANCE_IDX}" STREQUAL "2")
	       set(SPLOCALTESTPORT 7623)
       endif()

# hack
if (WIN32)
else()

if (WIN32)
	add_test(NAME sts COMMAND cmd.exe /c start /b $<TARGET_FILE:test-server> -s --port ${SPLOCALTESTPORT})
	add_test(NAME cts COMMAND taskkill /F /IM $<TARGET_FILE_NAME:test-server> /T)
else()
	add_test(NAME sts COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh $<TARGET_FILE:test-server> -s --port ${SPLOCALTESTPORT})
	add_test(NAME cts COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh $<TARGET_FILE_NAME:test-server>)
endif()

	set_tests_properties(sts PROPERTIES WORKING_DIRECTORY . FIXTURES_SETUP localspamserver TIMEOUT 800)
	set_tests_properties(cts PROPERTIES FIXTURES_CLEANUP localspamserver)

	add_test(NAME ws-client-spam COMMAND lws-minimal-ws-client-spam --server localhost --port ${SPLOCALTESTPORT} -l 32 -c 3)
	set_tests_properties(ws-client-spam PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/ws-client/minimal-ws-client-spam
			     FIXTURES_REQUIRED "localspamserver"
			     TIMEOUT 40)
endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${PTHREAD_LIB})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${PTHREAD_LIB})
	endif()
endif()
