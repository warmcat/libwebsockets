project(lws-minimal-http-client-multi)
cmake_minimum_required(VERSION 2.8)
include(CheckCSourceCompiles)

set(SAMP lws-minimal-http-client-multi)
set(SRCS minimal-http-client-multi.c)

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
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	
       #
       # instantiate the server per sai builder instance, they are running in the same
       # machine context in parallel so they can tread on each other otherwise
       #
       set(PORT_HCM_SRV "7670")
       if ("$ENV{SAI_INSTANCE_IDX}" STREQUAL "0")
               set(PORT_HCM_SRV 7671)
       endif()
       if ("$ENV{SAI_INSTANCE_IDX}" STREQUAL "1")
               set(PORT_HCM_SRV 7672)
       endif()
       if ("$ENV{SAI_INSTANCE_IDX}" STREQUAL "2")
               set(PORT_HCM_SRV 7673)
       endif()
       if ("$ENV{SAI_INSTANCE_IDX}" STREQUAL "3")
               set(PORT_HCM_SRV 7674)
       endif()


# hack
if (NOT WIN32 AND LWS_WITH_SERVER)

	#
	# Tests against built server running locally (needs daemonization...)
	#

if (WIN32)
	add_test(NAME st_hcm_srv COMMAND cmd.exe /c start /b $<TARGET_FILE:lws-minimal-http-server-tls> --port ${PORT_HCM_SRV})
	add_test(NAME ki_hcm_srv COMMAND taskkill /F /IM $<TARGET_FILE_NAME:lws-minimal-http-server-tls> /T)
	add_test(NAME st_hcmp_srv COMMAND cmd.exe /c start /b $<TARGET_FILE:test-server> -s --port 1${PORT_HCM_SRV})
	add_test(NAME ki_hcmp_srv COMMAND taskkill /F /IM $<TARGET_FILE_NAME:test-server> /T)
else()
	add_test(NAME st_hcm_srv COMMAND
		${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
			hcm_srv $<TARGET_FILE:lws-minimal-http-server-tls>
			--port ${PORT_HCM_SRV})
	add_test(NAME ki_hcm_srv COMMAND
		${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
			hcm_srv $<TARGET_FILE_NAME:lws-minimal-http-server-tls>
				--port ${PORT_HCM_SRV})
	add_test(NAME st_hcmp_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				hcmp_srv $<TARGET_FILE:test-server> -s
				-r ${CMAKE_SOURCE_DIR}/destdir/usr/local/share/libwebsockets-test-server/
				--port 1${PORT_HCM_SRV})
	add_test(NAME ki_hcmp_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				hcmp_srv $<TARGET_FILE_NAME:test-server>
				--port 1${PORT_HCM_SRV})
endif()

	set_tests_properties(st_hcm_srv PROPERTIES
       		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/http-server/minimal-http-server-tls
		FIXTURES_SETUP hcm_srv
		TIMEOUT 800)
	set_tests_properties(ki_hcm_srv PROPERTIES
		FIXTURES_CLEANUP hcm_srv)

	set_tests_properties(st_hcmp_srv PROPERTIES
       		WORKING_DIRECTORY .
		FIXTURES_SETUP hcmp_srv
		TIMEOUT 800)
	set_tests_properties(ki_hcmp_srv PROPERTIES
		FIXTURES_CLEANUP hcmp_srv)

	#
	# Tests against local server peer
	#

	add_test(NAME http-client-multi COMMAND lws-minimal-http-client-multi
			-l --port ${PORT_HCM_SRV})
	add_test(NAME http-client-multi-h1 COMMAND lws-minimal-http-client-multi
			--h1 -l --port ${PORT_HCM_SRV})
	add_test(NAME http-client-multi-pipe COMMAND lws-minimal-http-client-multi
			-p -l --port ${PORT_HCM_SRV})
	add_test(NAME http-client-multi-h1-pipe COMMAND lws-minimal-http-client-multi
			--h1 -p -l --port ${PORT_HCM_SRV})
	add_test(NAME http-client-multi-stag COMMAND lws-minimal-http-client-multi
			-s -l --port ${PORT_HCM_SRV})
	add_test(NAME http-client-multi-stag-h1 COMMAND lws-minimal-http-client-multi
			--h1 -s -l --port ${PORT_HCM_SRV})
	add_test(NAME http-client-multi-stag-pipe COMMAND lws-minimal-http-client-multi
			-p -s -l --port ${PORT_HCM_SRV})
	add_test(NAME http-client-multi-stag-h1-pipe COMMAND lws-minimal-http-client-multi
			--h1 -p -s -l --port ${PORT_HCM_SRV})

	# confirm that the pipelined mode really is doing it in one connection
	add_test(NAME http-client-multi-restrict-pipe COMMAND lws-minimal-http-client-multi -d1151 --limit 1 -p -l --port ${PORT_HCM_SRV})
	add_test(NAME http-client-multi-restrict-h1-pipe COMMAND lws-minimal-http-client-multi -d1151 --limit 1 --h1 -p -l --port ${PORT_HCM_SRV})
	add_test(NAME http-client-multi-restrict-stag-pipe COMMAND lws-minimal-http-client-multi -d1151 --limit 1 -p -s -l --port ${PORT_HCM_SRV})
	add_test(NAME http-client-multi-restrict-stag-h1-pipe COMMAND lws-minimal-http-client-multi -d1151 --limit 1 --h1 -p -s -l --port ${PORT_HCM_SRV})
	# confirm that we do fail with a one connection limit and no pipelining
	add_test(NAME http-client-multi-restrict-nopipe-fail COMMAND lws-minimal-http-client-multi --limit 1 -l --port ${PORT_HCM_SRV})
	set_property(TEST http-client-multi-restrict-nopipe-fail PROPERTY WILL_FAIL TRUE)
	add_test(NAME http-client-multi-restrict-h1-nopipe-fail COMMAND lws-minimal-http-client-multi --limit 1 --h1 -l --port ${PORT_HCM_SRV})
	set_property(TEST http-client-multi-restrict-h1-nopipe-fail PROPERTY WILL_FAIL TRUE)

	set_tests_properties(http-client-multi-restrict-pipe
			     http-client-multi-restrict-h1-pipe
			     http-client-multi-restrict-stag-pipe
			     http-client-multi-restrict-stag-h1-pipe
			     http-client-multi-restrict-nopipe-fail
			     http-client-multi-restrict-h1-nopipe-fail
			     http-client-multi
			     http-client-multi-h1
			     http-client-multi-pipe
			     http-client-multi-h1-pipe
			     http-client-multi-stag
			     http-client-multi-stag-h1
			     http-client-multi-stag-pipe
			     http-client-multi-stag-h1-pipe
			     PROPERTIES
			     FIXTURES_REQUIRED "hcm_srv"
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/http-client/minimal-http-client-multi
			     TIMEOUT 20)

	# POSTs against local http-server-form-post
	add_test(NAME http-client-multi-post COMMAND lws-minimal-http-client-multi
			--post -l --port 1${PORT_HCM_SRV})
	add_test(NAME http-client-multi-post-h1 COMMAND lws-minimal-http-client-multi
			--post --h1 -l --port 1${PORT_HCM_SRV})
	add_test(NAME http-client-multi-post-pipe COMMAND lws-minimal-http-client-multi
			--post -p -l --port 1${PORT_HCM_SRV})
	add_test(NAME http-client-multi-post-h1-pipe COMMAND lws-minimal-http-client-multi
			--post --h1 -p -l --port 1${PORT_HCM_SRV})
	add_test(NAME http-client-multi-post-stag COMMAND lws-minimal-http-client-multi
			--post -s -l -d1151 --port 1${PORT_HCM_SRV})
	add_test(NAME http-client-multi-post-stag-h1 COMMAND lws-minimal-http-client-multi
			--post --h1 -d1151 -s -l --port 1${PORT_HCM_SRV})
	add_test(NAME http-client-multi-post-stag-pipe COMMAND lws-minimal-http-client-multi
			--post -p -s -l --port 1${PORT_HCM_SRV})
	add_test(NAME http-client-multi-post-stag-h1-pipe COMMAND lws-minimal-http-client-multi
			--post --h1 -p -s -l --port 1${PORT_HCM_SRV})
	set_tests_properties(http-client-multi-post
			     http-client-multi-post-h1
			     http-client-multi-post-pipe
			     http-client-multi-post-h1-pipe
			     http-client-multi-post-stag
			     http-client-multi-post-stag-h1
			     http-client-multi-post-stag-pipe
			     http-client-multi-post-stag-h1-pipe
			     PROPERTIES
			     	FIXTURES_REQUIRED "hcmp_srv"
			     	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/http-client/minimal-http-client-multi
			     	TIMEOUT 20)

endif(NOT WIN32 AND LWS_WITH_SERVER)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared)
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets)
	endif()
endif()
