project(lws-minimal-http-client-post)
cmake_minimum_required(VERSION 2.8)
include(CheckCSourceCompiles)

set(SAMP lws-minimal-http-client-post)
set(SRCS minimal-http-client-post.c)

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
	set(PORT_HCP_SRV "7640")
	if ("$ENV{SAI_INSTANCE_IDX}" STREQUAL "0")
		set(PORT_HCP_SRV 7641)
	endif()
	if ("$ENV{SAI_INSTANCE_IDX}" STREQUAL "1")
		set(PORT_HCP_SRV 7642)
	endif()
	if ("$ENV{SAI_INSTANCE_IDX}" STREQUAL "2")
		set(PORT_HCP_SRV 7643)
	endif()
	if ("$ENV{SAI_INSTANCE_IDX}" STREQUAL "3")
		set(PORT_HCP_SRV 7644)
	endif()
	
# hack
if (NOT WIN32 AND LWS_WITH_SERVER)

	#
	# Tests against built server running locally (needs daemonization...)
	#

if (WIN32)
	add_test(NAME st_hcp_srv COMMAND cmd.exe /c start /b $<TARGET_FILE:test-server> -s --port ${PORT_HCP_SRV})
	add_test(NAME ki_hcp_srv COMMAND taskkill /F /IM $<TARGET_FILE_NAME:test-server> /T)
else()
	add_test(NAME st_hcp_srv COMMAND
		${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				hcp_srv
				$<TARGET_FILE:test-server>
				-r ${CMAKE_SOURCE_DIR}/destdir/usr/local/share/libwebsockets-test-server/
				-s --port ${PORT_HCP_SRV})
	add_test(NAME ki_hcp_srv COMMAND
		${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh hcp_srv
				$<TARGET_FILE_NAME:test-server> --port ${PORT_HCP_SRV})
endif()

	set_tests_properties(st_hcp_srv PROPERTIES
					     WORKING_DIRECTORY .
					     FIXTURES_SETUP hcp_srv
					     TIMEOUT 800)
	set_tests_properties(ki_hcp_srv PROPERTIES
					     FIXTURES_CLEANUP hcp_srv)

	add_test(NAME http-client-post COMMAND
		lws-minimal-http-client-post -l --port ${PORT_HCP_SRV})
	add_test(NAME http-client-post-m COMMAND
		lws-minimal-http-client-post -l -m --port ${PORT_HCP_SRV})
	add_test(NAME http-client-post-h1 COMMAND
		lws-minimal-http-client-post -l --h1 --port ${PORT_HCP_SRV})
	add_test(NAME http-client-post-m-h1 COMMAND
		lws-minimal-http-client-post -l -m --h1 --port ${PORT_HCP_SRV})
	set_tests_properties(http-client-post
			     http-client-post-m
			     http-client-post-h1
			     http-client-post-m-h1
			     PROPERTIES
			     FIXTURES_REQUIRED "hcp_srv"
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/http-client/minimal-http-client-post
			     TIMEOUT 20)
endif()


	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared)
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets)
	endif()
endif()
