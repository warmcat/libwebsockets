project(lws-minimal-http-client-post-form C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-client-post-form)
set(SRCS minimal-http-client-post-form.c)

set(requirements 1)
set(MBEDTLS 0)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
# ctest for this requires server
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITHOUT_TEST_SERVER 0 requirements)
require_lws_config(LWS_WITHOUT_TESTAPPS 0 requirements)
require_lws_config(LWS_WITH_FILE_OPS 1 requirements)

require_lws_config(LWS_WITH_MBEDTLS 1 MBEDTLS)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	find_program(VALGRIND "valgrind")
	
	#
	# instantiate the server per sai builder instance, they are running in the same
	# machine context in parallel so they can tread on each other otherwise
	#
	set(PORT_HCP_SRV "7340")
	if ("$ENV{SAI_INSTANCE_IDX}")
		math(EXPR PORT_HCP_SRV "7341 + $ENV{SAI_INSTANCE_IDX}")
	endif()

# hack
if (NOT WIN32 AND LWS_WITH_SERVER)

	#
	# Tests against built server running locally (needs daemonization...)
	#

if (WIN32)
	add_test(NAME st_hcpf_srv COMMAND cmd.exe /c start /b $<TARGET_FILE:test-server> -s --port ${PORT_HCP_SRV})
	add_test(NAME ki_hcpf_srv COMMAND taskkill /F /IM $<TARGET_FILE_NAME:test-server> /T)
else()
	#
	# mbedtls is too slow to keep up on some targets, when ctest is in parallel
	#
	if (VALGRIND AND NOT MBEDTLS)
		add_test(NAME st_hcpf_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
					hcpf_srv ${VALGRIND} --tool=memcheck 
					$<TARGET_FILE:test-server>
					-r ${CMAKE_BINARY_DIR}/share/libwebsockets-test-server/
					-s --port ${PORT_HCP_SRV} -d1151)
		add_test(NAME ki_hcpf_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh hcpf_srv ${VALGRIND}
					$<TARGET_FILE_NAME:test-server> --port ${PORT_HCP_SRV})
	else()
		add_test(NAME st_hcpf_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
					hcpf_srv
					$<TARGET_FILE:test-server>
					-r ${CMAKE_BINARY_DIR}/share/libwebsockets-test-server/
					-s --port ${PORT_HCP_SRV} )
		add_test(NAME ki_hcpf_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh hcpf_srv
					$<TARGET_FILE_NAME:test-server> --port ${PORT_HCP_SRV})
	endif()
endif()

	set_tests_properties(st_hcpf_srv PROPERTIES
					     WORKING_DIRECTORY .
					     FIXTURES_SETUP hcpf_srv
					     TIMEOUT 800)
	set_tests_properties(ki_hcpf_srv PROPERTIES
					     FIXTURES_CLEANUP hcpf_srv)

	add_test(NAME http-client-post-form COMMAND
		lws-minimal-http-client-post-form -l https://localhost:${PORT_HCP_SRV}/formtest)
	add_test(NAME http-client-post-form-m COMMAND
		lws-minimal-http-client-post-form -l -m https://localhost:${PORT_HCP_SRV}/formtest)
	add_test(NAME http-client-post-form-h1 COMMAND
		lws-minimal-http-client-post-form -l --h1 https://localhost:${PORT_HCP_SRV}/formtest)
	add_test(NAME http-client-post-form-m-h1 COMMAND
		lws-minimal-http-client-post-form -l -m --h1 https://localhost:${PORT_HCP_SRV}/formtest)
	set_tests_properties(http-client-post-form
			     http-client-post-form-m
			     http-client-post-form-h1
			     http-client-post-form-m-h1
			     PROPERTIES
			     FIXTURES_REQUIRED "hcpf_srv"
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-client/minimal-http-client-post-form
			     TIMEOUT 20)
endif()


	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
