project(lws-api-test-form-post-file C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-form-post-file)
set(SRCS main.c)

#
# The client half here, and lws-minimal-http-server-form-post-file as the
# server under test, so its requirements too
#
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_FILE_OPS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (NOT WIN32)
		lws_get_free_port(PORT_FPF_SRV)

		set(FPF_UPLOADS ${CMAKE_CURRENT_BINARY_DIR}/uploads)
		set(FPF_OUTSIDE ${CMAKE_CURRENT_BINARY_DIR}/outside)
		set(FPF_LIMITS --max-size 8192 --max-files 6)

		# each run starts from nothing: the server refuses names that
		# already exist, and what a run leaves outside must be its own
		add_test(NAME fpf_clean COMMAND ${CMAKE_COMMAND} -E
			 remove_directory ${FPF_UPLOADS})
		add_test(NAME fpf_clean_outside COMMAND ${CMAKE_COMMAND} -E
			 remove_directory ${FPF_OUTSIDE})
		add_test(NAME fpf_mk_outside COMMAND ${CMAKE_COMMAND} -E
			 make_directory ${FPF_OUTSIDE})
		add_test(NAME fpf_clean_escape COMMAND ${CMAKE_COMMAND} -E
			 remove -f ${CMAKE_CURRENT_BINARY_DIR}/escape.txt)
		set_tests_properties(fpf_clean fpf_clean_outside fpf_clean_escape
				     PROPERTIES
				     FIXTURES_SETUP fpf_clean)
		set_tests_properties(fpf_mk_outside PROPERTIES
				     FIXTURES_REQUIRED fpf_clean
				     FIXTURES_SETUP fpf_outside)

		add_test(NAME st_fpf_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
			fpf_srv $<TARGET_FILE:lws-minimal-http-server-form-post-file>
			--port ${PORT_FPF_SRV} --upload-dir ${FPF_UPLOADS}
			${FPF_LIMITS})
		add_test(NAME ki_fpf_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
			fpf_srv
			$<TARGET_FILE_NAME:lws-minimal-http-server-form-post-file>
			--port ${PORT_FPF_SRV})
		set_tests_properties(st_fpf_srv PROPERTIES
			# it serves its pages from ./mount-origin
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-form-post-file
			FIXTURES_REQUIRED fpf_clean
			FIXTURES_SETUP fpf_srv
			TIMEOUT 800
			ENVIRONMENT "SAI_LIST_PORT=${PORT_FPF_SRV}")
		set_tests_properties(ki_fpf_srv PROPERTIES
				     FIXTURES_CLEANUP fpf_srv)

		add_test(NAME api-test-form-post-file COMMAND ${SAMP}
			 --server ${LWS_CTEST_SERVER_RESOLVE}
			 -p ${PORT_FPF_SRV}
			 --upload-dir ${FPF_UPLOADS}
			 --outside-dir ${FPF_OUTSIDE}
			 --max-size 8192)
		set_tests_properties(api-test-form-post-file PROPERTIES
				     FIXTURES_REQUIRED "fpf_srv;fpf_outside"
				     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
				     TIMEOUT 90)
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
