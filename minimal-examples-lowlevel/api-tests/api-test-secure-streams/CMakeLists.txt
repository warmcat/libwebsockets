project(lws-api-test-secure-streams C)
cmake_minimum_required(VERSION 3.10)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(requirements 1)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(LWS_WITH_SYS_STATE 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(USE_WOLFSSL 0 requirements)

if (requirements)

	add_executable(${PROJECT_NAME} main.c)

	#
	# Local-server variant: runs the same test logic against a local
	# lws-minimal-http-server-httpbin over TLS, so it does not need any
	# external network egress.  Suitable for IPv6-only / no-egress CI.
	#

	if (NOT WIN32 AND LWS_WITH_SERVER)
		lws_get_free_port(PORT_ATS_SRV_TLS)

		configure_file(policy-local.json.in policy-local.json @ONLY)

		add_test(NAME st_ats_hbin
			COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				ats_hbin $<TARGET_FILE:lws-minimal-http-server-httpbin>
				-s -p ${PORT_ATS_SRV_TLS})
		add_test(NAME ki_ats_hbin
			COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				ats_hbin $<TARGET_FILE_NAME:lws-minimal-http-server-httpbin>
				-p ${PORT_ATS_SRV_TLS})
		set_tests_properties(st_ats_hbin PROPERTIES
				WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-tls
				FIXTURES_SETUP ats_hbin
				TIMEOUT 800
				ENVIRONMENT "SAI_LIST_PORT=${PORT_ATS_SRV_TLS}")
		set_tests_properties(ki_ats_hbin PROPERTIES FIXTURES_CLEANUP ats_hbin)

		add_test(NAME api-test-secure-streams-local
			COMMAND ${PROJECT_NAME}
				-c ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json)
		set_tests_properties(api-test-secure-streams-local PROPERTIES
				WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-secure-streams
				FIXTURES_REQUIRED "ats_hbin"
				TIMEOUT 90)
	endif()

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME} websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
