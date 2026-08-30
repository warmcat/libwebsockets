project(lws-minimal-secure-streams-perf C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-secure-streams-perf)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITHOUT_CLIENT 0 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(LWS_WITH_SYS_STATE 1 requirements)
require_lws_config(USE_WOLFSSL 0 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)

if (requirements)
	add_executable(${SAMP} minimal-secure-streams.c)

	find_program(VALGRIND "valgrind")

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	CHECK_C_SOURCE_COMPILES("#include <libwebsockets.h>\nint main(void) {\ni#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)\n return 0;\n #else\n fail\n #endif\n return 0;\n}\n" HAS_LWS_WITH_SECURE_STREAMS_PROXY_API)

	if (HAS_LWS_WITH_SECURE_STREAMS_PROXY_API OR LWS_WITH_SECURE_STREAMS_PROXY_API)
		add_compile_options(-DLWS_SS_USE_SSPC)

		add_executable(${SAMP}-client minimal-secure-streams.c)
		if (websockets_shared)
			target_link_libraries(${SAMP}-client websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
			add_dependencies(${SAMP}-client websockets_shared)
		else()
			target_link_libraries(${SAMP}-client websockets ${LIBWEBSOCKETS_DEP_LIBS})
		endif()
	endif()


	#
	# Local-server variant: runs against a local lws-minimal-http-server-httpbin
	# over TLS, so it does not need any external network egress.
	#

	if (NOT WIN32 AND LWS_WITH_SERVER)
		lws_get_free_port(PORT_PERF_HBIN_TLS)

		configure_file(policy-local.json.in policy-local.json @ONLY)

		add_test(NAME st_perf_hbin
			COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				perf_hbin $<TARGET_FILE:lws-minimal-http-server-httpbin>
								-s -p ${PORT_PERF_HBIN_TLS})
		add_test(NAME ki_perf_hbin
			COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				perf_hbin $<TARGET_FILE_NAME:lws-minimal-http-server-httpbin>
				-p ${PORT_PERF_HBIN_TLS})
		set_tests_properties(st_perf_hbin PROPERTIES
				WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-tls
				FIXTURES_SETUP perf_hbin
				TIMEOUT 800
				ENVIRONMENT "SAI_LIST_PORT=${PORT_PERF_HBIN_TLS}")
		set_tests_properties(ki_perf_hbin PROPERTIES FIXTURES_CLEANUP perf_hbin)

					endif()


	#
	# Local-proxy variant: the proxy uses the local policy and the local
	# peer instead of fetching a policy from warmcat.com, so this needs no
	# external network egress.  Deliberately outside the
	#

	if (NOT WIN32 AND (HAS_LWS_WITH_SECURE_STREAMS_PROXY_API OR
			   LWS_WITH_SECURE_STREAMS_PROXY_API) AND LWS_WITH_SERVER)

		if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
			# uds abstract namespace for linux
			set(CTEST_LOCAL_SOCKET_PATH "@ctest-sspperf-local-$ENV{SAI_PROJECT}-$ENV{SAI_OVN}")
		else()
			# filesystem socket for others
			if (DEFINED ENV{SAI_OVN})
				string(SUBSTRING "$ENV{SAI_OVN}" 32 16 SHORT_HASH)
			else()
				set(SHORT_HASH "0")
			endif()
			set(CTEST_LOCAL_SOCKET_PATH "/tmp/ctest-sspperf-local-$ENV{SAI_PROJECT}-${SHORT_HASH}")
		endif()

		configure_file(policy-local.json.in policy-local.json @ONLY)

		add_test(NAME st_perf_proxy_local COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
			perf_proxy_local $<TARGET_FILE:lws-minimal-secure-streams-proxy>
			-i ${CTEST_LOCAL_SOCKET_PATH}
			-c ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json)
		set_tests_properties(st_perf_proxy_local PROPERTIES
			WORKING_DIRECTORY .
			FIXTURES_SETUP perf_proxy_local
			FIXTURES_REQUIRED "perf_hbin"
			TIMEOUT 800)

		add_test(NAME ki_perf_proxy_local COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
			perf_proxy_local $<TARGET_FILE:lws-minimal-secure-streams-proxy>
			-i ${CTEST_LOCAL_SOCKET_PATH}
			-c ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json)
		set_tests_properties(ki_perf_proxy_local PROPERTIES FIXTURES_CLEANUP perf_proxy_local)

					endif()

endif()
