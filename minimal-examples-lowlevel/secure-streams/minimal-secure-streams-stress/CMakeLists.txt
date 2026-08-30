project(lws-minimal-secure-streams-stress C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-secure-streams-stress)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITHOUT_CLIENT 0 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(LWS_WITH_SYS_STATE 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(USE_WOLFSSL 0 requirements)

if (NOT WIN32)
if (requirements)
	add_executable(${SAMP} minimal-secure-streams.c)

	find_program(VALGRIND "valgrind")

	#
	# Local-server variant: runs against a local
	# lws-minimal-http-server-httpbin over TLS, so it does not need
	# any external network egress.
	#

	if (LWS_WITH_SERVER)
		lws_get_free_port(PORT_SS_SRV_TLS)

		configure_file(policy-local.json.in policy-local.json @ONLY)

		add_test(NAME st_ss_hbin
			COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				ss_hbin $<TARGET_FILE:lws-minimal-http-server-httpbin>
				-s -p ${PORT_SS_SRV_TLS})
		add_test(NAME ki_ss_hbin
			COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				ss_hbin $<TARGET_FILE_NAME:lws-minimal-http-server-httpbin>
				-p ${PORT_SS_SRV_TLS})
		set_tests_properties(st_ss_hbin PROPERTIES
				WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-tls
				FIXTURES_SETUP ss_hbin
				TIMEOUT 800
				ENVIRONMENT "SAI_LIST_PORT=${PORT_SS_SRV_TLS}")
		set_tests_properties(ki_ss_hbin PROPERTIES FIXTURES_CLEANUP ss_hbin)

		add_test(NAME ssstress-local
			COMMAND lws-minimal-secure-streams-stress
				--policy ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json
				--cpd-bypass
				-c 2 --budget 3 --timeout_ms 50000)
		set_tests_properties(ssstress-local PROPERTIES
				WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/secure-streams/minimal-secure-streams-stress
				FIXTURES_REQUIRED "ss_hbin"
				TIMEOUT 300)
	endif()

	#
	# Local-proxy variant: the proxy uses the local policy and the local
	# httpbin peer, so this needs no external network egress either.
	#

	if (HAS_LWS_WITH_SECURE_STREAMS_PROXY_API OR LWS_WITH_SECURE_STREAMS_PROXY_API)

		if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
			# uds abstract namespace for linux
			set(CTEST_LOCAL_SOCKET_PATH "@ctest-sspstress-local-$ENV{SAI_PROJECT}-$ENV{SAI_OVN}")
		else()
			# filesystem socket for others
			if (DEFINED ENV{SAI_OVN})
				string(SUBSTRING "$ENV{SAI_OVN}" 32 16 SHORT_HASH)
			else()
				set(SHORT_HASH "0")
			endif()
			set(CTEST_LOCAL_SOCKET_PATH "/tmp/ctest-sspstress-local-$ENV{SAI_PROJECT}-${SHORT_HASH}")
		endif()

		add_test(NAME st_sstress_proxy_local COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
			sstress_proxy_local $<TARGET_FILE:lws-minimal-secure-streams-proxy>
			-i ${CTEST_LOCAL_SOCKET_PATH}
			-c ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json)
		set_tests_properties(st_sstress_proxy_local PROPERTIES
			WORKING_DIRECTORY .
			FIXTURES_SETUP sstress_proxy_local
			FIXTURES_REQUIRED "ss_hbin"
			TIMEOUT 800)

		add_test(NAME ki_sstress_proxy_local COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
			sstress_proxy_local $<TARGET_FILE:lws-minimal-secure-streams-proxy>
			-i ${CTEST_LOCAL_SOCKET_PATH}
			-c ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json)
		set_tests_properties(ki_sstress_proxy_local PROPERTIES FIXTURES_CLEANUP sstress_proxy_local)

		add_test(NAME sspc-minimalstress-local COMMAND
			lws-minimal-secure-streams-stress-client
			-i +${CTEST_LOCAL_SOCKET_PATH} -c 2 --budget 3 --timeout_ms 50000)
		set_tests_properties(sspc-minimalstress-local PROPERTIES
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/secure-streams/minimal-secure-streams-stress
			FIXTURES_REQUIRED "sstress_proxy_local;ss_hbin"
			TIMEOUT 140)

	endif()

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

endif()
endif()
