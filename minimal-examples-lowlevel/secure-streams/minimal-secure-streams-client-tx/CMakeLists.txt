project(lws-minimal-secure-streams-client-tx C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-secure-streams-client-tx)
set(SRCS minimal-secure-streams-client-tx.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITHOUT_CLIENT 0 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_PROXY_API 1 requirements)
require_lws_config(LWS_WITH_SYS_STATE 1 requirements)
require_lws_config(USE_WOLFSSL 0 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	add_compile_options(-DLWS_SS_USE_SSPC)
	
	find_program(VALGRIND "valgrind")

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	#
	# Local-server variant: "spam" is a nailed-up ws stream, so this runs the
	# lws test-server over TLS as a local ws peer (lws-mirror-protocol), and
	# the proxy with a local policy, so it does not need any external network
	# egress.  test-apps is added after the examples, so its target can't be
	# looked for here: these are the options it builds test-server under.
	#

	set(TX_WS_SRV 0)
	if (NOT WIN32 AND LWS_WITH_SERVER AND LWS_WITH_FILE_OPS AND
	    NOT LWS_WITHOUT_TESTAPPS AND NOT LWS_WITHOUT_TEST_SERVER)
		set(TX_WS_SRV 1)
	endif()

	if (TX_WS_SRV)

		lws_get_free_port(PORT_TX_WS_SRV_TLS)

		set(LOCAL_CERT_DIR ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-tls)

		add_test(NAME st_tx_ws_srv
			COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				tx_ws_srv $<TARGET_FILE:test-server>
				-s -p ${PORT_TX_WS_SRV_TLS}
				-C ${LOCAL_CERT_DIR}/localhost-100y.cert
				-K ${LOCAL_CERT_DIR}/localhost-100y.key
				-r ${CMAKE_BINARY_DIR}/share/libwebsockets-test-server)
		add_test(NAME ki_tx_ws_srv
			COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				tx_ws_srv $<TARGET_FILE_NAME:test-server>
				-p ${PORT_TX_WS_SRV_TLS})
		set_tests_properties(st_tx_ws_srv PROPERTIES
				WORKING_DIRECTORY .
				FIXTURES_SETUP tx_ws_srv
				TIMEOUT 800
				ENVIRONMENT "SAI_LIST_PORT=${PORT_TX_WS_SRV_TLS}")
		set_tests_properties(ki_tx_ws_srv PROPERTIES FIXTURES_CLEANUP tx_ws_srv)

	endif()


	#
	# Local-proxy variant: the proxy uses the local policy and the local
	# ws peer instead of fetching a policy from warmcat.com, so this needs no
	# external network egress.
	#

	if (TX_WS_SRV AND
	    (HAS_LWS_WITH_SECURE_STREAMS_PROXY_API OR LWS_WITH_SECURE_STREAMS_PROXY_API))

		if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
			# uds abstract namespace for linux
			set(CTEST_LOCAL_SOCKET_PATH "@ctest-ssptx-local-$ENV{SAI_PROJECT}-$ENV{SAI_OVN}")
		else()
			# filesystem socket for others
			if (DEFINED ENV{SAI_OVN})
				string(SUBSTRING "$ENV{SAI_OVN}" 32 16 SHORT_HASH)
			else()
				set(SHORT_HASH "0")
			endif()
			set(CTEST_LOCAL_SOCKET_PATH "/tmp/ctest-ssptx-local-$ENV{SAI_PROJECT}-${SHORT_HASH}")
		endif()

		configure_file(policy-local.json.in policy-local.json @ONLY)

		add_test(NAME st_tx_proxy_local COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
			tx_proxy_local $<TARGET_FILE:lws-minimal-secure-streams-proxy>
			-i ${CTEST_LOCAL_SOCKET_PATH}
			-c ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json)
		set_tests_properties(st_tx_proxy_local PROPERTIES
			WORKING_DIRECTORY .
			FIXTURES_SETUP tx_proxy_local
			FIXTURES_REQUIRED "tx_ws_srv"
			TIMEOUT 800)

		add_test(NAME ki_tx_proxy_local COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
			tx_proxy_local $<TARGET_FILE:lws-minimal-secure-streams-proxy>
			-i ${CTEST_LOCAL_SOCKET_PATH}
			-c ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json)
		set_tests_properties(ki_tx_proxy_local PROPERTIES FIXTURES_CLEANUP tx_proxy_local)

		add_test(NAME sspc-minimaltx-local COMMAND lws-minimal-secure-streams-client-tx
			 -i +${CTEST_LOCAL_SOCKET_PATH})
		set_tests_properties(sspc-minimaltx-local PROPERTIES
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/secure-streams/minimal-secure-streams-client-tx
			FIXTURES_REQUIRED "tx_proxy_local;tx_ws_srv"
			TIMEOUT 40)

	endif()

endif()
