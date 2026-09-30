project(lws-api-test-ss-server-accept C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-ss-server-accept)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(LWS_WITH_SYS_SMD 1 requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_H2 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(USE_WOLFSSL 0 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	lws_get_free_port(PORT_SS_SRV_ACCEPT)
	lws_get_free_port(PORT_SS_SRV_ACCEPT_PLAIN)
	lws_get_free_port(PORT_SS_SRV_ACCEPT_RAW)

	# the policy names the server port, so it's generated per-build
	configure_file(policy.json.in policy.json @ONLY)

	add_test(NAME api-test-ss-server-accept
		 COMMAND lws-api-test-ss-server-accept
			 -c ${CMAKE_CURRENT_BINARY_DIR}/policy.json
			 -p ${PORT_SS_SRV_ACCEPT}
			 --port-plain ${PORT_SS_SRV_ACCEPT_PLAIN}
			 --port-raw ${PORT_SS_SRV_ACCEPT_RAW}
			 --server ${LWS_CTEST_SERVER_RESOLVE})
	set_tests_properties(api-test-ss-server-accept
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 60)
endif()
