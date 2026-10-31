project(lws-api-test-http-strict-host C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-http-strict-host)
set(SRCS main.c)

#
# A vhost with LWS_SERVER_OPTION_VHOST_UPG_STRICT_HOST_CHECK only upgrades a
# connection whose Host (or h2 / h3 :authority) is exactly its name and port
# (G-492), and a wrong one doesn't crash it (G-686)
#
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	# the ws over h2 / h3 cases need a TLS vhost
	set(SHC_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	add_test(NAME api-test-http-strict-host COMMAND lws-api-test-http-strict-host
		 --server ${LWS_CTEST_SERVER_RESOLVE}
		 --cert ${SHC_CERTS}/localhost-100y.cert
		 --key ${SHC_CERTS}/localhost-100y.key)
	set_tests_properties(api-test-http-strict-host PROPERTIES TIMEOUT 120)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
