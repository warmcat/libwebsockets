project(lws-api-test-cert-dist C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-cert-dist)
set(SRCS main.c)

#
# The cert-dist server and client plugins, and what they need, both ends of
# an mTLS ws link, and the lejp-conf parser that brings them up from JSON
#
set(requirements 1)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(LWS_WITH_STUB 1 requirements)
require_lws_config(LWS_WITH_SPAWN 1 requirements)
require_lws_config(LWS_WITH_DIR 1 requirements)
require_lws_config(LWS_WITH_LEJP_CONF 1 requirements)
require_lws_config(LWS_WITH_PLUGINS_API 1 requirements)

if (requirements AND NOT WIN32)

	#
	# We compose both plugins into ourselves, whatever lws was built with,
	# so this is the plugin code under test
	#
	list(APPEND SRCS compose-cert-dist-server.c compose-cert-dist-client.c)

	add_executable(${SAMP} ${SRCS})
	target_include_directories(${SAMP} PRIVATE ${CMAKE_SOURCE_DIR}/plugins)

	lws_get_free_port(PORT_CERT_DIST)

	add_test(NAME api-test-cert-dist
		 COMMAND lws-api-test-cert-dist
			 -p ${PORT_CERT_DIST}
			 -s ${LWS_CTEST_SERVER_RESOLVE}
			 --certs ${CMAKE_CURRENT_SOURCE_DIR})
	set_tests_properties(api-test-cert-dist PROPERTIES TIMEOUT 90)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
