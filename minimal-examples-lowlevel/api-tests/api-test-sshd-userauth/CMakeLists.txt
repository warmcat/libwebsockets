project(lws-api-test-sshd-userauth C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-sshd-userauth)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(LWS_WITH_GENCRYPTO 1 requirements)
require_lws_config(LWS_WITH_MBEDTLS 0 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	# the test includes the sshd-base plugin sources statically, the
	# same way test-sshd does
	target_include_directories(${SAMP} PRIVATE
				     "${CMAKE_SOURCE_DIR}/plugins/protocol_lws_ssh_base/include")

	lws_get_free_port(PORT_SSHD_USERAUTH)

	add_test(NAME api-test-sshd-userauth
		 COMMAND lws-api-test-sshd-userauth -p ${PORT_SSHD_USERAUTH})
	set_tests_properties(api-test-sshd-userauth PROPERTIES
			     TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
