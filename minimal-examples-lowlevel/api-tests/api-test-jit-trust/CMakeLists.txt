project(lws-api-test-jit-trust C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)
include(CTest)

set(SAMP lws-api-test-jit-trust)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(LWS_WITH_TLS_JIT_TRUST 1 requirements)

#
# JIT Trust needs the tls backend to tell it the key ids of the peer's certs:
# schannel doesn't, and mbedtls only can with mbedtls_ssl_set_verify()
#
require_lws_config(LWS_WITH_SCHANNEL 0 requirements)
set(has_mbedtls 1)
require_lws_config(LWS_WITH_MBEDTLS 1 has_mbedtls)
if (has_mbedtls)
	require_lws_config(LWS_HAVE_mbedtls_ssl_set_verify 1 requirements)
endif()

if (requirements)

	add_executable(${SAMP} ${SRCS})

	lws_get_free_port(PORT_JIT_TRUST)
	lws_get_free_port(PORT_JIT_UNTRUSTED)
	lws_get_free_port(PORT_JIT_APPCA)

	add_test(NAME api-test-jit-trust
		 COMMAND lws-api-test-jit-trust -p ${PORT_JIT_TRUST}
			 --untrusted-port ${PORT_JIT_UNTRUSTED}
			 --appca-port ${PORT_JIT_APPCA})
	set_tests_properties(api-test-jit-trust PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 120)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
