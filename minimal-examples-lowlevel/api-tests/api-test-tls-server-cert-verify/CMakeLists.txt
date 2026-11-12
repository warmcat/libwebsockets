project(lws-api-test-tls-server-cert-verify C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-tls-server-cert-verify)
set(SRCS main.c)

#
# A tls server and client vhosts in one process: the clients act on the
# server's cert in LWS_CALLBACK_PERFORM_SERVER_CERT_VERIFICATION.  The test
# is for the mbedTLS backend, where lws can only make the callback with
# mbedtls_ssl_set_verify(), and hashes the cert's public key with genhash
#
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(LWS_WITH_MBEDTLS 1 requirements)
require_lws_config(LWS_HAVE_mbedtls_ssl_set_verify 1 requirements)
require_lws_config(LWS_WITH_GENCRYPTO 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	lws_get_free_port(PORT_TLS_SERVER_CERT_VERIFY)

	add_test(NAME api-test-tls-server-cert-verify
		 COMMAND lws-api-test-tls-server-cert-verify
			 -p ${PORT_TLS_SERVER_CERT_VERIFY}
			 -s ${LWS_CTEST_SERVER_RESOLVE}
			 --certs ${CMAKE_CURRENT_SOURCE_DIR})
	set_tests_properties(api-test-tls-server-cert-verify PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
