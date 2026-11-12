project(lws-api-test-tls-client-trust C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-tls-client-trust)
set(SRCS main.c)

#
# A tls server and client vhosts with different trust in one process: trust
# added to one client vhost must not reach another created the same way
#
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	lws_get_free_port(PORT_TLS_CLIENT_TRUST)

	add_test(NAME api-test-tls-client-trust
		 COMMAND lws-api-test-tls-client-trust
			 -p ${PORT_TLS_CLIENT_TRUST}
			 -s ${LWS_CTEST_SERVER_RESOLVE}
			 --certs ${CMAKE_CURRENT_SOURCE_DIR})
	set_tests_properties(api-test-tls-client-trust PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 60)

	#
	# The OS trust store, with SSL_CERT_FILE standing in for the OS bundle:
	# only the OpenSSL family loads its default verify paths from it.  A
	# result var other than "requirements" is only the last check's, so
	# each is checked on its own
	#
	require_lws_config(LWS_SSL_CLIENT_USE_OS_CA_CERTS 1 os_trust)
	foreach(_ctt_backend LWS_WITH_MBEDTLS LWS_WITH_GNUTLS LWS_WITH_SCHANNEL
			     LWS_WITH_BEARSSL LWS_WITH_OPENHITLS LWS_WITH_WOLFSSL)
		require_lws_config(${_ctt_backend} 0 _ctt_met)
		if (NOT _ctt_met)
			set(os_trust 0)
		endif()
	endforeach()

	if (os_trust)
		lws_get_free_port(PORT_TLS_CLIENT_TRUST_OS)

		add_test(NAME api-test-tls-client-trust-os
			 COMMAND lws-api-test-tls-client-trust --os-trust
				 -p ${PORT_TLS_CLIENT_TRUST_OS}
				 -s ${LWS_CTEST_SERVER_RESOLVE}
				 --certs ${CMAKE_CURRENT_SOURCE_DIR})
		set_tests_properties(api-test-tls-client-trust-os PROPERTIES
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			ENVIRONMENT "SSL_CERT_FILE=${CMAKE_CURRENT_SOURCE_DIR}/localhost-100y.cert"
			TIMEOUT 60)
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
