project(lws-api-test-mtls C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-mtls)
set(SRCS main.c)

#
# An mTLS server vhost and clients presenting different client certs, both
# ends in the one process
#
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	#
	# One test per transport, so ctest -j runs them side by side and a
	# failure names its transport
	#
	set(MTLS_XPORTS h1)
	if (LWS_WITH_HTTP2)
		list(APPEND MTLS_XPORTS h2)
	endif()
	if (LWS_WITH_HTTP3)
		list(APPEND MTLS_XPORTS h3)
	endif()

	foreach(MTLS_XPORT ${MTLS_XPORTS})
		lws_get_free_port(PORT_MTLS_${MTLS_XPORT})

		add_test(NAME api-test-mtls-${MTLS_XPORT}
			 COMMAND lws-api-test-mtls
				 --transport ${MTLS_XPORT}
				 -p ${PORT_MTLS_${MTLS_XPORT}}
				 -s ${LWS_CTEST_SERVER_RESOLVE}
				 --certs ${CMAKE_CURRENT_SOURCE_DIR})
		set_tests_properties(api-test-mtls-${MTLS_XPORT} PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
				     TIMEOUT 90)
	endforeach()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
