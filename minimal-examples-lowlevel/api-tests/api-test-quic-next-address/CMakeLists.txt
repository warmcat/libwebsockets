project(lws-api-test-quic-next-address C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-quic-next-address)
set(SRCS main.c)

#
# An h3 server listening on one loopback address only, and an h3 client in
# the same process asking for "localhost", which is both: refused by one of
# them first, the client must move on to the other at once
#
set(requirements 1)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)
require_lws_config(LWS_WITH_IPV6 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	set(QNA_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	#
	# Which of its addresses the client tries first is the platform's
	# choice: with the server on each of them in turn, one of the runs has
	# the client refused first
	#
	foreach(QNA_FAM v6 v4)
		if (QNA_FAM STREQUAL "v6")
			set(QNA_BIND "::1")
		else()
			set(QNA_BIND "127.0.0.1")
		endif()

		lws_get_free_port(PORT_QNA_${QNA_FAM})

		add_test(NAME api-test-quic-next-address-${QNA_FAM}
			 COMMAND lws-api-test-quic-next-address
				 -p ${PORT_QNA_${QNA_FAM}}
				 --bind ${QNA_BIND}
				 --address localhost
				 --cert ${QNA_CERTS}/localhost-100y.cert
				 --key ${QNA_CERTS}/localhost-100y.key)
		# 77: the host has no ipv6 loopback to listen on
		set_tests_properties(api-test-quic-next-address-${QNA_FAM}
				     PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77)
	endforeach()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
