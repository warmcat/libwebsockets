project(lws-api-test-h3-authority C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-h3-authority)
set(SRCS main.c)

#
# h3 server vhosts sharing one listener, and a unix socket vhost, with the
# h3 client (or, for the Host vs :authority cases, also an h2 client) in the
# same process
#
set(requirements 1)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_UNIX_SOCK 1 requirements)
# the client dials a literal 127.0.0.1, so that it sends no SNI
require_lws_config(LWS_WITH_IPV4 1 requirements)

set(H3A_H2 1)
require_lws_config(LWS_ROLE_H2 1 H3A_H2)

if (requirements AND NOT WIN32)
	add_executable(${SAMP} ${SRCS})

	set(H3A_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	foreach(H3A_CASE same-listener unix-socket)
		lws_get_free_port(PORT_H3A_${H3A_CASE})

		add_test(NAME api-test-h3-authority-${H3A_CASE}
			 COMMAND lws-api-test-h3-authority
				 --case ${H3A_CASE}
				 -p ${PORT_H3A_${H3A_CASE}}
				 --cert ${H3A_CERTS}/localhost-100y.cert
				 --key ${H3A_CERTS}/localhost-100y.key)
		set_tests_properties(api-test-h3-authority-${H3A_CASE} PROPERTIES
				     TIMEOUT 30)
	endforeach()

	#
	# A Host header disagreeing with :authority is refused (G-148), on h3
	# and, where the build has it, h2
	#
	set(H3A_ALPNS h3)
	if (H3A_H2)
		list(APPEND H3A_ALPNS h2)
	endif()

	foreach(H3A_ALPN ${H3A_ALPNS})
		foreach(H3A_CASE host-same host-default-port host-case
				 host-v6 host-name host-port)
			set(H3A_T ${H3A_CASE}-${H3A_ALPN})
			lws_get_free_port(PORT_H3A_${H3A_T})

			add_test(NAME api-test-h3-authority-${H3A_T}
				 COMMAND lws-api-test-h3-authority
					 --case ${H3A_CASE}
					 --alpn ${H3A_ALPN}
					 -p ${PORT_H3A_${H3A_T}}
					 --cert ${H3A_CERTS}/localhost-100y.cert
					 --key ${H3A_CERTS}/localhost-100y.key)
			set_tests_properties(api-test-h3-authority-${H3A_T}
					     PROPERTIES TIMEOUT 30)
		endforeach()
	endforeach()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
