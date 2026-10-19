project(lws-api-test-vhost-listener-scope C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-vhost-listener-scope)
set(SRCS main.c)

#
# Server vhosts on the same port on 127.0.0.1 and 127.0.0.2, and the client,
# in one process: a name the client sends may only select a vhost on the
# listener it arrived on (G-329, G-007); a connection moved onto another vhost
# keeps no protocol of the vhost it left (G-330).
#
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)

set(VLS_TLS 1)
require_lws_config(LWS_WITH_TLS 1 VLS_TLS)
set(VLS_H2 1)
require_lws_config(LWS_ROLE_H2 1 VLS_H2)
set(VLS_H3 1)
require_lws_config(LWS_ROLE_H3 1 VLS_H3)
set(VLS_PT 1)
require_lws_config(LWS_WITH_TLS_PASSTHROUGH 1 VLS_PT)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	set(VLS_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	# each test is "case" or "case/alpn"
	set(VLS_TESTS host-other host-same)

	if (VLS_TLS)
		set(VLS_ALPNS http/1.1)
		if (VLS_H2)
			list(APPEND VLS_ALPNS h2)
		endif()
		if (VLS_H3)
			list(APPEND VLS_ALPNS h3)
		endif()
		foreach(VLS_ALPN ${VLS_ALPNS})
			foreach(VLS_CASE sni-other sni-same sni-refused)
				list(APPEND VLS_TESTS ${VLS_CASE}/${VLS_ALPN})
			endforeach()
		endforeach()

		if (VLS_PT)
			set(VLS_PT_ALPNS http/1.1)
			if (VLS_H3)
				list(APPEND VLS_PT_ALPNS h3)
			endif()
			foreach(VLS_ALPN ${VLS_PT_ALPNS})
				foreach(VLS_CASE pt-same pt-other)
					list(APPEND VLS_TESTS ${VLS_CASE}/${VLS_ALPN})
				endforeach()
			endforeach()
		endif()

		list(APPEND VLS_TESTS proto-moved proto-keepalive)
	endif()

	foreach(VLS_T ${VLS_TESTS})
		string(REPLACE "/" ";" VLS_PARTS ${VLS_T})
		list(GET VLS_PARTS 0 VLS_CASE)
		set(VLS_ARGS --case ${VLS_CASE})
		set(VLS_NAME ${VLS_CASE})
		list(LENGTH VLS_PARTS VLS_N)
		if (VLS_N GREATER 1)
			list(GET VLS_PARTS 1 VLS_ALPN)
			list(APPEND VLS_ARGS --alpn ${VLS_ALPN})
			string(REPLACE "/" "" VLS_ALPN_NAME ${VLS_ALPN})
			set(VLS_NAME ${VLS_CASE}-${VLS_ALPN_NAME})
		endif()

		# the front's port, and the passthrough backend's after it
		lws_get_free_ports(PORT_VLS_${VLS_NAME} 2)

		add_test(NAME api-test-vhost-listener-scope-${VLS_NAME}
			 COMMAND lws-api-test-vhost-listener-scope
				 ${VLS_ARGS}
				 -p ${PORT_VLS_${VLS_NAME}}
				 --cert ${VLS_CERTS}/localhost-100y.cert
				 --key ${VLS_CERTS}/localhost-100y.key)
		# 127.0.0.2 can't be listened on everywhere: skipped there
		set_tests_properties(api-test-vhost-listener-scope-${VLS_NAME}
				     PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77)
	endforeach()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
