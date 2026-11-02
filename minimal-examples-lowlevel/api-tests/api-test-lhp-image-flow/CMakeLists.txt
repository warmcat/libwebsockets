project(lws-api-test-lhp-image-flow C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-lhp-image-flow)
set(SRCS main.c)

#
# A tls server vhost and lws_lhp_ss_browse() in one process: the page and its
# images over h2 and h3, as the build has them, each rendered once, and
# retained and rendered twice
#
set(requirements 1)
require_lws_config(LWS_WITH_LHP 1 requirements)
require_lws_config(LWS_WITH_UPNG 1 requirements)
require_lws_config(LWS_WITH_JPEG 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(LWS_WITH_FILE_OPS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)

set(IF_H2 1)
require_lws_config(LWS_ROLE_H2 1 IF_H2)
set(IF_H3 1)
require_lws_config(LWS_ROLE_H3 1 IF_H3)

if (requirements AND NOT WIN32)
	add_executable(${SAMP} ${SRCS})

	set(IF_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ss-redirect)

	set(IF_ALPNS)
	if (IF_H2)
		list(APPEND IF_ALPNS h2)
	endif()
	if (IF_H3)
		list(APPEND IF_ALPNS h3)
	endif()

	foreach(IF_ALPN ${IF_ALPNS})
		foreach(IF_MODE once retained)
			set(IF_NAME api-test-lhp-image-flow-${IF_ALPN}-${IF_MODE})
			lws_get_free_port(PORT_IF_${IF_ALPN}_${IF_MODE})
			set(IF_ARGS)
			if (IF_MODE STREQUAL "retained")
				set(IF_ARGS --retained)
			endif()

			add_test(NAME ${IF_NAME}
				 COMMAND lws-api-test-lhp-image-flow
					 --alpn ${IF_ALPN} ${IF_ARGS}
					 -p ${PORT_IF_${IF_ALPN}_${IF_MODE}}
					 --src ${CMAKE_SOURCE_DIR}
					 --cert ${IF_CERTS}/ss-redirect-100y.cert
					 --key ${IF_CERTS}/ss-redirect-100y.key)
			set_tests_properties(${IF_NAME} PROPERTIES TIMEOUT 40)
		endforeach()
	endforeach()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
