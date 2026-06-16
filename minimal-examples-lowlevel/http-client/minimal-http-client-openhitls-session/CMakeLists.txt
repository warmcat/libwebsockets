project(lws-minimal-http-client-session C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-client-session)
set(SRCS minimal-http-client-openhitls-session.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(LWS_WITH_OPENHITLS 1 requirements)
require_lws_config(LWS_WITH_TLS_SESSIONS 1 requirements)
require_lws_config(LWS_WITH_FILE_OPS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	set(PORT_OHSESS_SRV "7730")
	if ("$ENV{SAI_INSTANCE_IDX}")
		math(EXPR PORT_OHSESS_SRV "7731 + $ENV{SAI_INSTANCE_IDX}")
	endif()

	if (NOT WIN32 AND LWS_WITH_SERVER)

		# HTTPS session reuse test: uses the local minimal TLS server fixture
		add_test(NAME st_sess_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				sess_srv
				$<TARGET_FILE:lws-minimal-http-server-tls>
				--port ${PORT_OHSESS_SRV})
		add_test(NAME ki_sess_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				sess_srv $<TARGET_FILE_NAME:lws-minimal-http-server-tls>
				--port ${PORT_OHSESS_SRV})

		set_tests_properties(st_sess_srv PROPERTIES
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-tls
			FIXTURES_SETUP sess_srv
			TIMEOUT 800)
		if (APPLE)
			set_property(TEST st_sess_srv PROPERTY ENVIRONMENT
				"SAI_LIST_PORT=${PORT_OHSESS_SRV};VENDOR=apple")
		else()
			set_property(TEST st_sess_srv PROPERTY ENVIRONMENT
				"SAI_LIST_PORT=${PORT_OHSESS_SRV};VENDOR=$ENV{VENDOR}")
		endif()
		set_tests_properties(ki_sess_srv PROPERTIES
			FIXTURES_CLEANUP sess_srv)

		add_test(NAME http-client-session-https COMMAND
			lws-minimal-http-client-session
				--port ${PORT_OHSESS_SRV})
		set_tests_properties(http-client-session-https PROPERTIES
			FIXTURES_REQUIRED "sess_srv"
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
			TIMEOUT 30)

		# WSS session reuse test: uses embedded WS echo server
		set(PORT_OHSESS_WSS "7740")
		if ("$ENV{SAI_INSTANCE_IDX}")
			math(EXPR PORT_OHSESS_WSS "7741 + $ENV{SAI_INSTANCE_IDX}")
		endif()

		add_test(NAME http-client-session-wss COMMAND
			lws-minimal-http-client-session
				--ws --port ${PORT_OHSESS_WSS})
		set_tests_properties(http-client-session-wss PROPERTIES
			WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
			TIMEOUT 30)
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
