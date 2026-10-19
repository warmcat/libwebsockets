project(lws-api-test-webtransport C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)
include(CTest)

set(SAMP lws-api-test-webtransport)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_WT 1 requirements)
require_lws_config(LWS_WITH_HTTP3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
set(has_fault_injection 1)
require_lws_config(LWS_WITH_SYS_FAULT_INJECTION 1 has_fault_injection)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	lws_get_free_port(PORT_WT_WT)
	lws_get_free_port(PORT_WT_NOWT)

	add_test(NAME api-test-webtransport
		 COMMAND lws-api-test-webtransport
			 -p ${PORT_WT_WT} --nowt-port ${PORT_WT_NOWT})
	set_tests_properties(api-test-webtransport PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 60)

	#
	# The same with both ends advertising initial_max_stream_data_* (and
	# initial_max_data) of 2^31, 2^32 and 2^62 - 1: the streams the client
	# and server open on their sessions must still be able to send
	#
	if (has_fault_injection)
		foreach(wt_v 2147483648 4294967296 4611686018427387903)
			math(EXPR wt_v1 "${wt_v} + 1")
			lws_get_free_port(PORT_WT_WT_V)
			lws_get_free_port(PORT_WT_NOWT_V)
			add_test(NAME api-test-webtransport-tp-${wt_v}
				 COMMAND lws-api-test-webtransport
					 -p ${PORT_WT_WT_V} --nowt-port ${PORT_WT_NOWT_V}
					 --fault-injection "wsi/quic_tp_window(${wt_v}..${wt_v1})")
			set_tests_properties(api-test-webtransport-tp-${wt_v} PROPERTIES
					     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
					     TIMEOUT 60)
		endforeach()
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
