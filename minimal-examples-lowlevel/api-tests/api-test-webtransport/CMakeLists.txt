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

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
