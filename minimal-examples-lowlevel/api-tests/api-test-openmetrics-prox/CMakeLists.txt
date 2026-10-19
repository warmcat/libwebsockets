project(lws-api-test-openmetrics-prox C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-openmetrics-prox)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_SYS_METRICS 1 requirements)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	# the openmetrics plugin, built in
	target_include_directories(${SAMP} PRIVATE
		${CMAKE_SOURCE_DIR}/plugins/protocol_lws_openmetrics_export)

	# the server listens on a port the kernel picks, so no port to allocate
	add_test(NAME api-test-openmetrics-prox
		 COMMAND lws-api-test-openmetrics-prox
			 --server ${LWS_CTEST_SERVER_RESOLVE})
	set_tests_properties(api-test-openmetrics-prox PROPERTIES TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
