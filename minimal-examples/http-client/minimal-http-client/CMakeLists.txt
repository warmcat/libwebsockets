project(lws-minimal-http-client C)
cmake_minimum_required(VERSION 2.8.12)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-client)
set(SRCS minimal-http-client.c)

set(has_h2 1)
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SYS_STATE 1 requirements)

require_lws_config(LWS_ROLE_H2 1 has_h2)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	
	sai_resource(warmcat_conns 1 40 http_client_warmcat)

	if (LWS_CTEST_INTERNET_AVAILABLE)
		set(mytests http-client-warmcat-h1)
		if (has_h2)
			add_test(NAME http-client-warmcat COMMAND lws-minimal-http-client )
			list(APPEND mytests http-client-warmcat)
		endif()
		add_test(NAME http-client-warmcat-h1 COMMAND lws-minimal-http-client  --h1)
		set_tests_properties(${mytests} PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/http-client/minimal-http-client
				     TIMEOUT 20)
				     
    		if (DEFINED ENV{SAI_OVN})
			set_tests_properties(${mytests} PROPERTIES
					     FIXTURES_REQUIRED "res_http_client_warmcat")
		endif()
	
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
