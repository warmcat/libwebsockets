project(lws-api-test-http-attack C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-http-attack)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_FILE_OPS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	#
	# One test per transport, so ctest -j runs them side by side and a
	# failure names its transport
	#
	set(ATK_XPORTS h1)
	if (LWS_WITH_HTTP2)
		list(APPEND ATK_XPORTS h2)
	endif()
	if (LWS_WITH_HTTP3)
		list(APPEND ATK_XPORTS h3)
	endif()

	foreach(ATK_XPORT ${ATK_XPORTS})
		lws_get_free_port(PORT_ATK_${ATK_XPORT})

		add_test(NAME api-test-http-attack-${ATK_XPORT}
			 COMMAND lws-api-test-http-attack
				 --server ${LWS_CTEST_SERVER_RESOLVE}
				 --transport ${ATK_XPORT}
				 -p ${PORT_ATK_${ATK_XPORT}}
				 --h2-port ${PORT_ATK_${ATK_XPORT}}
				 --h3-port ${PORT_ATK_${ATK_XPORT}})
		set_tests_properties(api-test-http-attack-${ATK_XPORT} PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
				     TIMEOUT 300)
	endforeach()
endif()
