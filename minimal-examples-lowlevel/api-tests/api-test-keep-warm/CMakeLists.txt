project(lws-api-test-keep-warm C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)
include(CTest)

set(SAMP lws-api-test-keep-warm)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	#
	# One test per transport group, so ctest -j runs them side by side
	# and a failure names its transport and has a log of its own
	#
	set(KW_GROUPS h1)
	if (LWS_WITH_TLS)
		list(APPEND KW_GROUPS h1-tls)
	endif()
	if (LWS_WITH_HTTP2)
		list(APPEND KW_GROUPS h2c)
		if (LWS_WITH_TLS)
			list(APPEND KW_GROUPS h2-tls)
		endif()
	endif()
	if (LWS_WITH_HTTP3)
		list(APPEND KW_GROUPS h3 h3-alt)
	endif()

	foreach(KW_GROUP ${KW_GROUPS})
		string(REPLACE "-" "_" KW_G ${KW_GROUP})
		lws_get_free_port(PORT_KW_${KW_G}_H1)
		lws_get_free_port(PORT_KW_${KW_G}_TLS)
		lws_get_free_port(PORT_KW_${KW_G}_H2C)
		lws_get_free_port(PORT_KW_${KW_G}_H3)

		add_test(NAME api-test-keep-warm-${KW_GROUP}
			 COMMAND lws-api-test-keep-warm --transport ${KW_GROUP}
				 -p ${PORT_KW_${KW_G}_H1}
				 --tls-port ${PORT_KW_${KW_G}_TLS}
				 --h2c-port ${PORT_KW_${KW_G}_H2C}
				 --h3-port ${PORT_KW_${KW_G}_H3})
		set_tests_properties(api-test-keep-warm-${KW_GROUP} PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
				     TIMEOUT 120)
	endforeach()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
