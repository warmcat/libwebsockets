project(lws-api-test-dlo-pan C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-dlo-pan)
set(SRCS main.c)

#
# A page laid out taller than a pretend display, panned around: everything is
# local, the page and its png are in the dlo filesystem
#
set(requirements 1)
require_lws_config(LWS_WITH_DLO 1 requirements)
require_lws_config(LWS_WITH_LHP 1 requirements)
require_lws_config(LWS_WITH_UPNG 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_FILE_OPS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-dlo-pan COMMAND lws-api-test-dlo-pan)
	set_tests_properties(api-test-dlo-pan
			     PROPERTIES
			     WORKING_DIRECTORY .
			     TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
