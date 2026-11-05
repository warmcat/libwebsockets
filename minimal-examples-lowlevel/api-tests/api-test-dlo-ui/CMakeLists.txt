project(lws-api-test-dlo-ui C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-dlo-ui)
set(SRCS main.c)

#
# The strip ui on a pretend round display: everything is local, its html and
# icon are in the dlo filesystem
#
set(requirements 1)
require_lws_config(LWS_WITH_DLO 1 requirements)
require_lws_config(LWS_WITH_LHP 1 requirements)
require_lws_config(LWS_WITH_SVG 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_FILE_OPS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
# lhp fetches its assets through a secure stream from the JSON policy
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-dlo-ui COMMAND lws-api-test-dlo-ui)
	set_tests_properties(api-test-dlo-ui
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
