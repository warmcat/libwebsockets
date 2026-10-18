project(lws-api-test-lhp-doc-cache C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-lhp-doc-cache)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_LHP 1 requirements)
require_lws_config(LWS_WITH_CACHE_BLOB 1 requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
# lhp fetches through a secure stream from the JSON policy
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-lhp-doc-cache COMMAND lws-api-test-lhp-doc-cache
		 --server ${LWS_CTEST_SERVER_RESOLVE}
		 --tmpdir ${CMAKE_CURRENT_BINARY_DIR})
	set_tests_properties(api-test-lhp-doc-cache PROPERTIES TIMEOUT 120)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
