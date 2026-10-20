project(lws-api-test-listen-any-port C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-listen-any-port)
set(SRCS main.c)

#
# A vhost on any free port listening on IPv4 and IPv6, its second address
# family's bind finding the port the first chose taken, by fault injection
#
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)
require_lws_config(LWS_WITH_IPV6 1 requirements)
require_lws_config(LWS_WITH_SYS_FAULT_INJECTION 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-listen-any-port COMMAND lws-api-test-listen-any-port)
	set_tests_properties(api-test-listen-any-port PROPERTIES TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
