project(lws-api-test-iface-bind C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-iface-bind)
set(SRCS main.c)

#
# A vhost restricted to an iface never listens on the wildcard address when
# the process runs out of fds as it comes up, and one whose listen socket
# couldn't be created is retried until it can.  It exhausts fds with
# RLIMIT_NOFILE, so posix only.
#
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)
require_lws_config(LWS_WITH_SYS_FAULT_INJECTION 1 requirements)

if (requirements AND NOT WIN32)

	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-iface-bind COMMAND lws-api-test-iface-bind)
	set_tests_properties(api-test-iface-bind PROPERTIES TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
