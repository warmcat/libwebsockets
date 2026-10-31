project(lws-api-test-client-early-fail C)
cmake_minimum_required(VERSION 3.10)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

#
# Clients that fail before their socket is in the fds table are freed under
# the context and pt locks (G-701): debug SMP builds assert it
#
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SYS_ASYNC_DNS 1 requirements)
require_lws_config(LWS_WITH_UDP 1 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)

if (requirements)
	add_executable(${PROJECT_NAME} main.c)

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME} websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	# the port the fake nameserver answers on
	lws_get_free_port(PORT_EARLYFAIL_DNS)

	add_test(NAME api-test-client-early-fail
		 COMMAND lws-api-test-client-early-fail)
	set_tests_properties(api-test-client-early-fail PROPERTIES
			     WORKING_DIRECTORY .
			     ENVIRONMENT "LWS_ASYNCDNS_PORT=${PORT_EARLYFAIL_DNS}"
			     TIMEOUT 30)
endif()
