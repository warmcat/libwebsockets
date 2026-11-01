project(lws-api-test-async-dns-faults C)
cmake_minimum_required(VERSION 3.10)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

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

	# the port the fake nameservers answer on
	lws_get_free_port(PORT_ADNS_FAULTS)

	add_test(NAME api-test-async-dns-faults
		 COMMAND lws-api-test-async-dns-faults)
	set_tests_properties(api-test-async-dns-faults PROPERTIES
			     WORKING_DIRECTORY .
			     ENVIRONMENT "LWS_ASYNCDNS_PORT=${PORT_ADNS_FAULTS};LWS_ASYNCDNS_RESOLV_CONF=adns-faults-resolv.conf"
			     TIMEOUT 40)
endif()
