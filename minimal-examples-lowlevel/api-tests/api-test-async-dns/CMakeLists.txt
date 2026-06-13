project(lws-api-test-async-dns C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)

set(SAMP lws-api-test-async-dns)
set(SRCS main.c)

require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SYS_ASYNC_DNS 1 requirements)
require_lws_config(LWS_WITH_AUTHORITATIVE_DNS 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	set(PORT_ADNS_SRV "5353")
	if ("$ENV{SAI_INSTANCE_IDX}")
		math(EXPR PORT_ADNS_SRV \"5353 + ($ENV{SAI_INSTANCE_IDX} * 50)\")
	endif()

	if (NOT WIN32)
		add_test(NAME st_adns_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
					adns_srv
					$<TARGET_FILE:lws-api-test-dns-server>
					-p ${PORT_ADNS_SRV} )
		add_test(NAME ki_adns_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh adns_srv
					$<TARGET_FILE_NAME:lws-api-test-dns-server> -p ${PORT_ADNS_SRV})

		set_tests_properties(st_adns_srv PROPERTIES
						 WORKING_DIRECTORY .
						 FIXTURES_SETUP adns_srv
						 TIMEOUT 800)
		set_tests_properties(ki_adns_srv PROPERTIES
						 FIXTURES_CLEANUP adns_srv)
	endif()

	add_test(NAME api-test-async-dns COMMAND lws-api-test-async-dns -s 127.0.0.1)
	set_tests_properties(api-test-async-dns
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-async-dns
			     ENVIRONMENT "LWS_ASYNCDNS_PORT=${PORT_ADNS_SRV}"
			     TIMEOUT 60)
	if (NOT WIN32)
		set_tests_properties(api-test-async-dns PROPERTIES FIXTURES_REQUIRED "adns_srv")
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
