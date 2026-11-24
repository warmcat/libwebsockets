project(lws-api-test-client-racer-fail C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-client-racer-fail)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
# the racer is started at once, and the refusal of a connected attempt, by FI
require_lws_config(LWS_WITH_SYS_FAULT_INJECTION 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	lws_get_free_port(PORT_CLIENT_RACER_FAIL)

	add_test(NAME api-test-client-racer-fail
		 COMMAND lws-api-test-client-racer-fail
			 --server ${LWS_CTEST_SERVER_RESOLVE}
			 -p ${PORT_CLIENT_RACER_FAIL})
	set_tests_properties(api-test-client-racer-fail
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 60)

	# the same on libuv, which keeps a watcher of its own for each racer
	set(uv_requirements 1)
	require_lws_config(LWS_WITH_LIBUV 1 uv_requirements)

	if (uv_requirements)
		lws_get_free_port(PORT_CLIENT_RACER_FAIL_UV)

		add_test(NAME api-test-client-racer-fail-libuv
			 COMMAND lws-api-test-client-racer-fail --uv
				 --server ${LWS_CTEST_SERVER_RESOLVE}
				 -p ${PORT_CLIENT_RACER_FAIL_UV})
		set_tests_properties(api-test-client-racer-fail-libuv
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
				     ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib"
				     TIMEOUT 60)
	endif()
endif()
