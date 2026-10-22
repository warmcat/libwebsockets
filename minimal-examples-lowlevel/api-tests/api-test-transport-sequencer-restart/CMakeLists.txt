project(lws-api-test-transport-sequencer-restart C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-transport-sequencer-restart)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_TRANSPORT_SEQUENCER 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	# no sockets: the two sequencers talk over a network simulated in-process
	add_test(NAME api-test-transport-sequencer-restart COMMAND
		 $<TARGET_FILE:${SAMP}>)
	set_tests_properties(api-test-transport-sequencer-restart PROPERTIES
		TIMEOUT 30
		WORKING_DIRECTORY .
		ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib")

endif()
