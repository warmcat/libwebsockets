project(lws-api-test-peer-stack C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-peer-stack)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	# the tcp servers listen on ports the kernel picks; udp needs one, and
	# so does the tls server, whose h3 listens on the same port
	lws_get_free_port(PORT_PEER_STACK_UDP)
	lws_get_free_port(PORT_PEER_STACK_TLS)

	add_test(NAME api-test-peer-stack
		 COMMAND lws-api-test-peer-stack
			 --server ${LWS_CTEST_SERVER_RESOLVE}
			 -p ${PORT_PEER_STACK_UDP}
			 --tls-port ${PORT_PEER_STACK_TLS}
			 --access-log ${CMAKE_CURRENT_BINARY_DIR}/api-test-peer-stack-access.log)
	# the tls server's certificate and key are in the source dir
	set_tests_properties(api-test-peer-stack PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
