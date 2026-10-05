project(lws-api-test-tls-accept-async C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-tls-accept-async)
set(SRCS main.c)

#
# A tls server and a burst of h1 and h2 clients in one process.  The async
# tls accept it is about needs LWS_WITH_ASYNC_QUEUE and LWS_MAX_SMP > 1, but
# every connection must be served in any build, so it runs in all of them.
#
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_H2 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)

set(has_fault_injection 1)
require_lws_config(LWS_WITH_SYS_FAULT_INJECTION 1 has_fault_injection)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	# the server's own RSA-2048 test certificate: every accept of the
	# burst signs with it in one service pass, so RSA-4096 there blocks
	# slow boards (riscv, mbedtls 4's constant-time RSA) past timeout_secs
	set(TAAQ_CERTS ${CMAKE_CURRENT_SOURCE_DIR})

	lws_get_free_port(PORT_TLS_ACCEPT_ASYNC)

	# the burst races the worker: accepts go to it, or inline when its
	# queue is full
	add_test(NAME api-test-tls-accept-async
		 COMMAND lws-api-test-tls-accept-async
			 -p ${PORT_TLS_ACCEPT_ASYNC}
			 -s ${LWS_CTEST_SERVER_RESOLVE}
			 --certs ${TAAQ_CERTS})
	set_tests_properties(api-test-tls-accept-async PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 60)

	if (has_fault_injection)
		lws_get_free_port(PORT_TLS_ACCEPT_ASYNC_FULL)

		# every accept finds the worker queue full and is done inline
		add_test(NAME api-test-tls-accept-async-queue-full
			 COMMAND lws-api-test-tls-accept-async
				 -p ${PORT_TLS_ACCEPT_ASYNC_FULL}
				 -s ${LWS_CTEST_SERVER_RESOLVE}
				 --certs ${TAAQ_CERTS}
				 --fault-injection "async_queue_full")
		set_tests_properties(api-test-tls-accept-async-queue-full
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
				     TIMEOUT 60)
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
