project(lws-api-test-tls-passthrough C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-tls-passthrough)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_TLS_PASSTHROUGH 1 requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	# the front, the backend, the ClientHello capture listener, and the udp
	# "NAT"s the h3 migration and spoofing steps go through
	lws_get_free_ports(PORT_TLSPT 5)

	add_test(NAME api-test-tls-passthrough
		 COMMAND lws-api-test-tls-passthrough -p ${PORT_TLSPT}
			 --certs ${CMAKE_CURRENT_SOURCE_DIR})
	set_tests_properties(api-test-tls-passthrough PROPERTIES TIMEOUT 90)

	#
	# The same with the backend forgetting quiet relayed clients after
	# 700ms, swept every 50ms, instead of 120s and 10s: the slow responses'
	# 1.5s pause is then a long idle, which a proven relay of a live
	# connection must survive, while a handshake still has the time it
	# needs under a sanitizer on a loaded machine
	#
	set(has_fault_injection 1)
	require_lws_config(LWS_WITH_SYS_FAULT_INJECTION 1 has_fault_injection)
	if (has_fault_injection)
		lws_get_free_ports(PORT_TLSPT_IDLE 5)
		add_test(NAME api-test-tls-passthrough-relay-idle
			 COMMAND lws-api-test-tls-passthrough -p ${PORT_TLSPT_IDLE}
				 --certs ${CMAKE_CURRENT_SOURCE_DIR}
				 --fault-injection "qpt_sweep_ms(50..51),qpt_relayed_idle_ms(700..701)")
		set_tests_properties(api-test-tls-passthrough-relay-idle
				     PROPERTIES TIMEOUT 90)
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
