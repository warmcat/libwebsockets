project(lws-api-test-quic-credit C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-quic-credit)
set(SRCS main.c)

#
# an h3 server and client in this process, the server sending a response
# while the ends advertise huge flow control limits
#
set(requirements 1)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)
set(has_fault_injection 1)
require_lws_config(LWS_WITH_SYS_FAULT_INJECTION 1 has_fault_injection)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	set(QCR_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	lws_get_free_port(PORT_QCR)
	add_test(NAME api-test-quic-credit
		 COMMAND lws-api-test-quic-credit -p ${PORT_QCR}
			 --cert ${QCR_CERTS}/localhost-100y.cert
			 --key ${QCR_CERTS}/localhost-100y.key)
	set_tests_properties(api-test-quic-credit PROPERTIES TIMEOUT 30)

	#
	# The same with each end advertising 2^31, 2^32 and 2^62 - 1, in its
	# transport parameters (tp_window), or in its MAX_DATA / MAX_STREAM_DATA
	# (max_data)
	#
	if (has_fault_injection)
		foreach(qcr_v 2147483648 4294967296 4611686018427387903)
			math(EXPR qcr_v1 "${qcr_v} + 1")
			foreach(qcr_fi tp_window max_data)
				lws_get_free_port(PORT_QCR)
				add_test(NAME api-test-quic-credit-${qcr_fi}-${qcr_v}
					 COMMAND lws-api-test-quic-credit -p ${PORT_QCR}
						 --cert ${QCR_CERTS}/localhost-100y.cert
						 --key ${QCR_CERTS}/localhost-100y.key
						 --fault-injection "wsi/quic_${qcr_fi}(${qcr_v}..${qcr_v1})")
				set_tests_properties(api-test-quic-credit-${qcr_fi}-${qcr_v}
						     PROPERTIES TIMEOUT 30)
			endforeach()
		endforeach()
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
