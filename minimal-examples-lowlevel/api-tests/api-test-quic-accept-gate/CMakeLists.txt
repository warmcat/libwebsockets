project(lws-api-test-quic-accept-gate C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-quic-accept-gate)
set(SRCS main.c)

#
# An h3 server and client in one process: pausing the server's tcp accepts,
# for the tls restriction or a full fds table, must not stop its established
# QUIC connections, and new QUIC connections honour the tls restriction
# once their address is validated, not before; a tls listener made while
# accepts are paused starts paused (the late case), and one whose accept()
# ran out of fds stays paused after its back-off if accepts were paused
# meanwhile (the emfile case, also run on libuv when it is built in)
#
set(requirements 1)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
# the idle tcp connects go to 127.0.0.1
require_lws_config(LWS_WITH_IPV4 1 requirements)

if (requirements AND NOT WIN32)
	add_executable(${SAMP} ${SRCS})

	set(CGA_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	#
	# While the emfile case has used up the fds, the async dns' poll of
	# the platform's nameservers would find none it can read, and close
	# its socket, giving the server's accept() an fd: not during a test
	#
	set(CGA_ENV "LWS_ASYNCDNS_WATCH_MS=3600000")

	foreach(CGA_CASE handshakes sessions fds flood late emfile)
		# the server, and the flood case's udp relay or the late case's
		# second vhost
		lws_get_free_ports(PORT_CGA_${CGA_CASE} 2)
		math(EXPR PORT_CGA_RELAY_${CGA_CASE} "${PORT_CGA_${CGA_CASE}} + 1")

		add_test(NAME api-test-quic-accept-gate-${CGA_CASE}
			 COMMAND lws-api-test-quic-accept-gate
				 --case ${CGA_CASE}
				 -p ${PORT_CGA_${CGA_CASE}}
				 --relay-port ${PORT_CGA_RELAY_${CGA_CASE}}
				 --cert ${CGA_CERTS}/localhost-100y.cert
				 --key ${CGA_CERTS}/localhost-100y.key)
		set_tests_properties(api-test-quic-accept-gate-${CGA_CASE}
				     PROPERTIES
				     ENVIRONMENT "${CGA_ENV}"
				     TIMEOUT 40)
	endforeach()

	set(uv_requirements 1)
	require_lws_config(LWS_WITH_LIBUV 1 uv_requirements)

	if (uv_requirements)
		lws_get_free_ports(PORT_CGA_emfile_uv 2)
		math(EXPR PORT_CGA_RELAY_emfile_uv "${PORT_CGA_emfile_uv} + 1")

		add_test(NAME api-test-quic-accept-gate-emfile-libuv
			 COMMAND lws-api-test-quic-accept-gate --uv
				 --case emfile
				 -p ${PORT_CGA_emfile_uv}
				 --relay-port ${PORT_CGA_RELAY_emfile_uv}
				 --cert ${CGA_CERTS}/localhost-100y.cert
				 --key ${CGA_CERTS}/localhost-100y.key)
		set_tests_properties(api-test-quic-accept-gate-emfile-libuv
				     PROPERTIES
				     ENVIRONMENT "${CGA_ENV};LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib"
				     TIMEOUT 40)
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
