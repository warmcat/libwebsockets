project(lws-minimal-http-server-sni-mismatch C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-server-sni-mismatch)
set(SRCS minimal-http-server-openhitls-sni-mismatch.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)

#
# What this exercises is backend code: which vhost, and so which certificate,
# a TLS connection is served by according to the SNI name it asked for.  So
# it wants running on every backend that implements server-side SNI selection.
# openHiTLS came first; BearSSL has no servername callback that can still
# change the certificate and reads the name out of the ClientHello itself.
#
set(sni_openhitls 0)
set(sni_bearssl 0)
require_lws_config(LWS_WITH_OPENHITLS 1 sni_openhitls)
require_lws_config(LWS_WITH_BEARSSL 1 sni_bearssl)

if (NOT sni_openhitls AND NOT sni_bearssl)
	set(requirements 0)
endif()

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	#
	# CTest configuration
	#
	# This test opens four server sockets (one per stage, base_port + 0..3) in a
	# single process, so reserve a contiguous block of four rather than a single
	# port: otherwise a sibling test can grab an individual port from inside our
	# block in parallel CI.
	#
	if (NOT WIN32)
		lws_get_free_ports(PORT_OH_SNI_MISMATCH 4)

		add_test(NAME http-server-sni-mismatch COMMAND
			${SAMP} --port ${PORT_OH_SNI_MISMATCH})
		set_tests_properties(http-server-sni-mismatch PROPERTIES
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-openhitls-sni-mismatch
			TIMEOUT 30)
	endif()
endif()
