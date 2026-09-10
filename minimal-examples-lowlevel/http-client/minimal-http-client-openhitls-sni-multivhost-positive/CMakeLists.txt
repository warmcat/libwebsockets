project(lws-minimal-http-client-sni-multivhost-positive C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-client-sni-multivhost-positive)
set(SRCS minimal-http-client-openhitls-sni-multivhost-positive.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(LWS_WITH_FILE_OPS 1 requirements)

#
# Two TLS vhosts share one listen port and the client dials each by name, so
# this is the test that actually proves a backend's server-side SNI moves the
# connection onto the named vhost's certificate.  Run it on every backend that
# has a leg here: openHiTLS came first, BearSSL has no servername callback
# that could still change the certificate and reads the name out of the
# ClientHello itself.
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

	lws_get_free_port(PORT_OHSNI_MVH)

	add_test(NAME http-client-sni-multivhost-positive COMMAND
		lws-minimal-http-client-sni-multivhost-positive
			--port ${PORT_OHSNI_MVH})
	set_tests_properties(http-client-sni-multivhost-positive PROPERTIES
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		TIMEOUT 20)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
