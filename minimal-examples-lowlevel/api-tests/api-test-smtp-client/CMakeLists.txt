project(lws-api-test-smtp-client C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)
include(CTest)

set(SAMP lws-api-test-smtp-client)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_EMAIL 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	#
	# The fake relay listens on four ports: plaintext, implicit tls, the tls
	# a STARTTLS is relayed to, and one that never says anything
	#
	lws_get_free_port(PORT_SMTP_PLAIN)
	lws_get_free_port(PORT_SMTP_TLS)
	lws_get_free_port(PORT_SMTP_TLSB)
	lws_get_free_port(PORT_SMTP_SILENT)

	add_test(NAME api-test-smtp-client
		 COMMAND lws-api-test-smtp-client
			 -p ${PORT_SMTP_PLAIN}
			 --tls-port ${PORT_SMTP_TLS}
			 --tlsb-port ${PORT_SMTP_TLSB}
			 --silent-port ${PORT_SMTP_SILENT})
	set_tests_properties(api-test-smtp-client PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 120)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
