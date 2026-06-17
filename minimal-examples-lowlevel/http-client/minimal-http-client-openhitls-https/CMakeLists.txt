project(lws-minimal-http-client-https C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-client-https)
set(SRCS minimal-http-client-openhitls-https.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_OPENHITLS 1 requirements)
# ctest for this requires server
require_lws_config(LWS_WITH_SERVER 1 requirements)
if (requirements)
	add_executable(${SAMP} ${SRCS})

	lws_get_free_port(PORT_OHHTTPS_SRV)

	if (NOT WIN32 AND LWS_WITH_SERVER)

		add_test(NAME st_https_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				https_srv
				$<TARGET_FILE:lws-minimal-http-server-tls>
			-p ${PORT_OHHTTPS_SRV})
		add_test(NAME ki_https_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh https_srv
				$<TARGET_FILE_NAME:lws-minimal-http-server-tls>
				-p ${PORT_OHHTTPS_SRV})

		set_tests_properties(st_https_srv PROPERTIES
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-tls
			FIXTURES_SETUP https_srv
			TIMEOUT 800)
		if (APPLE)
			set_property(TEST st_https_srv PROPERTY ENVIRONMENT
				"SAI_LIST_PORT=${PORT_OHHTTPS_SRV};VENDOR=apple")
		else()
			set_property(TEST st_https_srv PROPERTY ENVIRONMENT
				"SAI_LIST_PORT=${PORT_OHHTTPS_SRV};VENDOR=$ENV{VENDOR}")
		endif()
		set_tests_properties(ki_https_srv PROPERTIES
			FIXTURES_CLEANUP https_srv)

		add_test(NAME http-client-https-positive COMMAND
			lws-minimal-http-client-https
				-l --port ${PORT_OHHTTPS_SRV})
		set_tests_properties(http-client-https-positive PROPERTIES
			FIXTURES_REQUIRED "https_srv"
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
			TIMEOUT 20)
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
