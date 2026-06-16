project(lws-minimal-http-client-certfail C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-client-certfail)
set(SRCS minimal-http-client-openhitls-certfail.c)
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_OPENHITLS 1 requirements)
# ctest for selfsigned requires test-server
require_lws_config(LWS_WITHOUT_TEST_SERVER 0 requirements)
require_lws_config(LWS_WITHOUT_TESTAPPS 0 requirements)
require_lws_config(LWS_WITH_FILE_OPS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	target_compile_definitions(${SAMP} PRIVATE
		LWS_TEST_SERVER_CERT_PEM="${CMAKE_BINARY_DIR}/libwebsockets-test-server.pem"
		LWS_TEST_SERVER_KEY_PEM="${CMAKE_BINARY_DIR}/libwebsockets-test-server.key.pem")

	set(PORT_OHCERT_SRV "7750")
	if ("$ENV{SAI_INSTANCE_IDX}")
		math(EXPR PORT_OHCERT_SRV "7751 + $ENV{SAI_INSTANCE_IDX}")
	endif()

	set(PORT_OHCERT_HOST "7770")
	if ("$ENV{SAI_INSTANCE_IDX}")
		math(EXPR PORT_OHCERT_HOST "7771 + $ENV{SAI_INSTANCE_IDX}")
	endif()

	set(PORT_OHCERT_MTLS "7790")
	if ("$ENV{SAI_INSTANCE_IDX}")
		math(EXPR PORT_OHCERT_MTLS "7791 + $ENV{SAI_INSTANCE_IDX}")
	endif()

	if (NOT WIN32 AND LWS_WITH_SERVER)

		# R6: Self-signed cert rejection - uses test-server -s fixture
		add_test(NAME st_cert_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				cert_srv
				$<TARGET_FILE:test-server>
				-r ${CMAKE_BINARY_DIR}/share/libwebsockets-test-server/
				-s --port ${PORT_OHCERT_SRV})
		add_test(NAME ki_cert_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				cert_srv $<TARGET_FILE_NAME:test-server>
				--port ${PORT_OHCERT_SRV})

		set_tests_properties(st_cert_srv PROPERTIES
			WORKING_DIRECTORY .
			FIXTURES_SETUP cert_srv
			TIMEOUT 800)
		set_tests_properties(ki_cert_srv PROPERTIES
			FIXTURES_CLEANUP cert_srv)

		# R6: Self-signed cert rejection test
		add_test(NAME http-client-certfail-selfsigned COMMAND
			lws-minimal-http-client-certfail
				--test selfsigned --port ${PORT_OHCERT_SRV})
		set_tests_properties(http-client-certfail-selfsigned PROPERTIES
			FIXTURES_REQUIRED "cert_srv"
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
			TIMEOUT 20)

		set_property(TEST http-client-certfail-selfsigned
			PROPERTY WILL_FAIL TRUE)

		# R7: Hostname mismatch - embedded wronghost server
		add_test(NAME st_cert_host_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				cert_host_srv
				$<TARGET_FILE:lws-minimal-http-client-certfail>
				--server-only hostname --port ${PORT_OHCERT_HOST})
		add_test(NAME ki_cert_host_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				cert_host_srv
				$<TARGET_FILE_NAME:lws-minimal-http-client-certfail>
				--server-only hostname --port ${PORT_OHCERT_HOST})
		set_tests_properties(st_cert_host_srv PROPERTIES
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-client/minimal-http-client-openhitls-certfail
			FIXTURES_SETUP cert_host_srv
			TIMEOUT 800)
		if (APPLE)
			set_property(TEST st_cert_host_srv PROPERTY ENVIRONMENT
				"SAI_LIST_PORT=${PORT_OHCERT_HOST};VENDOR=apple")
		else()
			set_property(TEST st_cert_host_srv PROPERTY ENVIRONMENT
				"SAI_LIST_PORT=${PORT_OHCERT_HOST};VENDOR=$ENV{VENDOR}")
		endif()
		set_tests_properties(ki_cert_host_srv PROPERTIES
			FIXTURES_CLEANUP cert_host_srv)

		add_test(NAME http-client-certfail-hostname COMMAND
			lws-minimal-http-client-certfail
				--test hostname --port ${PORT_OHCERT_HOST})
		set_tests_properties(http-client-certfail-hostname PROPERTIES
			FIXTURES_REQUIRED "cert_host_srv"
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-client/minimal-http-client-openhitls-certfail
			TIMEOUT 20)
		set_property(TEST http-client-certfail-hostname
			PROPERTY WILL_FAIL TRUE)

		# R8: mTLS client cert required - embedded mTLS server
		add_test(NAME st_cert_mtls_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				cert_mtls_srv
				$<TARGET_FILE:lws-minimal-http-client-certfail>
				--server-only mtls --port ${PORT_OHCERT_MTLS})
		add_test(NAME ki_cert_mtls_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				cert_mtls_srv
				$<TARGET_FILE_NAME:lws-minimal-http-client-certfail>
				--server-only mtls --port ${PORT_OHCERT_MTLS})
		set_tests_properties(st_cert_mtls_srv PROPERTIES
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
			FIXTURES_SETUP cert_mtls_srv
			TIMEOUT 800)
		if (APPLE)
			set_property(TEST st_cert_mtls_srv PROPERTY ENVIRONMENT
				"SAI_LIST_PORT=${PORT_OHCERT_MTLS};VENDOR=apple")
		else()
			set_property(TEST st_cert_mtls_srv PROPERTY ENVIRONMENT
				"SAI_LIST_PORT=${PORT_OHCERT_MTLS};VENDOR=$ENV{VENDOR}")
		endif()
		set_tests_properties(ki_cert_mtls_srv PROPERTIES
			FIXTURES_CLEANUP cert_mtls_srv)

		add_test(NAME http-client-certfail-mtls COMMAND
			lws-minimal-http-client-certfail
				--test mtls --port ${PORT_OHCERT_MTLS})
		set_tests_properties(http-client-certfail-mtls PROPERTIES
			FIXTURES_REQUIRED "cert_mtls_srv"
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
			TIMEOUT 20)
		set_property(TEST http-client-certfail-mtls
			PROPERTY WILL_FAIL TRUE)
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
