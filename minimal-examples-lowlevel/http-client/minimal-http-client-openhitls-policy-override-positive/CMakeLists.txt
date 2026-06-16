project(lws-minimal-http-client-policy-override-positive C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-client-policy-override-positive)
set(SRCS minimal-http-client-openhitls-policy-override-positive.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_OPENHITLS 1 requirements)
require_lws_config(LWS_WITH_FILE_OPS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	target_compile_definitions(${SAMP} PRIVATE
		LWS_TEST_SERVER_CERT_PEM="${CMAKE_BINARY_DIR}/libwebsockets-test-server.pem"
		LWS_TEST_SERVER_KEY_PEM="${CMAKE_BINARY_DIR}/libwebsockets-test-server.key.pem")

	set(PORT_OHPOLICY_SELFSIGNED "7840")
	if ("$ENV{SAI_INSTANCE_IDX}")
		math(EXPR PORT_OHPOLICY_SELFSIGNED "7841 + $ENV{SAI_INSTANCE_IDX}")
	endif()

	set(PORT_OHPOLICY_INVALIDCA "7850")
	if ("$ENV{SAI_INSTANCE_IDX}")
		math(EXPR PORT_OHPOLICY_INVALIDCA "7851 + $ENV{SAI_INSTANCE_IDX}")
	endif()

	set(PORT_OHPOLICY_HOSTNAME "7860")
	if ("$ENV{SAI_INSTANCE_IDX}")
		math(EXPR PORT_OHPOLICY_HOSTNAME "7861 + $ENV{SAI_INSTANCE_IDX}")
	endif()

	set(PORT_OHPOLICY_EXPIRED "7870")
	if ("$ENV{SAI_INSTANCE_IDX}")
		math(EXPR PORT_OHPOLICY_EXPIRED "7871 + $ENV{SAI_INSTANCE_IDX}")
	endif()

	if (NOT WIN32 AND LWS_WITH_SERVER)
		add_test(NAME st_policy_selfsigned_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				policy_selfsigned_srv
				$<TARGET_FILE:${SAMP}>
				--server-only selfsigned --port ${PORT_OHPOLICY_SELFSIGNED})
		add_test(NAME ki_policy_selfsigned_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				policy_selfsigned_srv
				$<TARGET_FILE_NAME:${SAMP}>
				--server-only selfsigned --port ${PORT_OHPOLICY_SELFSIGNED})
		set_tests_properties(st_policy_selfsigned_srv PROPERTIES
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			FIXTURES_SETUP policy_selfsigned_srv
			TIMEOUT 800)
		if (APPLE)
			set_property(TEST st_policy_selfsigned_srv PROPERTY ENVIRONMENT
				"SAI_LIST_PORT=${PORT_OHPOLICY_SELFSIGNED};VENDOR=apple")
		else()
			set_property(TEST st_policy_selfsigned_srv PROPERTY ENVIRONMENT
				"SAI_LIST_PORT=${PORT_OHPOLICY_SELFSIGNED};VENDOR=$ENV{VENDOR}")
		endif()
		set_tests_properties(ki_policy_selfsigned_srv PROPERTIES
			FIXTURES_CLEANUP policy_selfsigned_srv)

		add_test(NAME http-client-policy-override-selfsigned-negative COMMAND
			${SAMP} --test selfsigned --policy off
				--port ${PORT_OHPOLICY_SELFSIGNED})
		set_tests_properties(http-client-policy-override-selfsigned-negative PROPERTIES
			FIXTURES_REQUIRED policy_selfsigned_srv
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			TIMEOUT 20)
		add_test(NAME http-client-policy-override-selfsigned-positive COMMAND
			${SAMP} --test selfsigned --policy on
				--port ${PORT_OHPOLICY_SELFSIGNED})
		set_tests_properties(http-client-policy-override-selfsigned-positive PROPERTIES
			FIXTURES_REQUIRED policy_selfsigned_srv
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			TIMEOUT 20)

		add_test(NAME st_policy_invalidca_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				policy_invalidca_srv
				$<TARGET_FILE:${SAMP}>
				--server-only invalidca --port ${PORT_OHPOLICY_INVALIDCA})
		add_test(NAME ki_policy_invalidca_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				policy_invalidca_srv
				$<TARGET_FILE_NAME:${SAMP}>
				--server-only invalidca --port ${PORT_OHPOLICY_INVALIDCA})
		set_tests_properties(st_policy_invalidca_srv PROPERTIES
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			FIXTURES_SETUP policy_invalidca_srv
			TIMEOUT 800)
		if (APPLE)
			set_property(TEST st_policy_invalidca_srv PROPERTY ENVIRONMENT
				"SAI_LIST_PORT=${PORT_OHPOLICY_INVALIDCA};VENDOR=apple")
		else()
			set_property(TEST st_policy_invalidca_srv PROPERTY ENVIRONMENT
				"SAI_LIST_PORT=${PORT_OHPOLICY_INVALIDCA};VENDOR=$ENV{VENDOR}")
		endif()
		set_tests_properties(ki_policy_invalidca_srv PROPERTIES
			FIXTURES_CLEANUP policy_invalidca_srv)

		add_test(NAME http-client-policy-override-invalidca-negative COMMAND
			${SAMP} --test invalidca --policy off
				--port ${PORT_OHPOLICY_INVALIDCA})
		set_tests_properties(http-client-policy-override-invalidca-negative PROPERTIES
			FIXTURES_REQUIRED policy_invalidca_srv
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			TIMEOUT 20)
		add_test(NAME http-client-policy-override-invalidca-positive COMMAND
			${SAMP} --test invalidca --policy on
				--port ${PORT_OHPOLICY_INVALIDCA})
		set_tests_properties(http-client-policy-override-invalidca-positive PROPERTIES
			FIXTURES_REQUIRED policy_invalidca_srv
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			TIMEOUT 20)

		add_test(NAME st_policy_hostname_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				policy_hostname_srv
				$<TARGET_FILE:${SAMP}>
				--server-only hostname --port ${PORT_OHPOLICY_HOSTNAME})
		add_test(NAME ki_policy_hostname_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				policy_hostname_srv
				$<TARGET_FILE_NAME:${SAMP}>
				--server-only hostname --port ${PORT_OHPOLICY_HOSTNAME})
		set_tests_properties(st_policy_hostname_srv PROPERTIES
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			FIXTURES_SETUP policy_hostname_srv
			TIMEOUT 800)
		if (APPLE)
			set_property(TEST st_policy_hostname_srv PROPERTY ENVIRONMENT
				"SAI_LIST_PORT=${PORT_OHPOLICY_HOSTNAME};VENDOR=apple")
		else()
			set_property(TEST st_policy_hostname_srv PROPERTY ENVIRONMENT
				"SAI_LIST_PORT=${PORT_OHPOLICY_HOSTNAME};VENDOR=$ENV{VENDOR}")
		endif()
		set_tests_properties(ki_policy_hostname_srv PROPERTIES
			FIXTURES_CLEANUP policy_hostname_srv)

		add_test(NAME http-client-policy-override-hostname-negative COMMAND
			${SAMP} --test hostname --policy off
				--port ${PORT_OHPOLICY_HOSTNAME})
		set_tests_properties(http-client-policy-override-hostname-negative PROPERTIES
			FIXTURES_REQUIRED policy_hostname_srv
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			TIMEOUT 20)
		add_test(NAME http-client-policy-override-hostname-positive COMMAND
			${SAMP} --test hostname --policy on
				--port ${PORT_OHPOLICY_HOSTNAME})
		set_tests_properties(http-client-policy-override-hostname-positive PROPERTIES
			FIXTURES_REQUIRED policy_hostname_srv
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			TIMEOUT 20)

		add_test(NAME st_policy_expired_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				policy_expired_srv
				$<TARGET_FILE:${SAMP}>
				--server-only expired --port ${PORT_OHPOLICY_EXPIRED})
		add_test(NAME ki_policy_expired_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				policy_expired_srv
				$<TARGET_FILE_NAME:${SAMP}>
				--server-only expired --port ${PORT_OHPOLICY_EXPIRED})
		set_tests_properties(st_policy_expired_srv PROPERTIES
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			FIXTURES_SETUP policy_expired_srv
			TIMEOUT 800)
		if (APPLE)
			set_property(TEST st_policy_expired_srv PROPERTY ENVIRONMENT
				"SAI_LIST_PORT=${PORT_OHPOLICY_EXPIRED};VENDOR=apple")
		else()
			set_property(TEST st_policy_expired_srv PROPERTY ENVIRONMENT
				"SAI_LIST_PORT=${PORT_OHPOLICY_EXPIRED};VENDOR=$ENV{VENDOR}")
		endif()
		set_tests_properties(ki_policy_expired_srv PROPERTIES
			FIXTURES_CLEANUP policy_expired_srv)

		add_test(NAME http-client-policy-override-expired-negative COMMAND
			${SAMP} --test expired --policy off
				--port ${PORT_OHPOLICY_EXPIRED})
		set_tests_properties(http-client-policy-override-expired-negative PROPERTIES
			FIXTURES_REQUIRED policy_expired_srv
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			TIMEOUT 20)
		add_test(NAME http-client-policy-override-expired-positive COMMAND
			${SAMP} --test expired --policy on
				--port ${PORT_OHPOLICY_EXPIRED})
		set_tests_properties(http-client-policy-override-expired-positive PROPERTIES
			FIXTURES_REQUIRED policy_expired_srv
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			TIMEOUT 20)
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
