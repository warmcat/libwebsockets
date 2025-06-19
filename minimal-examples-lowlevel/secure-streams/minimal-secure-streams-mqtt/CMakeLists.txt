project(lws-minimal-secure-streams-mqtt C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)

set(requirements 1)
require_lws_config(LWS_ROLE_MQTT 1 requirements)
require_lws_config(LWS_WITHOUT_CLIENT 0 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)

require_lws_config(LWS_WITH_SECURE_STREAMS_PROXY_API 1 has_ss_proxy)
require_lws_config(LWS_WITH_SYS_STATE 1 has_sys_state)

if (requirements)

	add_executable(${PROJECT_NAME} minimal-secure-streams-mqtt.c)

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME} websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	# also make a -client build using SSPC if enabled

	if (has_ss_proxy OR LWS_WITH_SECURE_STREAMS_PROXY_API)
		add_compile_options(-DLWS_SS_USE_SSPC)

		add_executable(${PROJECT_NAME}-client minimal-secure-streams-mqtt.c)

		if (websockets_shared)
			target_link_libraries(${PROJECT_NAME}-client websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
			add_dependencies(${PROJECT_NAME}-client websockets_shared)
		else()
			target_link_libraries(${PROJECT_NAME}-client websockets ${LIBWEBSOCKETS_DEP_LIBS})
		endif()
	endif()

	# ctest

	if (LWS_CTEST_INTERNET_AVAILABLE AND NOT WIN32 AND DISABLE_IT_DUE_TO_JIG_ROT)

		# the direct selftest

		add_test(NAME mqttss-warmcat COMMAND ${PROJECT_NAME})
		set_tests_properties(mqttss-warmcat
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/secure-streams/minimal-secure-streams-mqtt
			     TIMEOUT 30)

		# via the proxy

		if (has_sys_state AND
		    (HAS_LWS_WITH_SECURE_STREAMS_PROXY_API OR LWS_WITH_SECURE_STREAMS_PROXY_API))

			#
			# Define test dep to bring up and take down the test proxy
			#

			if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
				# uds abstract namespace for linux
				set(CTEST_SOCKET_PATH "@ctest-mqttssp-$ENV{SAI_PROJECT}-$ENV{SAI_OVN}")
			else()
				# filesystem socket for others
				set(CTEST_SOCKET_PATH "/tmp/ctest-mqttssp-$ENV{SAI_PROJECT}-$ENV{SAI_OVN}")
			endif()
			add_test(NAME st_mqttssproxy COMMAND
				${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				mqttssproxy $<TARGET_FILE:lws-minimal-secure-streams-proxy>
				-i ${CTEST_SOCKET_PATH} )
			set_tests_properties(st_mqttssproxy PROPERTIES WORKING_DIRECTORY . FIXTURES_SETUP mqttssproxy TIMEOUT 800)

			add_test(NAME ki_mqttssproxy COMMAND
				${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				mqttssproxy $<TARGET_FILE:lws-minimal-secure-streams-proxy>
				-i ${CTEST_SOCKET_PATH})
			set_tests_properties(ki_mqttssproxy PROPERTIES FIXTURES_CLEANUP mqttssproxy)

			#
			# the client part that will connect to the proxy
			#

			add_test(NAME mqttsspc-minimal COMMAND ${PROJECT_NAME}-client --ssproxy-iface +${CTEST_SOCKET_PATH})

			set(fixlist "mqttssproxy")
			if (DEFINED ENV{SAI_OVN})
				list(APPEND fixlist "res_mqttssproxy")
			endif()

			set_tests_properties(mqttsspc-minimal PROPERTIES
				WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/secure-streams/minimal-secure-streams-mqtt
				FIXTURES_REQUIRED "${fixlist}"
				TIMEOUT 40)

		endif()

	endif()

endif()

