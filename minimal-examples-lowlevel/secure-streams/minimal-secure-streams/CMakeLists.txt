project(lws-minimal-secure-streams C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-secure-streams)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITHOUT_CLIENT 0 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(LWS_WITH_SYS_STATE 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(USE_WOLFSSL 0 requirements)

require_lws_config(LWS_WITH_SYS_FAULT_INJECTION 1 has_fault_injection)

if (requirements)
	add_executable(${SAMP} minimal-secure-streams.c)

	find_program(VALGRIND "valgrind")

	if (NOT WIN32)
	
		#
		# When running in CI, wait for a lease on the resources
		# before starting this test, so the server does not get
		# thousands of simultaneous tls connection attempts
		#
		# sai-resource holds the lease on the resources until
		# the time given in seconds or the sai-resource instance
		# exits, whichever happens first
		#
		# If running under Sai, creates a lock test called "res_sspcmin" 
		#
		
		#
		# simple test not via proxy
		#
	
				if (DEFINED ENV{SAI_OVN})
					     
		endif()

		if (has_fault_injection)
			if (VALGRIND AND NOT LWS_WITH_ASAN)
											else()
								 			 endif()

					endif()


		if (HAS_LWS_WITH_SECURE_STREAMS_PROXY_API OR LWS_WITH_SECURE_STREAMS_PROXY_API)

			#
			# Define test dep to bring up and take down the test
			# proxy
			#

			if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
				# uds abstract namespace for linux
				set(CTEST_SOCKET_PATH "@ctest-ssp-$ENV{SAI_PROJECT}-$ENV{SAI_OVN}")
			else()
				# filesystem socket for others
				if (DEFINED ENV{SAI_OVN})
					string(SUBSTRING "$ENV{SAI_OVN}" 32 16 SHORT_HASH)
				else()
					set(SHORT_HASH "0")
				endif()
				set(CTEST_SOCKET_PATH "/tmp/ctest-ssp-$ENV{SAI_PROJECT}-${SHORT_HASH}")
			endif()
			#
			# the client part that will connect to the proxy
			#

			
			set(fixlist "ssproxy")
			if (DEFINED ENV{SAI_OVN})
				list(APPEND fixlist "res_ssproxy")
			endif()
			
					endif()

	endif()

	#
	# Local-server variant: runs against a local lws-minimal-http-server-httpbin
	# over TLS, so it does not need any external network egress.
	#

	if (NOT WIN32 AND LWS_WITH_SERVER)
		lws_get_free_port(PORT_MS_HBIN_TLS)

		configure_file(policy-local.json.in policy-local.json @ONLY)

		add_test(NAME st_ms_hbin
			COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				ms_hbin $<TARGET_FILE:lws-minimal-http-server-httpbin>
				-s -p ${PORT_MS_HBIN_TLS})
		add_test(NAME ki_ms_hbin
			COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				ms_hbin $<TARGET_FILE_NAME:lws-minimal-http-server-httpbin>
				-p ${PORT_MS_HBIN_TLS})
		set_tests_properties(st_ms_hbin PROPERTIES
				WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-tls
				FIXTURES_SETUP ms_hbin
				TIMEOUT 800
				ENVIRONMENT "SAI_LIST_PORT=${PORT_MS_HBIN_TLS}")
		set_tests_properties(ki_ms_hbin PROPERTIES FIXTURES_CLEANUP ms_hbin)

					endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	CHECK_C_SOURCE_COMPILES("#include <libwebsockets.h>\nint main(void) {\ni#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)\n return 0;\n #else\n fail\n #endif\n return 0;\n}\n" HAS_LWS_WITH_SECURE_STREAMS_PROXY_API)

	if (HAS_LWS_WITH_SECURE_STREAMS_PROXY_API OR LWS_WITH_SECURE_STREAMS_PROXY_API)
		add_compile_options(-DLWS_SS_USE_SSPC)

		add_executable(${SAMP}-client minimal-secure-streams.c)
		if (websockets_shared)
			target_link_libraries(${SAMP}-client websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
			add_dependencies(${SAMP}-client websockets_shared)
		else()
			target_link_libraries(${SAMP}-client websockets ${LIBWEBSOCKETS_DEP_LIBS})
		endif()
	endif()


	#
	# Local-proxy variant: the proxy uses the local policy and the local
	# httpbin peer instead of fetching a policy from warmcat.com, so this
	# needs no external network egress.  Deliberately outside the
	#

	if (NOT WIN32 AND LWS_WITH_SERVER AND
	    (HAS_LWS_WITH_SECURE_STREAMS_PROXY_API OR LWS_WITH_SECURE_STREAMS_PROXY_API))

		if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
			# uds abstract namespace for linux
			set(CTEST_LOCAL_SOCKET_PATH "@ctest-sspmin2-local-$ENV{SAI_PROJECT}-$ENV{SAI_OVN}")
		else()
			# filesystem socket for others
			if (DEFINED ENV{SAI_OVN})
				string(SUBSTRING "$ENV{SAI_OVN}" 32 16 SHORT_HASH)
			else()
				set(SHORT_HASH "0")
			endif()
			set(CTEST_LOCAL_SOCKET_PATH "/tmp/ctest-sspmin2-local-$ENV{SAI_PROJECT}-${SHORT_HASH}")
		endif()

		configure_file(policy-local.json.in policy-local.json @ONLY)

		add_test(NAME st_ms_proxy_local COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
			ms_proxy_local $<TARGET_FILE:lws-minimal-secure-streams-proxy>
			-i ${CTEST_LOCAL_SOCKET_PATH}
			-c ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json)
		set_tests_properties(st_ms_proxy_local PROPERTIES
			WORKING_DIRECTORY .
			FIXTURES_SETUP ms_proxy_local
			FIXTURES_REQUIRED "ms_hbin"
			TIMEOUT 800)

		add_test(NAME ki_ms_proxy_local COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
			ms_proxy_local $<TARGET_FILE:lws-minimal-secure-streams-proxy>
			-i ${CTEST_LOCAL_SOCKET_PATH}
			-c ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json)
		set_tests_properties(ki_ms_proxy_local PROPERTIES FIXTURES_CLEANUP ms_proxy_local)

					endif()

endif()
