project(lws-minimal-secure-streams-threads C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(requirements 1)
require_pthreads(requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SYS_SMD 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(LWS_WITH_SYS_STATE 1 requirements)
require_lws_config(LWS_WITH_NO_LOGS 0 requirements)
require_lws_config(USE_WOLFSSL 0 requirements)

if (requirements AND NOT WIN32)
# win32 has problems with pthreads.h and timespec struct redef
	add_executable(${PROJECT_NAME} minimal-secure-streams-threads.c)

	find_program(VALGRIND "valgrind")

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME} websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	CHECK_C_SOURCE_COMPILES("#include <libwebsockets.h>\nint main(void) {\ni#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)\n return 0;\n #else\n fail\n #endif\n return 0;\n}\n" HAS_LWS_WITH_SECURE_STREAMS_PROXY_API)

	if (HAS_LWS_WITH_SECURE_STREAMS_PROXY_API OR LWS_WITH_SECURE_STREAMS_PROXY_API)
		add_compile_options(-DLWS_SS_USE_SSPC)

		add_executable(${PROJECT_NAME}-client minimal-secure-streams-threads.c)

		if (websockets_shared)
			target_link_libraries(${PROJECT_NAME}-client websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
			add_dependencies(${PROJECT_NAME}-client websockets_shared)
		else()
			target_link_libraries(${PROJECT_NAME}-client websockets ${LIBWEBSOCKETS_DEP_LIBS})
		endif()

		#
		# Define test dep to bring up and take down the test
		# proxy
		#

		if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
			# uds abstract namespace for linux
			set(CTEST_SOCKET_PATH "@ctest-sspthreads_sspc-$ENV{SAI_PROJECT}-$ENV{SAI_OVN}")
		else()
			# filesystem socket for others
                        if (DEFINED ENV{SAI_OVN})
                                string(SUBSTRING "$ENV{SAI_OVN}" 32 16 SHORT_HASH)
                        else()
                                set(SHORT_HASH "0")
                        endif()
			set(CTEST_SOCKET_PATH "/tmp/ctest-sspthreads_sspc-$ENV{SAI_PROJECT}-${SHORT_HASH}")
		endif()

		#
		# the client part that will connect to the proxy
		#

				#
		# Define test dep to bring up and take down the test
		# proxy
		#

		if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
			# uds abstract namespace for linux
			set(CTEST_SOCKET_PATH "@ctest-mul-sspthreads_sspc-$ENV{SAI_PROJECT}-$ENV{SAI_OVN}")
		else()
			# filesystem socket for others
                                if (DEFINED ENV{SAI_OVN})
                                        string(SUBSTRING "$ENV{SAI_OVN}" 32 16 SHORT_HASH)
                                else()
                                        set(SHORT_HASH "0")
                                endif()
			set(CTEST_SOCKET_PATH "/tmp/ctest-mul-sspthreads_sspc-$ENV{SAI_PROJECT}-${SHORT_HASH}")
		endif()

		add_test(NAME st_mulssprxthreads_sspc COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
			mulssproxythreads_sspc $<TARGET_FILE:lws-minimal-secure-streams-proxy>
			-i ${CTEST_SOCKET_PATH}  -d1039)
		set_tests_properties(st_mulssprxthreads_sspc PROPERTIES WORKING_DIRECTORY . FIXTURES_SETUP mulssproxythreads_sspc TIMEOUT 800)

		add_test(NAME ki_mulssprxthreads_sspc COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
			mulssproxythreads_sspc $<TARGET_FILE:lws-minimal-secure-streams-proxy>
			-i ${CTEST_SOCKET_PATH}  -d1039)
		set_tests_properties(ki_mulssprxthreads_sspc PROPERTIES FIXTURES_CLEANUP mulssproxythreads_sspc)

	endif()


	#
	# Local-server variant: runs against a local lws-minimal-http-server-httpbin
	# over TLS, so it does not need any external network egress.
	#

	if (NOT WIN32 AND LWS_WITH_SERVER)
		lws_get_free_port(PORT_THR_HBIN_TLS)

		configure_file(policy-local.json.in policy-local.json @ONLY)

		add_test(NAME st_thr_hbin
			COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				thr_hbin $<TARGET_FILE:lws-minimal-http-server-httpbin>
								-s -p ${PORT_THR_HBIN_TLS})
		add_test(NAME ki_thr_hbin
			COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				thr_hbin $<TARGET_FILE_NAME:lws-minimal-http-server-httpbin>
				-p ${PORT_THR_HBIN_TLS})
		set_tests_properties(st_thr_hbin PROPERTIES
				WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-tls
				FIXTURES_SETUP thr_hbin
				TIMEOUT 800
				ENVIRONMENT "SAI_LIST_PORT=${PORT_THR_HBIN_TLS}")
		set_tests_properties(ki_thr_hbin PROPERTIES FIXTURES_CLEANUP thr_hbin)

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
			set(CTEST_LOCAL_SOCKET_PATH "@ctest-sspthr-local-$ENV{SAI_PROJECT}-$ENV{SAI_OVN}")
		else()
			# filesystem socket for others
			if (DEFINED ENV{SAI_OVN})
				string(SUBSTRING "$ENV{SAI_OVN}" 32 16 SHORT_HASH)
			else()
				set(SHORT_HASH "0")
			endif()
			set(CTEST_LOCAL_SOCKET_PATH "/tmp/ctest-sspthr-local-$ENV{SAI_PROJECT}-${SHORT_HASH}")
		endif()

		configure_file(policy-local.json.in policy-local.json @ONLY)

		add_test(NAME st_thr_proxy_local COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
			thr_proxy_local $<TARGET_FILE:lws-minimal-secure-streams-proxy>
			-i ${CTEST_LOCAL_SOCKET_PATH}
			-c ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json)
		set_tests_properties(st_thr_proxy_local PROPERTIES
			WORKING_DIRECTORY .
			FIXTURES_SETUP thr_proxy_local
			FIXTURES_REQUIRED "thr_hbin"
			TIMEOUT 800)

		add_test(NAME ki_thr_proxy_local COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
			thr_proxy_local $<TARGET_FILE:lws-minimal-secure-streams-proxy>
			-i ${CTEST_LOCAL_SOCKET_PATH}
			-c ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json)
		set_tests_properties(ki_thr_proxy_local PROPERTIES FIXTURES_CLEANUP thr_proxy_local)

		add_test(NAME sspcthreads_sspc_local COMMAND lws-minimal-secure-streams-threads-client
			-i +${CTEST_LOCAL_SOCKET_PATH})
		set_tests_properties(sspcthreads_sspc_local PROPERTIES
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/secure-streams/minimal-secure-streams-threads
			FIXTURES_REQUIRED "thr_proxy_local;thr_hbin"
			TIMEOUT 40)

	endif()

endif()
