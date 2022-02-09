project(lws-minimal-ss-hello_world-policy C)
cmake_minimum_required(VERSION 2.8.12)
find_package(libwebsockets CONFIG REQUIRED)

require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITHOUT_CLIENT 0 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)

require_lws_config(LWS_WITH_SYS_FAULT_INJECTION 1 has_fault_injection)
require_lws_config(LWS_WITH_SECURE_STREAMS_PROXY_API 1 has_ss_proxy)
require_lws_config(LWS_WITH_SYS_STATE 1 has_sys_state)

if (requirements)

	add_executable(${PROJECT_NAME}
			main.c
			hello_world-ss.c)

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME}
			websockets_shared
			${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME}
			websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME}
			websockets
			${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	### --- this section related to also building example with SSPC / Proxy --->

	if (has_ss_proxy OR LWS_WITH_SECURE_STREAMS_PROXY_API)
		add_compile_options(-DLWS_SS_USE_SSPC)

		add_executable(${PROJECT_NAME}-client
				main.c
				hello_world-ss.c)

		if (websockets_shared)
			target_link_libraries(${PROJECT_NAME}-client
				websockets_shared
				${LIBWEBSOCKETS_DEP_LIBS})
			add_dependencies(${PROJECT_NAME}-client
				websockets_shared)
		else()
			target_link_libraries(${PROJECT_NAME}-client
				websockets
				${LIBWEBSOCKETS_DEP_LIBS})
		endif()
	endif()

	### <--- this section related to building with SSPC / Proxy END



	### ---everything else related to ctest / CI ----->

	find_program(VALGRIND "valgrind")

	if (LWS_CTEST_INTERNET_AVAILABLE AND NOT WIN32)
	
		#
		# When running in CI, wait for a lease on the resources
		# before starting this test, so the server does not get
		# thousands of simultaneous tls connection attempts
		#
		# sai-resource holds the lease on the resources until
		# the time given in seconds or the sai-resource instance
		# exits, whichever happens first
		#
		# If running under Sai, creates a lock test called "res_sspc-${PROJECT_NAME}" 
		#
		
		sai_resource(warmcat_conns 1 40 sspc-${PROJECT_NAME})
		
		#
		# simple test not via proxy
		#
	
		if (VALGRIND)
			message("testing via valgrind")
			add_test(NAME mss-${PROJECT_NAME}-warmcat COMMAND
				${VALGRIND} --tool=memcheck --leak-check=yes --num-callers=20
				$<TARGET_FILE:${PROJECT_NAME}>)
		else()
			add_test(NAME mss-${PROJECT_NAME}-warmcat COMMAND ${PROJECT_NAME})
		endif()

		set_tests_properties(mss-${PROJECT_NAME}-warmcat
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/client/hello_world-policy
				     TIMEOUT 40)
		if (DEFINED ENV{SAI_OVN})
			set_tests_properties(mss-${PROJECT_NAME}-warmcat PROPERTIES FIXTURES_REQUIRED "res_sspc-${PROJECT_NAME}")
		endif()

		if (has_fault_injection)
			if (VALGRIND)
				add_test(NAME mss-#{PROJECT_NAME}-warmcat-fi1 COMMAND
					${VALGRIND} --tool=memcheck --leak-check=yes --num-callers=20
					$<TARGET_FILE:${PROJECT_NAME}>
					--fault-injection "ss/ss_create_destroy_me"
					--expected-exit 1)
				add_test(NAME mss-#{PROJECT_NAME}-warmcat-fi2 COMMAND
					${VALGRIND} --tool=memcheck --leak-check=yes --num-callers=20
					$<TARGET_FILE:${PROJECT_NAME}>
					--fault-injection "ss/ss_no_streamtype_policy"
					--expected-exit 1)
			else()
				add_test(NAME mss-${PROJECT_NAME}-warmcat-fi1 COMMAND lws-minimal-secure-streams
					 --fault-injection "ss/ss_create_destroy_me"
					 --expected-exit 1)
				 add_test(NAME mss-${PROJECT_NAME}-warmcat-fi2 COMMAND lws-minimal-secure-streams
					 --fault-injection "ss/ss_no_streamtype_policy"
					 --expected-exit 1)
 			 endif()

			 set_tests_properties(mss-${PROJECT_NAME}-warmcat-fi1
					      mss-${PROJECT_NAME}-warmcat-fi2
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/client/hello_world
				     TIMEOUT 5)

		endif()


		if (has_sys_state AND
		    (HAS_LWS_WITH_SECURE_STREAMS_PROXY_API OR LWS_WITH_SECURE_STREAMS_PROXY_API))

			#
			# Define test dep to bring up and take down the test
			# proxy
			#

			if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
				# uds abstract namespace for linux
				set(CTEST_SOCKET_PATH "@ctest-mssp-$ENV{SAI_PROJECT}-$ENV{SAI_OVN}")
			else()
				# filesystem socket for others
				set(CTEST_SOCKET_PATH "/tmp/ctest-mssp-$ENV{SAI_PROJECT}-$ENV{SAI_OVN}")
			endif()
			add_test(NAME st_mss-${PROJECT_NAME}-proxy COMMAND
				${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				mss-${PROJECT_NAME}-proxy $<TARGET_FILE:lws-minimal-secure-streams-proxy>
				-i ${CTEST_SOCKET_PATH} )
			set_tests_properties(st_mss-${PROJECT_NAME}-proxy PROPERTIES WORKING_DIRECTORY . FIXTURES_SETUP mss-${PROJECT_NAME}-proxy TIMEOUT 800)

			add_test(NAME ki_mss-${PROJECT_NAME}-proxy COMMAND
				${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				mss-${PROJECT_NAME}-proxy $<TARGET_FILE:lws-minimal-secure-streams-proxy>
				-i ${CTEST_SOCKET_PATH})
			set_tests_properties(ki_mss-${PROJECT_NAME}-proxy PROPERTIES FIXTURES_CLEANUP mss-${PROJECT_NAME}-proxy)

			#
			# the client part that will connect to the proxy
			#

			if (VALGRIND)
				message("testing via valgrind")
				add_test(NAME msspc-${PROJECT_NAME} COMMAND
					${VALGRIND} --tool=memcheck --leak-check=yes --num-callers=20
					$<TARGET_FILE:${PROJECT_NAME}-client> --ssproxy-iface +${CTEST_SOCKET_PATH})
			else()
				add_test(NAME msspc-${PROJECT_NAME} COMMAND ${PROJECT_NAME}-client --ssproxy-iface +${CTEST_SOCKET_PATH})
			endif()
			
			set(fixlist "mss-${PROJECT_NAME}-proxy")
			if (DEFINED ENV{SAI_OVN})
				list(APPEND fixlist "res_sspc-${PROJECT_NAME}-proxy")
			endif()
			
			set_tests_properties(msspc-${PROJECT_NAME} PROPERTIES
				WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/client/hello_world
				FIXTURES_REQUIRED "${fixlist}"
				TIMEOUT 40)

		endif()

	endif()

	### <--- related to ctest / CI END

endif()

