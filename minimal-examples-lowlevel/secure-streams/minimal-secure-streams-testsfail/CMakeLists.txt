project(lws-minimal-secure-streams-testsfail C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-secure-streams-testsfail)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_H2 1 requirements)
require_lws_config(LWS_WITHOUT_CLIENT 0 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(LWS_WITH_SYS_STATE 1 requirements)
require_lws_config(USE_WOLFSSL 0 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)

if (requirements)
	add_executable(${SAMP} minimal-secure-streams-testsfail.c)

	find_program(VALGRIND "valgrind")

	if (LWS_CTEST_INTERNET_AVAILABLE AND NOT WIN32)
		if (VALGRIND)
			add_test(NAME ss-tf COMMAND
				${VALGRIND} --tool=memcheck --leak-check=yes --num-callers=20
				$<TARGET_FILE:lws-minimal-secure-streams-testsfail>)
		else()
			add_test(NAME ss-tf COMMAND lws-minimal-secure-streams-testsfail)
		endif()

		set_tests_properties(ss-tf
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/secure-streams/minimal-secure-streams-testsfail
				     TIMEOUT 640)

		if (HAS_LWS_WITH_SECURE_STREAMS_PROXY_API OR LWS_WITH_SECURE_STREAMS_PROXY_API)

			#
			# Define test dep to bring up and take down the test
			# proxy
			#

			if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
				# uds abstract namespace for linux
				set(CTEST_SOCKET_PATH "@ctest-ssptf-$ENV{SAI_PROJECT}-$ENV{SAI_OVN}")
			else()
				# filesystem socket for others
                                if (DEFINED ENV{SAI_OVN})
                                        string(SUBSTRING "$ENV{SAI_OVN}" 32 16 SHORT_HASH)
                                else()
                                        set(SHORT_HASH "0")
                                endif()
				set(CTEST_SOCKET_PATH "/tmp/ctest-ssptf-$ENV{SAI_PROJECT}-${SHORT_HASH}")
			endif()
			add_test(NAME st_sstfproxy COMMAND
				${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				sstfproxy $<TARGET_FILE:lws-minimal-secure-streams-proxy>
				-i ${CTEST_SOCKET_PATH}  -d1039)
			set_tests_properties(st_sstfproxy PROPERTIES WORKING_DIRECTORY . FIXTURES_SETUP sstfproxy TIMEOUT 800)

			add_test(NAME ki_sstfproxy COMMAND
				${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				sstfproxy $<TARGET_FILE:lws-minimal-secure-streams-proxy>
				-i ${CTEST_SOCKET_PATH})
			set_tests_properties(ki_sstfproxy PROPERTIES FIXTURES_CLEANUP sstfproxy)

			#
			# the client part that will connect to the proxy
			#

			if (VALGRIND)
				add_test(NAME sspc-minimaltf COMMAND
					${VALGRIND} --tool=memcheck --leak-check=yes --num-callers=20
					$<TARGET_FILE:lws-minimal-secure-streams-testsfail-client> -i +${CTEST_SOCKET_PATH} -d1039)
			else()
				add_test(NAME sspc-minimaltf COMMAND lws-minimal-secure-streams-testsfail-client -i +${CTEST_SOCKET_PATH} -d1039)
			endif()
		
			set_tests_properties(sspc-minimaltf PROPERTIES
				WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/secure-streams/minimal-secure-streams-testsfail
				FIXTURES_REQUIRED "sstfproxy"
				TIMEOUT 640)

		endif()

	endif()

	#
	# Local standalone test
	#
	if ("$ENV{SAI_INSTANCE_IDX}")
		math(EXPR PORT_SRV "7681 + $ENV{SAI_INSTANCE_IDX}")
	else()
		set(PORT_SRV "7681")
	endif()

	# Allow running server on a different port than default
	add_test(NAME st_sstf_srv COMMAND
		${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
		sstf_srv $<TARGET_FILE:lws-minimal-http-server-testsfail>
		--port ${PORT_SRV})
	# We run from CMAKE_BINARY_DIR so the server can find the certs generated there
	set_tests_properties(st_sstf_srv PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR} FIXTURES_SETUP sstf_srv TIMEOUT 800)

	add_test(NAME ki_sstf_srv COMMAND
		${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
		sstf_srv $<TARGET_FILE:lws-minimal-http-server-testsfail>
		--port ${PORT_SRV})
	set_tests_properties(ki_sstf_srv PROPERTIES FIXTURES_CLEANUP sstf_srv)

	add_test(NAME ss-tf-local COMMAND lws-minimal-secure-streams-testsfail --local ${PORT_SRV})
	set_tests_properties(ss-tf-local PROPERTIES
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
		FIXTURES_REQUIRED "sstf_srv"
		TIMEOUT 60)


	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	CHECK_C_SOURCE_COMPILES("#include <libwebsockets.h>\nint main(void) {\ni#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)\n return 0;\n #else\n fail\n #endif\n return 0;\n}\n" HAS_LWS_WITH_SECURE_STREAMS_PROXY_API)

	if (HAS_LWS_WITH_SECURE_STREAMS_PROXY_API OR LWS_WITH_SECURE_STREAMS_PROXY_API)
		add_compile_options(-DLWS_SS_USE_SSPC)

		add_executable(${SAMP}-client minimal-secure-streams-testsfail.c)
		if (websockets_shared)
			target_link_libraries(${SAMP}-client websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
			add_dependencies(${SAMP}-client websockets_shared)
		else()
			target_link_libraries(${SAMP}-client websockets ${LIBWEBSOCKETS_DEP_LIBS})
		endif()
	endif()

endif()
