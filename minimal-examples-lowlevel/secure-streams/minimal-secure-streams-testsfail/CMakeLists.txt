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
require_lws_config(LWS_WITH_SERVER 1 requirements)

if (requirements)
	add_executable(${SAMP} minimal-secure-streams-testsfail.c)

	find_program(VALGRIND "valgrind")

	if (LWS_CTEST_INTERNET_AVAILABLE AND NOT WIN32)
		if ("$ENV{SAI_INSTANCE_IDX}")
			math(EXPR PORT_TF_SRV "7681 + $ENV{SAI_INSTANCE_IDX}")
			math(EXPR PORT_TF_SRV_TLS "7682 + $ENV{SAI_INSTANCE_IDX}")
			math(EXPR PORT_TF_SRV_B_HOST "7683 + $ENV{SAI_INSTANCE_IDX}")
			math(EXPR PORT_TF_SRV_B_EXP "7684 + $ENV{SAI_INSTANCE_IDX}")
			math(EXPR PORT_TF_SRV_B_SELF "7685 + $ENV{SAI_INSTANCE_IDX}")
		else()
			set(PORT_TF_SRV "7681")
			set(PORT_TF_SRV_TLS "7682")
			set(PORT_TF_SRV_B_HOST "7683")
			set(PORT_TF_SRV_B_EXP "7684")
			set(PORT_TF_SRV_B_SELF "7685")
		endif()

		configure_file(policy-local.json.in policy-local.json @ONLY)

		if (VALGRIND)
			add_test(NAME ss-tf COMMAND
				${VALGRIND} --tool=memcheck --leak-check=yes --num-callers=20
				$<TARGET_FILE:lws-minimal-secure-streams-testsfail>
				-c ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json)
		else()
			add_test(NAME ss-tf COMMAND $<TARGET_FILE:lws-minimal-secure-streams-testsfail>
				-c ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json)
		endif()

		#
		# Spin up the local fixtures
		#
		add_test(NAME st_hbin COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh hbin $<TARGET_FILE:lws-minimal-http-server-httpbin> -p ${PORT_TF_SRV})
		add_test(NAME ki_hbin COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh hbin $<TARGET_FILE_NAME:lws-minimal-http-server-httpbin> -p ${PORT_TF_SRV})
		set_tests_properties(st_hbin PROPERTIES WORKING_DIRECTORY . FIXTURES_SETUP hbin TIMEOUT 800 ENVIRONMENT "SAI_LIST_PORT=${PORT_TF_SRV}")
		set_tests_properties(ki_hbin PROPERTIES FIXTURES_CLEANUP hbin)

		add_test(NAME st_hbin_tls COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh hbin_tls $<TARGET_FILE:lws-minimal-http-server-httpbin> -s -p ${PORT_TF_SRV_TLS})
		add_test(NAME ki_hbin_tls COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh hbin_tls $<TARGET_FILE_NAME:lws-minimal-http-server-httpbin> -p ${PORT_TF_SRV_TLS})
		set_tests_properties(st_hbin_tls PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-tls FIXTURES_SETUP hbin_tls TIMEOUT 800 ENVIRONMENT "SAI_LIST_PORT=${PORT_TF_SRV_TLS}")
		set_tests_properties(ki_hbin_tls PROPERTIES FIXTURES_CLEANUP hbin_tls)

		add_test(NAME st_hbin_b_host COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh hbin_b_host $<TARGET_FILE:lws-minimal-http-server-tls> -p ${PORT_TF_SRV_B_HOST})
		add_test(NAME ki_hbin_b_host COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh hbin_b_host $<TARGET_FILE_NAME:lws-minimal-http-server-tls> -p ${PORT_TF_SRV_B_HOST})
		set_tests_properties(st_hbin_b_host PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-tls FIXTURES_SETUP hbin_b_host TIMEOUT 800 ENVIRONMENT "SAI_LIST_PORT=${PORT_TF_SRV_B_HOST}")
		set_tests_properties(ki_hbin_b_host PROPERTIES FIXTURES_CLEANUP hbin_b_host)

		add_test(NAME st_hbin_b_exp COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh hbin_b_exp $<TARGET_FILE:lws-minimal-http-server-tls> -p ${PORT_TF_SRV_B_EXP})
		add_test(NAME ki_hbin_b_exp COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh hbin_b_exp $<TARGET_FILE_NAME:lws-minimal-http-server-tls> -p ${PORT_TF_SRV_B_EXP})
		set_tests_properties(st_hbin_b_exp PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-tls FIXTURES_SETUP hbin_b_exp TIMEOUT 800 ENVIRONMENT "SAI_LIST_PORT=${PORT_TF_SRV_B_EXP}")
		set_tests_properties(ki_hbin_b_exp PROPERTIES FIXTURES_CLEANUP hbin_b_exp)

		add_test(NAME st_hbin_b_self COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh hbin_b_self $<TARGET_FILE:lws-minimal-http-server-tls> -p ${PORT_TF_SRV_B_SELF})
		add_test(NAME ki_hbin_b_self COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh hbin_b_self $<TARGET_FILE_NAME:lws-minimal-http-server-tls> -p ${PORT_TF_SRV_B_SELF})
		set_tests_properties(st_hbin_b_self PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-tls FIXTURES_SETUP hbin_b_self TIMEOUT 800 ENVIRONMENT "SAI_LIST_PORT=${PORT_TF_SRV_B_SELF}")
		set_tests_properties(ki_hbin_b_self PROPERTIES FIXTURES_CLEANUP hbin_b_self)

		set_tests_properties(ss-tf
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/secure-streams/minimal-secure-streams-testsfail
				     FIXTURES_REQUIRED "hbin;hbin_tls;hbin_b_host;hbin_b_exp;hbin_b_self"
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
				-c ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json
				-i ${CTEST_SOCKET_PATH}  -d1039)
			set_tests_properties(st_sstfproxy PROPERTIES WORKING_DIRECTORY . FIXTURES_SETUP sstfproxy FIXTURES_REQUIRED "hbin;hbin_tls;hbin_b_host;hbin_b_exp;hbin_b_self" TIMEOUT 800)

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
				add_test(NAME sspc-minimaltf COMMAND $<TARGET_FILE:lws-minimal-secure-streams-testsfail-client> -i +${CTEST_SOCKET_PATH} -d1039)
			endif()
		
			set_tests_properties(sspc-minimaltf PROPERTIES
				WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/secure-streams/minimal-secure-streams-testsfail
				FIXTURES_REQUIRED "sstfproxy;hbin;hbin_tls;hbin_b_host;hbin_b_exp;hbin_b_self"
				TIMEOUT 640)

		endif()

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

		add_executable(${SAMP}-client minimal-secure-streams-testsfail.c)
		if (websockets_shared)
			target_link_libraries(${SAMP}-client websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
			add_dependencies(${SAMP}-client websockets_shared)
		else()
			target_link_libraries(${SAMP}-client websockets ${LIBWEBSOCKETS_DEP_LIBS})
		endif()
	endif()

endif()
