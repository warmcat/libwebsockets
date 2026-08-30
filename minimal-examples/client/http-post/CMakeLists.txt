project(lws-minimal-ss-http-post C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)

require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITHOUT_CLIENT 0 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)

require_lws_config(LWS_WITH_SYS_FAULT_INJECTION 1 has_fault_injection)
require_lws_config(LWS_WITH_SECURE_STREAMS_PROXY_API 1 has_ss_proxy)
require_lws_config(LWS_WITH_SYS_STATE 1 has_sys_state)

CHECK_C_SOURCE_COMPILES("#include <libwebsockets.h>\nint main(void) {\ni#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)\n return 0;\n #else\n fail\n #endif\n return 0;\n}\n" HAS_LWS_WITH_SECURE_STREAMS_PROXY_API)

if (requirements)

	set(SRCS main.c http-post-ss.c)

	add_executable(${PROJECT_NAME} ${SRCS})

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

	if (HAS_LWS_WITH_SECURE_STREAMS_PROXY_API OR has_ss_proxy OR
	    LWS_WITH_SECURE_STREAMS_PROXY_API)
		add_compile_options(-DLWS_SS_USE_SSPC)

		add_executable(${PROJECT_NAME}-client ${SRCS})

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

	if (NOT WIN32)

		# Note: no fault-injection ctests here: these examples return
		# nonzero directly when SS creation fails, so --expected-exit
		# cannot be reported through them.  The equivalent coverage is
		# in the minimal-secure-streams* examples' fi tests.

	
		#
		# External-egress variant: the example's default policy points at
		# libwebsockets.org, which needs real internet routing.  This is
		# only registered for builds that can actually reach it
		# (dual-stack / IPv4-capable); in an IPv6-only / no-egress CI
		# build the test would hang on DNS / connect until the ctest
		# timeout.  The -local variant below provides the IPv6 coverage
		# instead.
		#
		if (LWS_IPV4)

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

		endif() # LWS_IPV4 (external-egress variant)





	endif()

		#
		# Local-server variant: runs against a local
		# lws-minimal-http-server-httpbin over TLS, so it does not need
		# any external network egress.  Suitable for IPv6-only / no-egress CI.
		#

		if (LWS_WITH_SERVER)
			lws_get_free_port(PORT_HP_SRV_TLS)

			configure_file(policy-local.json.in policy-local.json @ONLY)

			add_test(NAME st_hp_hbin
				COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
					hp_hbin $<TARGET_FILE:lws-minimal-http-server-httpbin>
					-s -p ${PORT_HP_SRV_TLS})
			add_test(NAME ki_hp_hbin
				COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
					hp_hbin $<TARGET_FILE_NAME:lws-minimal-http-server-httpbin>
					-p ${PORT_HP_SRV_TLS})
			set_tests_properties(st_hp_hbin PROPERTIES
					WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-tls
					FIXTURES_SETUP hp_hbin
					TIMEOUT 800
					ENVIRONMENT "SAI_LIST_PORT=${PORT_HP_SRV_TLS}")
			set_tests_properties(ki_hp_hbin PROPERTIES FIXTURES_CLEANUP hp_hbin)

			add_test(NAME msshttp-post-local
				COMMAND ${PROJECT_NAME}
					-c ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json)
			set_tests_properties(msshttp-post-local PROPERTIES
					WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/client/http-post
					FIXTURES_REQUIRED "hp_hbin"
					TIMEOUT 40)
		endif()


	### <--- related to ctest / CI END


	#
	# Local-proxy variant: the proxy uses the local policy and the local
	# peer instead of fetching a policy from warmcat.com, so this needs no
	# external network egress.  Deliberately outside the
	#

	if (NOT WIN32 AND (HAS_LWS_WITH_SECURE_STREAMS_PROXY_API OR
			   LWS_WITH_SECURE_STREAMS_PROXY_API))

		if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
			# uds abstract namespace for linux
			set(CTEST_LOCAL_SOCKET_PATH "@ctest-ssphpp-local-$ENV{SAI_PROJECT}-$ENV{SAI_OVN}")
		else()
			# filesystem socket for others
			if (DEFINED ENV{SAI_OVN})
				string(SUBSTRING "$ENV{SAI_OVN}" 32 16 SHORT_HASH)
			else()
				set(SHORT_HASH "0")
			endif()
			set(CTEST_LOCAL_SOCKET_PATH "/tmp/ctest-ssphpp-local-$ENV{SAI_PROJECT}-${SHORT_HASH}")
		endif()

		configure_file(policy-local.json.in policy-local.json @ONLY)

		add_test(NAME st_hpp_proxy_local COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
			hpp_proxy_local $<TARGET_FILE:lws-minimal-secure-streams-proxy>
			-i ${CTEST_LOCAL_SOCKET_PATH}
			-c ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json)
		set_tests_properties(st_hpp_proxy_local PROPERTIES
			WORKING_DIRECTORY .
			FIXTURES_SETUP hpp_proxy_local
			FIXTURES_REQUIRED "hp_hbin"
			TIMEOUT 800)

		add_test(NAME ki_hpp_proxy_local COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
			hpp_proxy_local $<TARGET_FILE:lws-minimal-secure-streams-proxy>
			-i ${CTEST_LOCAL_SOCKET_PATH}
			-c ${CMAKE_CURRENT_BINARY_DIR}/policy-local.json)
		set_tests_properties(ki_hpp_proxy_local PROPERTIES FIXTURES_CLEANUP hpp_proxy_local)

		add_test(NAME msspc-http-post-local COMMAND lws-minimal-ss-http-post-client --ssproxy-iface +${CTEST_LOCAL_SOCKET_PATH}
			 -i ${CTEST_LOCAL_SOCKET_PATH})
		set_tests_properties(msspc-http-post-local PROPERTIES
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/client/http-post
			FIXTURES_REQUIRED "hpp_proxy_local;hp_hbin"
			TIMEOUT 40)

	endif()

endif()

