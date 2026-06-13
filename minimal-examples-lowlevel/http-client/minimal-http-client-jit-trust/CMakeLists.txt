project(lws-minimal-http-client-jit-trust C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-client-jit-trust)
set(SRCS minimal-http-client.c)

set(has_fault_injection 1)
set(has_h2 1)
set(has_plugins 1)
set(has_ss_policy_parse 1)
set(has_no_system_vhost 1)
set(has_async_dns 1)

set(requirements 1)

require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SYS_STATE 1 requirements)
require_lws_config(LWS_WITH_TLS_JIT_TRUST 1 requirements)

require_lws_config(LWS_ROLE_H2 1 has_h2)
require_lws_config(LWS_WITH_SYS_FAULT_INJECTION 1 has_fault_injection)
require_lws_config(LWS_WITH_EVLIB_PLUGINS 1 has_plugins)
require_lws_config(LWS_WITH_EVENT_LIBS 1 has_plugins)

require_lws_config(LWS_WITH_SECURE_STREAMS 1 has_ss_policy_parse)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 has_ss_policy_parse)

require_lws_config(LWS_WITH_SYS_ASYNC_DNS 0 has_no_system_vhost)
require_lws_config(LWS_WITH_SYS_NTPCLIENT 0 has_no_system_vhost)
require_lws_config(LWS_WITH_SYS_DHCP_CLIENT 0 has_no_system_vhost)

require_lws_config(LWS_WITH_SYS_ASYNC_DNS 1 has_async_dns)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	find_program(VALGRIND "valgrind")
	
	sai_resource(warmcat_conns 1 40 http_client_warmcat)

	lws_get_free_port(PORT_HC_JIT_SRV)

	if (NOT WIN32 AND LWS_WITH_SERVER AND LWS_WITH_TLS)
		add_test(NAME st_hc_jit_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
					hc_jit_srv
					$<TARGET_FILE:test-server>
					-r ${CMAKE_BINARY_DIR}/share/libwebsockets-test-server/
					-s --port ${PORT_HC_JIT_SRV} )
		add_test(NAME ki_hc_jit_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh hc_jit_srv
					$<TARGET_FILE_NAME:test-server> --port ${PORT_HC_JIT_SRV})

		set_tests_properties(st_hc_jit_srv PROPERTIES
							 WORKING_DIRECTORY .
							 FIXTURES_SETUP hc_jit_srv
							 TIMEOUT 800)
		set_tests_properties(ki_hc_jit_srv PROPERTIES
							 FIXTURES_CLEANUP hc_jit_srv)

		set(mytests jit-trust-http-client-warmcat-h1)
		if (has_h2)
			add_test(NAME jit-trust-http-client-warmcat COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV})
			list(APPEND mytests jit-trust-http-client-warmcat)
		endif()

		add_test(NAME jit-trust-http-client-warmcat-h1 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --h1)
				     
		if (has_fault_injection)
		
			# creation related faults
		
			list(APPEND mytests jit-trust-http-client-fi-ctx1)
			add_test(NAME jit-trust-http-client-fi-ctx1 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 5 --fault-injection "ctx_createfail1")
			
			list(APPEND mytests jit-trust-http-client-fi-ctx2)
			add_test(NAME jit-trust-http-client-fi-ctx2 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 5 --fault-injection "ctx_createfail_evlib_sel")
			
			list(APPEND mytests jit-trust-http-client-fi-ctx3)
			add_test(NAME jit-trust-http-client-fi-ctx3 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 5 --fault-injection "ctx_createfail_oom_ctx")
			
			list(APPEND mytests jit-trust-http-client-fi-ctx4)
			add_test(NAME jit-trust-http-client-fi-ctx4 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 5 --fault-injection "ctx_createfail_privdrop")

			list(APPEND mytests jit-trust-http-client-fi-ctx5)
			add_test(NAME jit-trust-http-client-fi-ctx5 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 5 --fault-injection "ctx_createfail_maxfds")
			
			list(APPEND mytests jit-trust-http-client-fi-ctx6)
			add_test(NAME jit-trust-http-client-fi-ctx6 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 5 --fault-injection "ctx_createfail_oom_fds")
			
			list(APPEND mytests jit-trust-http-client-fi-ctx7)
			add_test(NAME jit-trust-http-client-fi-ctx7 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 5 --fault-injection "ctx_createfail_plat_init")
			
			list(APPEND mytests jit-trust-http-client-fi-ctx8)
			add_test(NAME jit-trust-http-client-fi-ctx8 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 5 --fault-injection "ctx_createfail_evlib_init")
			
			list(APPEND mytests jit-trust-http-client-fi-ctx9)
			add_test(NAME jit-trust-http-client-fi-ctx9 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 5 --fault-injection "ctx_createfail_evlib_pt")
			
			if (NOT has_no_system_vhost)
			
				list(APPEND mytests jit-trust-http-client-fi-ctx10)
				add_test(NAME jit-trust-http-client-fi-ctx10 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 5 --fault-injection "ctx_createfail_sys_vh")
			
				list(APPEND mytests jit-trust-http-client-fi-ctx11)
				add_test(NAME jit-trust-http-client-fi-ctx11 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 5 --fault-injection "ctx_createfail_sys_vh_init")
				
			endif()
			
			list(APPEND mytests jit-trust-http-client-fi-ctx12)
			add_test(NAME jit-trust-http-client-fi-ctx12 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 5 --fault-injection "ctx_createfail_def_vh")
			

			list(APPEND mytests jit-trust-http-client-fi-vh1)
			add_test(NAME jit-trust-http-client-fi-vh1 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 5 --fault-injection "vh/vh_create_oom")
			
			list(APPEND mytests jit-trust-http-client-fi-vh2)
			add_test(NAME jit-trust-http-client-fi-vh2 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 5 --fault-injection "vh/vh_create_pcols_oom")
			
			list(APPEND mytests jit-trust-http-client-fi-vh3)
			add_test(NAME jit-trust-http-client-fi-vh3 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 5 --fault-injection "vh/vh_create_ssl_srv")

			list(APPEND mytests jit-trust-http-client-fi-vh4)
			add_test(NAME jit-trust-http-client-fi-vh4 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 5 --fault-injection "vh/vh_create_ssl_cli")
			
			list(APPEND mytests jit-trust-http-client-fi-vh5)
			add_test(NAME jit-trust-http-client-fi-vh5 COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 5 --fault-injection "vh/vh_create_srv_init")


			list(APPEND mytests jit-trust-http-client-fi-dnsfail)
			add_test(NAME jit-trust-http-client-fi-dnsfail COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 3 --fault-injection "wsi=user/dnsfail")
			
			list(APPEND mytests jit-trust-http-client-fi-connfail)
			add_test(NAME jit-trust-http-client-fi-connfail COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 3 --fault-injection "wsi=user/connfail")
			
			list(APPEND mytests jit-trust-http-client-fi-user-est-fail)
			add_test(NAME jit-trust-http-client-fi-user-est-fail COMMAND lws-minimal-http-client-jit-trust -l --server localhost -p ${PORT_HC_JIT_SRV} --expected-exit 3 --fault-injection "wsi/user_reject_at_est")	
		
			
		endif()
		
		set_tests_properties(${mytests} PROPERTIES
		     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-client/minimal-http-client
		     FIXTURES_REQUIRED "hc_jit_srv"
		     TIMEOUT 20)
				     
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
