project(lws-api-test-happy-eyeballs C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-happy-eyeballs)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_QUIC 1 requirements)
require_lws_config(LWS_ROLE_H2 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_SYS_ASYNC_DNS 1 requirements)
require_lws_config(LWS_WITH_UDP 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(LWS_WITH_CUSTOM_HEADERS 1 requirements)

message("api-test-happy-eyeballs requirements: ${requirements}")

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	lws_get_free_port(PORT_HE_TCP)
	lws_get_free_port(PORT_HE_QUIC)
	lws_get_free_port(PORT_HE_TCP_UV)
	lws_get_free_port(PORT_HE_QUIC_UV)
	lws_get_free_port(PORT_HE_TCP_UV6)
	lws_get_free_port(PORT_HE_QUIC_UV6)

	add_test(NAME api-test-happy-eyeballs COMMAND lws-api-test-happy-eyeballs --server ${LWS_CTEST_SERVER_RESOLVE} -p ${PORT_HE_TCP} -q ${PORT_HE_QUIC})
	set_tests_properties(api-test-happy-eyeballs
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-happy-eyeballs
			     TIMEOUT 60)

	#
	# The same test again on the libuv event loop.  With fault injection the
	# RFC8305 200ms happy-eyeballs pacing is shrunk to ~0us and the TCP
	# listener is bound to a single family, so the primary connect attempt
	# is deterministically refused while the racing attempt on the other
	# family is promoted.  This covers the primary-failed promote path in
	# lws_client_connect_3_connect() under an event lib with per-wsi
	# watchers, which otherwise only shows up after days of uptime as fd
	# recycling tripping UV_EEXIST in elops_accept_uv().
	#
	# Which family sorts first varies with the local routing table, so we
	# run both bind directions to be sure the refused one can be the
	# primary on any box.
	#

	set(uv_requirements 1)
	require_lws_config(LWS_WITH_LIBUV 1 uv_requirements)
	require_lws_config(LWS_WITH_SYS_FAULT_INJECTION 1 uv_requirements)

	if (uv_requirements)
		if (LWS_IPV4 AND LWS_IPV6)
			add_test(NAME api-test-happy-eyeballs-libuv
				 COMMAND lws-api-test-happy-eyeballs --uv --race-fast
					 --server ${LWS_CTEST_SERVER_RESOLVE}
					 -p ${PORT_HE_TCP_UV} -q ${PORT_HE_QUIC_UV}
					 --bind 127.0.0.1)
			add_test(NAME api-test-happy-eyeballs-libuv-v6
				 COMMAND lws-api-test-happy-eyeballs --uv --race-fast
					 --server ${LWS_CTEST_SERVER_RESOLVE}
					 -p ${PORT_HE_TCP_UV6} -q ${PORT_HE_QUIC_UV6}
					 --bind ::1)
			set_tests_properties(api-test-happy-eyeballs-libuv-v6
					     PROPERTIES
					     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-happy-eyeballs
					     ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib"
					     TIMEOUT 60)
		else()
			add_test(NAME api-test-happy-eyeballs-libuv
				 COMMAND lws-api-test-happy-eyeballs --uv --race-fast
					 --server ${LWS_CTEST_SERVER_RESOLVE}
					 -p ${PORT_HE_TCP_UV} -q ${PORT_HE_QUIC_UV})
		endif()

		set_tests_properties(api-test-happy-eyeballs-libuv
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-happy-eyeballs
				     ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib"
				     TIMEOUT 60)
	endif()

endif()
