cmake_minimum_required(VERSION 3.10)
project(lws-minimal-secure-streams-cpp C)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-secure-streams-cpp)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITHOUT_CLIENT 0 requirements)
require_lws_config(LWS_WITH_MBEDTLS 0 requirements)
require_lws_config(LWS_WITH_OPENHITLS 0 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_CPP 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(USE_WOLFSSL 0 requirements)

if (requirements)
	enable_language(CXX)
	add_executable(${SAMP} main.cxx)

	#
	# Local-server variant: runs against a local lws-minimal-http-server-httpbin
	# over plain http, so it does not need any external network egress.
	# deliberately outside the internet gate.
	#

	if (NOT WIN32 AND LWS_WITH_SERVER)
		lws_get_free_port(PORT_CPP_HBIN)

		add_test(NAME st_cpp_hbin
			COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				cpp_hbin $<TARGET_FILE:lws-minimal-http-server-httpbin>
				-p ${PORT_CPP_HBIN})
		add_test(NAME ki_cpp_hbin
			COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				cpp_hbin $<TARGET_FILE_NAME:lws-minimal-http-server-httpbin>
				-p ${PORT_CPP_HBIN})
		set_tests_properties(st_cpp_hbin PROPERTIES
				WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-tls
				FIXTURES_SETUP cpp_hbin
				TIMEOUT 800
				ENVIRONMENT "SAI_LIST_PORT=${PORT_CPP_HBIN}")
		set_tests_properties(ki_cpp_hbin PROPERTIES FIXTURES_CLEANUP cpp_hbin)

		add_test(NAME sscpp-warmcat-local COMMAND lws-minimal-secure-streams-cpp
			 -u http://${LWS_CTEST_SERVER_URL_RESOLVE}:${PORT_CPP_HBIN})
		set_tests_properties(sscpp-warmcat-local PROPERTIES
				FIXTURES_REQUIRED "cpp_hbin"
				TIMEOUT 40)
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

		add_executable(${SAMP}-client main.cxx)
		if (websockets_shared)
			target_link_libraries(${SAMP}-client websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
			add_dependencies(${SAMP}-client websockets_shared)
		else()
			target_link_libraries(${SAMP}-client websockets ${LIBWEBSOCKETS_DEP_LIBS})
		endif()
	endif()

endif()
