project(lws-api-test-ss-endpoint-subst C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-ss-endpoint-subst)
set(SRCS main.c)

#
# ${metadata} from outside the process (here, captured from a response header)
# substituted into an SS endpoint can't make it a file:// url or a unix domain
# socket, unless the policy wrote that part literally; app-set values can
#
set(requirements 1)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_FILE_OPS 1 requirements)
require_lws_config(LWS_WITH_UNIX_SOCK 1 requirements)
require_lws_config(LWS_WITH_CUSTOM_HEADERS 1 requirements)

if (requirements AND NOT WIN32)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	# the test file and unix socket are made in the working directory
	add_test(NAME api-test-ss-endpoint-subst
		 COMMAND lws-api-test-ss-endpoint-subst
			 --server ${LWS_CTEST_SERVER_RESOLVE})
	set_tests_properties(api-test-ss-endpoint-subst
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 30)
endif()
