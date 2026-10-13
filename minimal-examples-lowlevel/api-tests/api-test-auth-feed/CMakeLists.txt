project(lws-api-test-auth-feed C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-auth-feed)
set(SRCS main.c)

#
# The real lws-auth-server and lws-login plugins, from a build with them built
# into the library, both ends of the auth feed between them
#
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_JOSE 1 requirements)
require_lws_config(LWS_WITH_DIR 1 requirements)
require_lws_config(LWS_WITH_STRUCT_JSON 1 requirements)
require_lws_config(LWS_WITH_STRUCT_SQLITE3 1 requirements)
require_lws_config(LWS_WITH_AUTH_SERVER 1 requirements)
require_lws_config(LWS_WITH_PLUGINS_BUILTIN 1 requirements)

#
# The test changes the auth server's records in its sqlite db behind its
# back, the way an admin would, so it needs sqlite3 itself
#
find_path(AUTHFEED_SQLITE3_INCLUDE_DIRS NAMES sqlite3.h)
find_library(AUTHFEED_SQLITE3_LIBRARIES NAMES sqlite3)
if (NOT AUTHFEED_SQLITE3_INCLUDE_DIRS OR NOT AUTHFEED_SQLITE3_LIBRARIES)
	set(requirements 0)
endif()

if (requirements AND NOT WIN32)
	add_executable(${SAMP} ${SRCS})
	# for the feed's schema, plugins/lws-auth-feed.h
	target_include_directories(${SAMP} PRIVATE ${CMAKE_SOURCE_DIR}/plugins
				   ${AUTHFEED_SQLITE3_INCLUDE_DIRS})
	target_link_libraries(${SAMP} ${AUTHFEED_SQLITE3_LIBRARIES})

	# the auth vhost and the app vhost
	lws_get_free_ports(PORT_AUTHFEED 2)

	add_test(NAME api-test-auth-feed
		 COMMAND lws-api-test-auth-feed -p ${PORT_AUTHFEED})
	set_tests_properties(api-test-auth-feed PROPERTIES TIMEOUT 90)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
