project(lws-api-test-lws-login-bff C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-lws-login-bff)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_JOSE 1 requirements)
# the real lws-login / lws_login_client plugin protocols must be in the
# vhost protocol table
require_lws_config(LWS_WITH_PLUGINS_BUILTIN 1 requirements)
# protocol_lws_login only builds when sqlite3 is available
require_lws_config(LWS_WITH_STRUCT_SQLITE3 1 requirements)

#
# The stale-token scenarios seed the plugin's db with users, grants and devices
# rows, so the test needs sqlite3 itself rather than only the library's use of it
#
find_path(LOGINBFF_SQLITE3_INCLUDE_DIRS NAMES sqlite3.h)
find_library(LOGINBFF_SQLITE3_LIBRARIES NAMES sqlite3)
if (NOT LOGINBFF_SQLITE3_INCLUDE_DIRS OR NOT LOGINBFF_SQLITE3_LIBRARIES)
	set(requirements 0)
endif()

if (requirements)
	add_executable(${SAMP} ${SRCS})
	target_include_directories(${SAMP} PRIVATE ${LOGINBFF_SQLITE3_INCLUDE_DIRS})
	target_link_libraries(${SAMP} ${LOGINBFF_SQLITE3_LIBRARIES})

	# app + second app (relative auth-api-url) + mock auth vhosts listen on
	# adjacent ports; the sqlite db the test seeds for the plugin stays inside
	# the build dir
	lws_get_free_ports(PORT_LOGINBFF 3)

	add_test(NAME api-test-lws-login-bff
		 COMMAND lws-api-test-lws-login-bff -p ${PORT_LOGINBFF}
			 --db-path ${CMAKE_CURRENT_BINARY_DIR}/apitest-login-bff.sqlite3)
	set_tests_properties(api-test-lws-login-bff PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 120)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
