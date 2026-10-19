project(lws-api-test-captcha-login C)
cmake_minimum_required(VERSION 3.10)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-captcha-login)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_JOSE 1 requirements)
# protocol_lws_login only builds with lws_struct JSON, for the auth feed
require_lws_config(LWS_WITH_STRUCT_JSON 1 requirements)

if (requirements)
	add_executable(${SAMP} main.c)
	# the lws-login and captcha_ratelimit plugins, built in
	target_include_directories(${SAMP} PRIVATE
		${CMAKE_SOURCE_DIR}/plugins/protocol_lws_login
		${CMAKE_SOURCE_DIR}/plugins/protocol_lws_captcha_ratelimit)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	lws_get_free_port(PORT_CAPTCHA_LOGIN)

	add_test(NAME api-test-captcha-login
		 COMMAND ${SAMP} -p ${PORT_CAPTCHA_LOGIN}
			 --assets ${CMAKE_SOURCE_DIR}/plugins/protocol_lws_captcha_ratelimit/captcha-assets)
	set_tests_properties(api-test-captcha-login PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 30)
endif()
