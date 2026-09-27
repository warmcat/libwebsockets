project(lws-api-test-lwsws-oauth C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-lwsws-oauth)
set(SRCS main.c)

#
# This api-test drives a real lwsws carrying both halves of the delegated
# login -- lws-auth-server on one vhost, lws-oauth2-client + lws-login on
# another -- with the plugins dlopened out of this build tree, exactly like a
# production deployment.  So it needs the whole lwsws stack, plus the auth
# server plugin and what it is built on.
#
set(requirements 1)
require_lws_config(LWS_WITH_LWSWS 1 requirements)
require_lws_config(LWS_WITH_LIBUV 1 requirements)
require_lws_config(LWS_WITH_PLUGINS 1 requirements)
require_lws_config(LWS_WITH_PLUGINS_BUILTIN 0 requirements)
require_lws_config(LWS_WITH_SHARED 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(LWS_WITH_JOSE 1 requirements)
require_lws_config(LWS_WITH_GENCRYPTO 1 requirements)
require_lws_config(LWS_WITH_STRUCT_SQLITE3 1 requirements)
require_lws_config(LWS_WITH_AUTH_SERVER 1 requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)

set(has_h2 1)
require_lws_config(LWS_WITH_HTTP2 1 has_h2)

# the h3 cases need the QUIC role as well as h3 itself, both ends
set(has_h3 1)
require_lws_config(LWS_WITH_HTTP3 1 has_h3)
require_lws_config(LWS_ROLE_QUIC 1 has_h3)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	if (NOT WIN32 AND LWS_WITH_MINIMAL_EXAMPLES)

		#
		# Two ports: the auth vhost and the app vhost.  Each binds h1 +
		# h2 over TCP and, because its "alpn" names h3, a QUIC UDP
		# listener on the same port number.
		#
		lws_get_free_ports(PORT_OAUTH 2)
		math(EXPR PORT_OAUTH_APP "${PORT_OAUTH} + 1")

		set(OAUTH_DIR		${CMAKE_CURRENT_BINARY_DIR})
		set(OAUTH_CONF_DIR	${OAUTH_DIR}/lwsws-conf)

		set(OAUTH_VHOST_NAME	${LWS_CTEST_SERVER_RESOLVE})
		set(OAUTH_PORT_AUTH	${PORT_OAUTH})
		set(OAUTH_PORT_APP	${PORT_OAUTH_APP})

		# CMAKE_BINARY_DIR, not PROJECT_BINARY_DIR: this file calls
		# project() itself, so PROJECT_BINARY_DIR is this subdir
		set(OAUTH_PLUGIN_DIR	${CMAKE_BINARY_DIR}/lib)
		set(OAUTH_CERT		${CMAKE_BINARY_DIR}/libwebsockets-test-server.pem)
		set(OAUTH_KEY		${CMAKE_BINARY_DIR}/libwebsockets-test-server.key.pem)

		set(OAUTH_AUTH_ASSETS_DIR ${CMAKE_SOURCE_DIR}/plugins/protocol_lws_auth_server/assets)
		set(OAUTH_SAI_ORIGIN_DIR  ${CMAKE_CURRENT_SOURCE_DIR}/sai-origin)
		set(OAUTH_APP_ORIGIN_DIR  ${CMAKE_CURRENT_SOURCE_DIR}/app-origin)

		set(OAUTH_AUTH_DB	${OAUTH_DIR}/apitest-oauth-auth.sqlite3)
		set(OAUTH_JWK_PATH	${OAUTH_DIR}/apitest-oauth.jwk)

		set(OAUTH_CLIENT_ID	"apitest-oauth-client")
		set(OAUTH_SERVICE_NAME	"apitest-oauth-service")

		# short, so a ctest can outlast a session and exercise renewal
		set(OAUTH_JWT_VALIDITY	60)

		#
		# Domain= scoping is the thing that produced parallel host-only
		# and Domain=-scoped copies of the same cookie in the field, so
		# it is part of what is under test rather than a detail.  The
		# default run asserts a Domain= is set, since that is what the
		# deployment does.
		#
		set(OAUTH_COOKIE_DOMAIN_KEY "cookie-domain")
		set(OAUTH_COOKIE_DOMAIN	    ${LWS_CTEST_SERVER_RESOLVE})

		#
		# Throwaway P-256 keypair, the same one api-test-lws-login-bff
		# uses: the auth server signs with it and lws-login verifies
		# with it, both by this path.  It is written here rather than
		# letting the auth server mint its own at first start, so that
		# lws-login can read it at init whatever order the vhosts come
		# up in.
		#
		file(WRITE ${OAUTH_JWK_PATH}
"{\"crv\":\"P-256\",\"d\":\"D4EjZm33VsKBwIO2_BXL-GRKuQpn65wDo0a9Tc7TdMI\",\"kty\":\"EC\",\"x\":\"M_5UuNbZp2RGuV_6_us0qstvioPr4nd6d_FU0dTfsBc\",\"y\":\"2hmXygj6XfChnLtCtLeLO1y8OOWWLRYzabvjBUVVbJk\"}")

		# a fresh db every configure, so a stale one cannot make a run pass
		file(REMOVE ${OAUTH_AUTH_DB})

		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/conf.in
			       ${OAUTH_CONF_DIR}/conf @ONLY)
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/conf.d/apitest.json.in
			       ${OAUTH_CONF_DIR}/conf.d/apitest.json @ONLY)

		#
		# The fixture: the real lwsws, on libuv, plugins dlopened from
		# this build tree's lib/.
		#
		#  -n  don't also scan the compiled-in install-time plugin dir,
		#      or an older installed plugin could be the one loaded
		#  -c  our generated config dir
		#
		add_test(NAME st_lwsws_oauth COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
					lwsws_oauth
					$<TARGET_FILE:lwsws>
					-n -c ${OAUTH_CONF_DIR})
		add_test(NAME ki_lwsws_oauth COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
					lwsws_oauth $<TARGET_FILE_NAME:lwsws>)

		set_tests_properties(st_lwsws_oauth PROPERTIES
				     WORKING_DIRECTORY ${OAUTH_DIR}
				     ENVIRONMENT "SAI_LIST_PORT=${PORT_OAUTH}"
				     FIXTURES_SETUP lwsws_oauth
				     TIMEOUT 120)
		set_tests_properties(ki_lwsws_oauth PROPERTIES
				     FIXTURES_CLEANUP lwsws_oauth)

		set(ARGS_COMMON --server ${LWS_CTEST_SERVER_RESOLVE}
				--auth-port ${PORT_OAUTH}
				--app-port ${PORT_OAUTH_APP}
				--client-id ${OAUTH_CLIENT_ID}
				--service-name ${OAUTH_SERVICE_NAME})

		set(mytests "")

		#
		# (a) the unauthenticated bounce chain, which is every piece of
		# the front half in one request: the lws-login interceptor in
		# front of the protected mount, its handover to the local
		# oauth2-client BFF, and that BFF's PKCE redirect to the auth
		# server with the state binding cookie.
		#
		# It runs once per transport because the bug this test exists
		# for did not care what the request said, only how it was
		# framed: the same exchange succeeded on h1 and lost its
		# headers on h2 / h3.
		#
		add_test(NAME lwsws-oauth-bounce-h1
			 COMMAND ${SAMP} -t bounce --h1 ${ARGS_COMMON})
		list(APPEND mytests lwsws-oauth-bounce-h1)

		if (has_h2)
			add_test(NAME lwsws-oauth-bounce-h2
				 COMMAND ${SAMP} -t bounce --h2 ${ARGS_COMMON})
			list(APPEND mytests lwsws-oauth-bounce-h2)
		endif()

		if (has_h3)
			add_test(NAME lwsws-oauth-bounce-h3
				 COMMAND ${SAMP} -t bounce --h3 ${ARGS_COMMON})
			list(APPEND mytests lwsws-oauth-bounce-h3)
		endif()

		foreach(t ${mytests})
			set_tests_properties(${t} PROPERTIES
					     WORKING_DIRECTORY ${OAUTH_DIR}
					     FIXTURES_REQUIRED "lwsws_oauth"
					     TIMEOUT 60)
		endforeach()

	endif()
endif()
