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

#
# The seed step writes verified accounts straight into the auth server's own
# sqlite db, so it needs sqlite3 itself rather than only the library's use of it
#
find_path(OAUTH_SQLITE3_INCLUDE_DIRS NAMES sqlite3.h)
find_library(OAUTH_SQLITE3_LIBRARIES NAMES sqlite3)
if (NOT OAUTH_SQLITE3_INCLUDE_DIRS OR NOT OAUTH_SQLITE3_LIBRARIES)
	set(requirements 0)
endif()

if (requirements)
	add_executable(${SAMP} ${SRCS})
	target_include_directories(${SAMP} PRIVATE ${OAUTH_SQLITE3_INCLUDE_DIRS})
	target_link_libraries(${SAMP} ${OAUTH_SQLITE3_LIBRARIES})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	if (NOT WIN32 AND LWS_WITH_MINIMAL_EXAMPLES)

		#
		# Four ports: the auth vhost and the app vhost, each binding h1 +
		# h2 over TCP and, because its "alpn" names h3, a QUIC UDP
		# listener on the same port number; and two h1 + h2 vhosts
		# where the auth server's mount is present but the plugin never
		# set itself up (no options / failed init), for the uninit case.
		#
		lws_get_free_ports(PORT_OAUTH 4)
		math(EXPR PORT_OAUTH_APP "${PORT_OAUTH} + 1")
		math(EXPR PORT_OAUTH_UNINIT "${PORT_OAUTH} + 2")
		math(EXPR PORT_OAUTH_FAILINIT "${PORT_OAUTH} + 3")

		set(OAUTH_DIR		${CMAKE_CURRENT_BINARY_DIR})
		set(OAUTH_CONF_DIR	${OAUTH_DIR}/lwsws-conf)

		set(OAUTH_VHOST_NAME	${LWS_CTEST_SERVER_RESOLVE})
		set(OAUTH_PORT_AUTH	${PORT_OAUTH})
		set(OAUTH_PORT_APP	${PORT_OAUTH_APP})
		set(OAUTH_PORT_UNINIT	${PORT_OAUTH_UNINIT})
		set(OAUTH_PORT_FAILINIT	${PORT_OAUTH_FAILINIT})

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
		# a key path whose directory does not exist, so the key the
		# plugin generates cannot be saved and its init fails
		set(OAUTH_JWK_PATH_BAD	${OAUTH_DIR}/no-such-dir/apitest-oauth.jwk)

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

		#
		# What the BFF composes as its redirect_uri.  Note it does not
		# carry the port, so a deployment on anything but 443 registers
		# a callback the client will not present -- both forms are
		# registered here so the flow is testable either way.
		#
		set(OAUTH_REDIRECT_URIS
		    "https://${LWS_CTEST_SERVER_RESOLVE}/oauth/callback,https://${LWS_CTEST_SERVER_RESOLVE}:${PORT_OAUTH_APP}/oauth/callback")

		#
		# Second fixture step: the schema is made by the auth server
		# plugin at vhost init, so the accounts can only go in once
		# lwsws is up.  DEPENDS orders it after the start step.
		#
		add_test(NAME sd_lwsws_oauth
			 COMMAND ${SAMP} -t seed
				 --db ${OAUTH_AUTH_DB}
				 --client-id ${OAUTH_CLIENT_ID}
				 --service-name ${OAUTH_SERVICE_NAME}
				 --redirect-uris ${OAUTH_REDIRECT_URIS})
		set_tests_properties(sd_lwsws_oauth PROPERTIES
				     WORKING_DIRECTORY ${OAUTH_DIR}
				     FIXTURES_SETUP lwsws_oauth
				     DEPENDS st_lwsws_oauth
				     TIMEOUT 60)

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

		#
		# (b) the credential half: the seeded account logs in through the
		# auth server, the BFF exchanges the code for a token over its
		# own server-to-server hop, and the session cookies land.  This
		# is the only path that makes the auth server mint a session --
		# so the only one that exercises the response carrying the large
		# Set-Cookies -- and the only one that makes the BFF talk to the
		# auth server at all.
		#
		add_test(NAME lwsws-oauth-login-h1
			 COMMAND ${SAMP} -t login --h1 ${ARGS_COMMON})
		list(APPEND mytests lwsws-oauth-login-h1)

		if (has_h2)
			add_test(NAME lwsws-oauth-login-h2
				 COMMAND ${SAMP} -t login --h2 ${ARGS_COMMON})
			list(APPEND mytests lwsws-oauth-login-h2)
		endif()

		if (has_h3)
			add_test(NAME lwsws-oauth-login-h3
				 COMMAND ${SAMP} -t login --h3 ${ARGS_COMMON})
			list(APPEND mytests lwsws-oauth-login-h3)
		endif()

		#
		# (c) a peer that sends Host as well as the authority, as a
		# browser or a reverse proxy may on h2 or h3.  The absolute URLs
		# the app composes from the request host must name one host.
		#
		if (has_h2)
			add_test(NAME lwsws-oauth-dualhost-h2
				 COMMAND ${SAMP} -t dualhost --h2 ${ARGS_COMMON})
			list(APPEND mytests lwsws-oauth-dualhost-h2)
		endif()
		if (has_h3)
			add_test(NAME lwsws-oauth-dualhost-h3
				 COMMAND ${SAMP} -t dualhost --h3 ${ARGS_COMMON})
			list(APPEND mytests lwsws-oauth-dualhost-h3)
		endif()

		#
		# (d) the admin console ws of the auth server: its Origin
		# check, and that revoking or demoting the session behind an
		# open console closes it.  Once only, over h1: it logs in and
		# demotes the one seeded admin, so two could not run at once.
		#
		add_test(NAME lwsws-oauth-adminws
			 COMMAND ${SAMP} -t adminws ${ARGS_COMMON})
		list(APPEND mytests lwsws-oauth-adminws)

		#
		# (d2) the mailed registration link: a GET only asks for
		# confirmation, the page's POST creates the account and shows
		# the second factor once, and the QR image of the seed needs
		# a live, confirmed registration.  Once only, over h1: the
		# seeded registration is consumed.
		#
		add_test(NAME lwsws-oauth-verify
			 COMMAND ${SAMP} -t verify --h1 ${ARGS_COMMON})
		list(APPEND mytests lwsws-oauth-verify)

		#
		# (e) the auth server's mount on vhosts where the plugin has no
		# per-vhost state: one names it with no options, one points
		# jwk_path where the key cannot be saved so its init fails.
		# Both must answer 503, and the process that carries every
		# other vhost must still be there afterwards.
		#
		add_test(NAME lwsws-oauth-uninit-h1
			 COMMAND ${SAMP} -t uninit --h1 ${ARGS_COMMON}
				 --uninit-port ${PORT_OAUTH_UNINIT}
				 --failinit-port ${PORT_OAUTH_FAILINIT})
		list(APPEND mytests lwsws-oauth-uninit-h1)

		if (has_h2)
			add_test(NAME lwsws-oauth-uninit-h2
				 COMMAND ${SAMP} -t uninit --h2 ${ARGS_COMMON}
					 --uninit-port ${PORT_OAUTH_UNINIT}
					 --failinit-port ${PORT_OAUTH_FAILINIT})
			list(APPEND mytests lwsws-oauth-uninit-h2)
		endif()

		foreach(t ${mytests})
			set_tests_properties(${t} PROPERTIES
					     WORKING_DIRECTORY ${OAUTH_DIR}
					     FIXTURES_REQUIRED "lwsws_oauth"
					     TIMEOUT 60)
		endforeach()

	endif()
endif()
