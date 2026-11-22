project(lws-api-test-h3-client-auth C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-h3-client-auth)
set(SRCS main.c)

#
# An h3 server and the h3 client in the same process: what the client sends
# for a digest challenge, from its cookie jar, and for a form body
#
set(requirements 1)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)

# digest auth's hashes come from the tls library
set(H3CA_DIGEST 1)
require_lws_config(LWS_WITH_HTTP_DIGEST_AUTH 1 H3CA_DIGEST)
set(H3CA_COOKIE 1)
require_lws_config(LWS_WITH_CACHE_NSCOOKIEJAR 1 H3CA_COOKIE)

set(H3CA_CASES form)
if (H3CA_DIGEST)
	list(APPEND H3CA_CASES digest)
endif()
if (H3CA_COOKIE)
	list(APPEND H3CA_CASES cookie)
endif()

if (requirements AND NOT WIN32)
	add_executable(${SAMP} ${SRCS})

	set(H3CA_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	foreach(H3CA_CASE ${H3CA_CASES})
		lws_get_free_port(PORT_H3CA_${H3CA_CASE})

		add_test(NAME api-test-h3-client-auth-${H3CA_CASE}
			 COMMAND lws-api-test-h3-client-auth
				 --case ${H3CA_CASE}
				 -p ${PORT_H3CA_${H3CA_CASE}}
				 --jar ${CMAKE_CURRENT_BINARY_DIR}/jar-${H3CA_CASE}.txt
				 --cert ${H3CA_CERTS}/localhost-100y.cert
				 --key ${H3CA_CERTS}/localhost-100y.key)
		set_tests_properties(api-test-h3-client-auth-${H3CA_CASE}
				     PROPERTIES TIMEOUT 30)
	endforeach()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
