project(lws-api-test-http-cookie-jar C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-http-cookie-jar)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_CACHE_NSCOOKIEJAR 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	lws_get_free_port(PORT_HTTP_COOKIE_JAR)

	add_test(NAME api-test-http-cookie-jar
		 COMMAND lws-api-test-http-cookie-jar -p ${PORT_HTTP_COOKIE_JAR}
			 --jar ${CMAKE_CURRENT_BINARY_DIR}/cookie-jar-test.txt)
	set_tests_properties(api-test-http-cookie-jar PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 60)

	# the same with an L1 too small to hold the cookies of one request
	lws_get_free_port(PORT_HTTP_COOKIE_JAR_SMALL_L1)

	add_test(NAME api-test-http-cookie-jar-small-l1
		 COMMAND lws-api-test-http-cookie-jar
			 -p ${PORT_HTTP_COOKIE_JAR_SMALL_L1}
			 --jar ${CMAKE_CURRENT_BINARY_DIR}/cookie-jar-test-l1.txt
			 --l1-max-items 2)
	set_tests_properties(api-test-http-cookie-jar-small-l1 PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
