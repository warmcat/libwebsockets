project(lws-api-test-sansio C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)
include(CTest)

set(SAMP lws-api-test-sansio)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)

if (requirements AND NOT WIN32)

	add_executable(${SAMP} ${SRCS})

	add_test(NAME api-test-sansio COMMAND lws-api-test-sansio)
	set_tests_properties(api-test-sansio PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-sansio
			     TIMEOUT 20)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	# the same test against the library whose sansIO half was built alone
	# (LWS_WITH_SANSIO_BUILD): both halves really are one library
	if (TARGET websockets-split)
		add_executable(${SAMP}-split ${SRCS})
		target_link_libraries(${SAMP}-split websockets-split
				      ${LIBWEBSOCKETS_DEP_LIBS})
		add_test(NAME api-test-sansio-split COMMAND ${SAMP}-split)
		set_tests_properties(api-test-sansio-split PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-sansio
				     TIMEOUT 20)
	endif()
endif()
