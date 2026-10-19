project(lws-api-test-auth-dns C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-auth-dns)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_AUTHORITATIVE_DNS 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	# the test writes the zones it signs next to its inputs, so it runs
	# in the build tree on copies of them, not in the shared source tree
	foreach(f test.zone.in ksk.jwk zsk.jwk other-ksk.jwk other-zsk.jwk
		  p384-ksk.jwk p384-zsk.jwk rsa-ksk.jwk rsa-zsk.jwk)
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/${f}
			       ${CMAKE_CURRENT_BINARY_DIR}/${f} COPYONLY)
	endforeach()

	add_test(NAME api-test-auth-dns COMMAND lws-api-test-auth-dns
		 WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
