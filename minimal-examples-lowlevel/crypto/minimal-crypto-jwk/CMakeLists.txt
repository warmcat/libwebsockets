project(lws-crypto-jwk C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-crypto-jwk)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_JOSE 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	install(TARGETS ${SAMP}
		RUNTIME DESTINATION ${LWS_INSTALL_EXAMPLES_DIR}
		COMPONENT examples)

endif()
